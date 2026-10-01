#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod checks;
mod config;
mod guard;
mod install;
mod tcp_table;
mod theme;
mod update;
mod widgets;
mod wizard;

use config::Config;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);

    if has("--check") {
        cmd_check();
    } else if has("--install") {
        match install::install() {
            Ok(p) => {
                guard::log_line(&format!("install ok: {}", p.display()));
                println!("installed: {}", p.display());
            }
            Err(e) => {
                eprintln!("install failed: {e}");
                std::process::exit(2);
            }
        }
    } else if has("--uninstall") {
        install::uninstall();
        println!("uninstalled");
    } else {
        run_gui(has("--tray"));
    }
}

fn cmd_check() {
    let cfg = Config::load();
    let out = checks::run_checks(&cfg, |m| guard::log_line(&m));
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    std::process::exit(if out.passed { 0 } else { 2 });
}

fn run_gui(start_hidden: bool) {
    let png = include_bytes!("../assets/icon.png");
    let img = image::load_from_memory(png).expect("decode icon").to_rgba8();
    let (w, h) = img.dimensions();
    let rgba = img.into_raw();
    let tray_img = tray_icon::Icon::from_rgba(rgba.clone(), w, h).expect("tray icon");

    // 主屏工作区物理高+系统 DPI → 逻辑窗口高（顶到任务栏上沿；200% 缩放屏上固定 620 逻辑=1240 物理会超出 1080 物理屏）
    // 注意: winit 初始化前进程尚未声明 DPI 感知, GetDpiForSystem/GetDeviceCaps 都会被虚拟化为 96;
    // GetSystemMetricsForDpi 恒返回物理像素。真实系统 DPI 从注册表 AppliedDPI 读取(不受感知状态影响)。
    // SPI_GETWORKAREA(48) 取排除任务栏后的工作区 RECT(物理), 比旧公式(整屏高-56)多找回约 32 逻辑像素——
    // 实测 1080p@200%: 工作区 1032 物理=516 逻辑, 旧公式只给 484。失败则回退整屏高-56。
    let target_h: Option<f32> = unsafe {
        let dpi = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey("Control Panel\\Desktop\\WindowMetrics")
            .ok()
            .and_then(|k| k.get_value::<u32, _>("AppliedDPI").ok())
            .unwrap_or(96);
        use windows::Win32::Foundation::RECT;
        use windows::Win32::UI::HiDpi::GetSystemMetricsForDpi;
        use windows::Win32::UI::WindowsAndMessaging::{
            SM_CYSCREEN, SystemParametersInfoW, SYSTEM_PARAMETERS_INFO_ACTION,
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
        };
        let mut rect = RECT::default();
        let wa_ok = SystemParametersInfoW(
            SYSTEM_PARAMETERS_INFO_ACTION(48), // SPI_GETWORKAREA
            0,
            Some(&mut rect as *mut RECT as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
        .is_ok();
        let phys_h: i32 = if wa_ok && rect.bottom > rect.top {
            rect.bottom - rect.top
        } else {
            GetSystemMetricsForDpi(SM_CYSCREEN, dpi)
        };
        if phys_h > 0 {
            let scale = dpi as f32 / 96.0;
            let logical = phys_h as f32 / scale;
            Some(((logical - 8.0).min(620.0)).max(420.0))
        } else if GetSystemMetricsForDpi(SM_CYSCREEN, dpi) > 0 {
            // 工作区查询失败的兜底: 整屏高 - 56(旧公式)
            let logical = GetSystemMetricsForDpi(SM_CYSCREEN, dpi) as f32 / (dpi as f32 / 96.0);
            Some(((logical - 56.0).min(620.0)).max(420.0))
        } else {
            None
        }
    };

    // 测试钩子: CG_WIN_H 覆盖窗口逻辑高度(截图验证用)
    let target_h = std::env::var("CG_WIN_H")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .or(target_h);

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Claude 守护器")
            .with_decorations(false)
            .with_inner_size([420.0, target_h.unwrap_or(620.0)])
            .with_min_inner_size([400.0, 420.0])
            .with_icon(egui::IconData {
                rgba,
                width: w,
                height: h,
            }),
        ..Default::default()
    };
    let res = eframe::run_native(
        "ClaudeGuard",
        opts,
        Box::new(move |cc| Ok(Box::new(app::GuardApp::new(cc, start_hidden, tray_img)))),
    );
    if let Err(e) = res {
        guard::log_line(&format!("eframe error: {e}"));
        eprintln!("gui error: {e}");
    }
}
