#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod checks;
mod config;
mod guard;
mod install;
mod ipc;
mod monitor;
mod tcp_table;
mod update;
// v1 egui 壳（app/wizard/widgets/theme）保留在仓库历史中；v2 已由 Tauri 壳替代，不再挂进模块树。

use std::sync::atomic::Ordering;
use std::sync::Arc;

use config::Config;
use monitor::Shared;
use tauri::Manager;

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
    } else if has("--update-selftest") {
        update_selftest();
    } else {
        run_gui(has("--tray"));
    }
}

/// 隐藏入口: 更新链路自测。真实走一遍 GitHub API → 资产解析 → 下载 → 自替换(不重启)。
/// 在 %TEMP% 的副本上运行, 不影响已安装实例。
fn update_selftest() {
    let cfg = Config::load();
    println!("current : {}", update::current_version());
    match update::check_latest(&cfg) {
        Ok(rel) => {
            println!("latest  : {} (tag {})", rel.version(), rel.tag_name);
            println!(
                "is_newer: {}",
                update::is_newer(rel.version(), update::current_version())
            );
            match rel.exe_asset() {
                Some(a) => {
                    println!("asset   : {} ({} bytes)", a.name, a.size);
                    match update::download(&cfg, &a.browser_download_url, a.size, |d, t| {
                        if d == t {
                            println!("download: {d}/{t} bytes");
                        }
                    }) {
                        Ok(p) => match update::apply_update(&p, false) {
                            Ok(()) => {
                                let cur = std::env::current_exe().unwrap();
                                println!("SWAP OK : {} (旧版本在 .old)", cur.display());
                            }
                            Err(e) => {
                                eprintln!("swap failed: {e}");
                                std::process::exit(2);
                            }
                        },
                        Err(e) => {
                            eprintln!("download failed: {e}");
                            std::process::exit(2);
                        }
                    }
                }
                None => {
                    eprintln!("release 里没有匹配的 exe 资产");
                    std::process::exit(2);
                }
            }
        }
        Err(e) => {
            eprintln!("check failed: {e}");
            std::process::exit(2);
        }
    }
}

fn cmd_check() {
    let cfg = Config::load();
    let out = checks::run_checks(&cfg, |m| guard::log_line(&m));
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    std::process::exit(if out.passed { 0 } else { 2 });
}

fn run_gui(start_hidden: bool) {
    let cfg = Config::load();
    update::cleanup_old();
    let sh = Arc::new(Shared::new(cfg));

    // v1 启动序列：检测到遗留防火墙规则则沿用隔离状态。
    if guard::firewall_active() {
        *sh.tripped.lock().unwrap() = Some(guard::TripResult::default());
        sh.log("检测到已有 ClaudeGuard 防火墙规则（沿用隔离状态）");
    }

    // 主屏工作区物理高+系统 DPI → 逻辑窗口高（v1 同款；WebView2 自身按监视器 DPI 缩放，
    // 这里只决定初始逻辑高度，避免小屏/高缩放下超屏）。
    let target_h: Option<f32> = unsafe {
        let dpi = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey("Control Panel\\Desktop\\WindowMetrics")
            .ok()
            .and_then(|k| k.get_value::<u32, _>("AppliedDPI").ok())
            .unwrap_or(96);
        use windows::Win32::Foundation::RECT;
        use windows::Win32::UI::HiDpi::GetSystemMetricsForDpi;
        use windows::Win32::UI::WindowsAndMessaging::{
            SystemParametersInfoW, SM_CYSCREEN, SYSTEM_PARAMETERS_INFO_ACTION,
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
            Some((logical - 8.0).clamp(420.0, 620.0))
        } else if GetSystemMetricsForDpi(SM_CYSCREEN, dpi) > 0 {
            let logical = GetSystemMetricsForDpi(SM_CYSCREEN, dpi) as f32 / (dpi as f32 / 96.0);
            Some((logical - 56.0).clamp(420.0, 620.0))
        } else {
            None
        }
    };
    // 测试钩子: CG_WIN_H 覆盖窗口逻辑高度(截图验证用)
    let target_h = std::env::var("CG_WIN_H")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .or(target_h);
    let win_h = target_h.unwrap_or(620.0);

    let sh_for_close = Arc::clone(&sh);
    let sh_for_tray = Arc::clone(&sh);
    let sh_for_monitor = Arc::clone(&sh);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // 二次启动：唤起已有主窗口（v1 无此保护，v2 顺带修掉多实例）。
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .manage(Arc::clone(&sh))
        .invoke_handler(tauri::generate_handler![
            ipc::get_state,
            ipc::get_config,
            ipc::set_config,
            ipc::recheck,
            ipc::launch,
            ipc::release,
            ipc::recent_logs,
            ipc::open_data_folder,
            ipc::open_guide,
            ipc::install_app,
            ipc::set_autostart,
            ipc::upd_state,
            ipc::upd_check,
            ipc::upd_download,
            ipc::js_log,
        ])
        .setup(move |app| {
            sh.attach(app.handle().clone());
            monitor::ADMIN_FLAG.store(guard::is_admin(), Ordering::SeqCst);
            monitor::INSTALLED_FLAG.store(install::is_installed(), Ordering::SeqCst);

            let icon = tauri::image::Image::from_bytes(include_bytes!("../assets/icon.png"))?;

            // 手动建窗：--tray 启动全程不闪窗（visible=false），正常启动 setup 内 show。
            let win = tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
                .title("Claude 守护器")
                .inner_size(420.0, win_h as f64)
                .min_inner_size(400.0, 420.0)
                .decorations(false)
                .visible(!start_hidden)
                .on_document_title_changed(|w, title| {
                    // document.title → 原生窗口标题（wry 只回调不代设）。P0 期兼作前端存活信标通道。
                    let _ = w.set_title(&title);
                })
                .icon(icon.clone())?
                .build()?;

            // 关窗驻留托盘（v1 语义：close_to_tray=true → 阻止关闭+隐藏并记日志；false → 真退出）。
            let w2 = win.clone();
            win.on_window_event(move |e| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                    let keep = sh_for_close.cfg.lock().unwrap().close_to_tray;
                    if keep {
                        api.prevent_close();
                        sh_for_close.log("窗口已收进托盘，守护仍在运行");
                        let _ = w2.hide();
                    }
                }
            });

            // 托盘（v1 菜单同 id 同文案 + 暂停守护/数据目录；左键显示+聚焦）。
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
            let m_show = MenuItem::with_id(app, "cg_show", "显示主窗口", true, None::<&str>)?;
            let m_recheck = MenuItem::with_id(app, "cg_recheck", "立即检测", true, None::<&str>)?;
            let m_pause =
                MenuItem::with_id(app, "cg_pause", "暂停守护 30 分钟", true, None::<&str>)?;
            let m_release = MenuItem::with_id(app, "cg_release", "解除隔离", true, None::<&str>)?;
            let m_data = MenuItem::with_id(app, "cg_data", "打开数据文件夹", true, None::<&str>)?;
            let m_quit = MenuItem::with_id(app, "cg_quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[&m_show, &m_recheck, &m_pause, &m_release, &m_data, &m_quit],
            )?;
            let m_pause_for_menu = m_pause.clone();
            TrayIconBuilder::with_id("main")
                .icon(icon)
                .tooltip("Claude 守护器")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |handle, event| match event.id().as_ref() {
                    "cg_show" => {
                        if let Some(w) = handle.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "cg_recheck" => monitor::spawn_check(&sh_for_tray, monitor::Purpose::Manual),
                    "cg_pause" => {
                        // 30 分钟暂停 ⇄ 恢复：菜单文案同步翻转（临时关代理改配置的场景）。
                        if monitor::pause_active(&sh_for_tray) {
                            let _ = m_pause_for_menu.set_text("暂停守护 30 分钟");
                            monitor::set_pause(&sh_for_tray, None);
                        } else {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            let _ = m_pause_for_menu.set_text("恢复守护");
                            monitor::set_pause(&sh_for_tray, Some(now + 1800));
                        }
                    }
                    "cg_release" => monitor::release_now(&sh_for_tray),
                    "cg_data" => {
                        let _ = std::process::Command::new("explorer.exe")
                            .arg(config::config_dir())
                            .spawn();
                    }
                    "cg_quit" => {
                        sh_for_tray.stop.store(true, Ordering::SeqCst);
                        handle.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            monitor::spawn_monitor(sh_for_monitor);
            Ok(())
        })
        .run(tauri::generate_context!());

    if let Err(e) = app {
        guard::log_line(&format!("tauri error: {e}"));
        eprintln!("gui error: {e}");
    }
}
