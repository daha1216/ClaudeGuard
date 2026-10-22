#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! ClaudeGuard v3 入口：CLI 分派、单实例、窗口/托盘装配、启动自愈与后台线程。
//!
//! 判定与调度在 `monitor`；这里只负责把各模块接起来并保持程序生命周期干净：
//! 退出前必须恢复网络、解除隔离（网络绝不能因为程序退出而保持断开）。

mod anchors;
#[cfg_attr(target_os = "macos", path = "macos/claude_update.rs")]
mod claude_update;
mod config;
mod feishu;
#[cfg_attr(target_os = "macos", path = "macos/guard.rs")]
mod guard;
#[cfg_attr(target_os = "macos", path = "macos/install.rs")]
mod install;
mod ipc;
#[cfg(target_os = "macos")]
mod macos;
mod model;
mod monitor;
#[cfg_attr(target_os = "macos", path = "macos/netcut.rs")]
mod netcut;
#[cfg_attr(target_os = "macos", path = "macos/notify.rs")]
mod notify;
mod policy;
mod state;
mod targets;
mod update;

use crate::claude_update::Product;
use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent};

fn application_context() -> tauri::Context<tauri::Wry> {
    tauri::generate_context!()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|arg| arg == flag);

    #[cfg(target_os = "macos")]
    if has("--macos-ui-selftest") {
        crate::macos::ui_acceptance::run(application_context());
        return;
    }
    #[cfg(target_os = "macos")]
    if has("--macos-monitor-selftest") {
        run_monitor_acceptance();
        return;
    }
    #[cfg(target_os = "macos")]
    if has("--notification-status") {
        match crate::notify::status() {
            Ok(status) => {
                print_json(&status);
                return;
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(target_os = "macos")]
    if has("--macos-client-check") {
        let product = args
            .iter()
            .position(|a| a == "--macos-client-check")
            .and_then(|i| args.get(i + 1));
        let product = match product.map(String::as_str) {
            Some("claude") => Product::Claude,
            Some("codex") => Product::Codex,
            _ => {
                eprintln!("需要 claude 或 codex");
                std::process::exit(1);
            }
        };
        match crate::claude_update::check_only(product, &config::Config::load()) {
            Ok(result) => {
                print_json(&result);
                return;
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
    if has("--version") {
        println!("ClaudeGuard {}", crate::model::VERSION);
        return;
    }
    if has("--check") {
        std::process::exit(cli_check());
    }
    if has("--restore") {
        std::process::exit(cli_restore());
    }
    if has("--install") {
        std::process::exit(cli_install());
    }
    if has("--uninstall") {
        #[cfg(target_os = "macos")]
        if let Err(error) = crate::install::uninstall() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        #[cfg(not(target_os = "macos"))]
        crate::install::uninstall();
        return;
    }
    if has("--feishu-status") {
        std::process::exit(cli_feishu_status());
    }
    if has("--claude-update-status") {
        std::process::exit(cli_client_status(Product::Claude));
    }
    if has("--codex-update-status") {
        std::process::exit(cli_client_status(Product::Codex));
    }
    if has("--update-selftest") {
        std::process::exit(cli_update_selftest());
    }
    if has("--notify-test") {
        let kind = args
            .iter()
            .position(|arg| arg == "--notify-test")
            .and_then(|index| args.get(index + 1))
            .cloned()
            .unwrap_or_else(|| "trip".to_string());
        #[cfg(target_os = "macos")]
        {
            run_notification_test(kind);
            return;
        }
        #[cfg(not(target_os = "macos"))]
        std::process::exit(cli_notify_test(&kind));
    }

    run_gui(has("--tray"), has("--settings"));
}

#[cfg(target_os = "macos")]
fn run_monitor_acceptance() {
    let _isolation = crate::macos::monitor_acceptance::prepare().expect("无法创建隔离测试环境");
    let app = tauri::Builder::default()
        .build(application_context())
        .expect("原生调度验收启动失败");
    let mut started = false;
    app.run(move |app, event| {
        if matches!(event, RunEvent::Ready) && !started {
            started = true;
            let handle = app.clone();
            std::thread::spawn(move || {
                let result = crate::macos::monitor_acceptance::run(handle.clone());
                let code = match result {
                    Ok(result) => {
                        print_json(&result);
                        0
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        1
                    }
                };
                handle.exit(code);
            });
        }
    });
}

// ---------- CLI ----------

fn print_json(value: &impl serde::Serialize) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
    );
}

fn cli_check() -> i32 {
    let cfg = config::Config::load();
    let results = monitor::dry_round(&cfg);
    let passed = !results.is_empty() && results.iter().all(|result| result.pass);
    print_json(&serde_json::json!({
        "version": crate::model::VERSION,
        "passed": passed,
        "targets": results,
    }));
    if passed {
        0
    } else {
        2
    }
}

fn cli_restore() -> i32 {
    let (ok, note) = crate::netcut::restore();
    let released = crate::guard::firewall_release();
    print_json(&serde_json::json!({
        "networkOk": ok,
        "network": note,
        "firewallReleased": released,
    }));
    0
}

fn cli_install() -> i32 {
    match crate::install::install() {
        Ok(path) => {
            print_json(&serde_json::json!({"installed": path.display().to_string()}));
            0
        }
        Err(err) => {
            eprintln!("安装失败：{err}");
            1
        }
    }
}

fn cli_feishu_status() -> i32 {
    let notifier = crate::feishu::Notifier::load();
    print_json(&notifier.status());
    0
}

fn cli_client_status(product: Product) -> i32 {
    let updater = crate::claude_update::Updater::load(product);
    print_json(&updater.status());
    0
}

fn cli_update_selftest() -> i32 {
    match crate::update::check_latest(&config::Config::load()) {
        Ok(release) => {
            print_json(&release);
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn cli_notify_test(kind: &str) -> i32 {
    let (title, body) = crate::notify::test_message(kind);
    #[cfg(target_os = "macos")]
    let result = crate::notify::test_blocking(title, &body);
    #[cfg(not(target_os = "macos"))]
    let result = crate::notify::send_blocking(title, &body);
    match result {
        Ok(()) => {
            println!("ok");
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn run_notification_test(kind: String) {
    let app = tauri::Builder::default()
        .setup(|app| {
            let window = tauri::WebviewWindowBuilder::new(
                app,
                "notification-test",
                tauri::WebviewUrl::App("notification-test.html".into()),
            )
            .title("ClaudeGuard 通知测试")
            .inner_size(430.0, 220.0)
            .resizable(false)
            .build()?;
            window.set_focus()?;
            Ok(())
        })
        .build(application_context())
        .expect("通知测试启动失败");
    let mut kind = Some(kind);
    app.run(move |app, event| {
        if matches!(event, RunEvent::Ready) {
            if let Some(kind) = kind.take() {
                let handle = app.clone();
                std::thread::spawn(move || {
                    let (title, body) = crate::notify::test_message(&kind);
                    let code = match crate::notify::test_blocking(title, &body) {
                        Ok(()) => {
                            println!("ok: notification delivered");
                            0
                        }
                        Err(error) => {
                            eprintln!("{error}");
                            1
                        }
                    };
                    handle.exit(code);
                });
            }
        }
    });
}

// ---------- GUI ----------

fn run_gui(start_hidden: bool, want_settings: bool) {
    crate::update::cleanup_old();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if !argv.iter().any(|arg| arg == "--tray") {
                show_main(app);
            }
            if argv.iter().any(|arg| arg == "--settings") {
                open_settings_ui(app);
            }
        }))
        .setup(move |app| {
            let handle = app.handle().clone();
            let state = AppState::new(handle.clone());
            app.manage(state.clone());

            // 冒烟钩子：造出指定界面状态，且不启动真实探测/更新线程（截图与 UI 验证用）。
            let smoke_state = std::env::var("CG_SMOKE_STATE").ok();

            if let Err(err) = crate::notify::ensure_identity() {
                state.log(format!("通知身份登记失败：{err}"));
            }

            let healed = crate::netcut::heal();
            if !healed.is_empty() {
                state.log(format!("启动自愈：{}", healed.join("；")));
            }
            let deduped = crate::guard::firewall_dedupe();
            if deduped > 0 {
                state.log(format!("清理重复防火墙规则 {deduped} 条"));
            }

            if let Some(kind) = smoke_state.as_deref() {
                apply_smoke_state(&state, kind);
            } else {
                state.feishu.clone().start(state.stop.clone());
                crate::claude_update::Updater::start(&state, Product::Claude);
                crate::claude_update::Updater::start(&state, Product::Codex);
                monitor::spawn(state.clone());
                crate::update::spawn_periodic_check(&state);
            }

            let height = window_height(&handle);
            build_window(app, height, !start_hidden)?;
            build_tray(&state)?;

            if want_settings {
                open_settings_ui(&handle);
            }
            Ok(())
        });
    let builder = with_ipc(builder);

    let app = builder
        .build(application_context())
        .expect("ClaudeGuard 启动失败");
    app.run(|app_handle, event| {
        #[cfg(target_os = "macos")]
        if matches!(
            event,
            RunEvent::Reopen {
                has_visible_windows: false,
                ..
            }
        ) {
            // Finder/Dock foreground reopen should restore the hidden window.
            // A login LaunchAgent uses open -g and must remain in the background.
            let handle = app_handle.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(60));
                let activate = handle.clone();
                let _ = handle.run_on_main_thread(move || {
                    if crate::macos::application_is_active() {
                        show_main(&activate);
                    }
                });
            });
        }
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            let state = app_handle.state::<Arc<AppState>>();
            state.stop.store(true, Ordering::SeqCst);
            let _ = crate::netcut::restore();
            let _ = crate::guard::firewall_release();
        }
    });
}

fn with_ipc(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    builder.invoke_handler(tauri::generate_handler![
        ipc::get_state,
        ipc::get_config,
        ipc::update_settings,
        ipc::save_targets,
        ipc::reset_targets,
        ipc::recheck,
        ipc::launch,
        ipc::recheck_target,
        ipc::release,
        ipc::pause,
        ipc::resume,
        ipc::sweep_claude,
        ipc::recent_logs,
        ipc::open_data_folder,
        ipc::open_guide,
        ipc::js_log,
        ipc::install_app,
        ipc::set_autostart,
        ipc::upd_state,
        ipc::upd_check,
        ipc::upd_download,
        ipc::feishu_status,
        ipc::feishu_save,
        ipc::feishu_test,
        ipc::feishu_retry_failed,
        ipc::claude_update_status,
        ipc::claude_update_configure,
        ipc::claude_update_check,
        ipc::codex_update_status,
        ipc::codex_update_configure,
        ipc::codex_update_check,
        ipc::notify_test,
    ])
}

/// 窗口高度 = 工作区逻辑高 − 8，限制在 420..=620；`CG_WIN_H` 可覆盖（截图/冒烟用）。
#[cfg(not(target_os = "macos"))]
fn window_height(app: &AppHandle) -> f64 {
    if let Ok(raw) = std::env::var("CG_WIN_H") {
        if let Ok(value) = raw.trim().parse::<f64>() {
            return value.clamp(320.0, 1400.0);
        }
    }
    if let Ok(Some(monitor)) = app.primary_monitor() {
        let logical = monitor.size().to_logical::<f64>(monitor.scale_factor());
        return (logical.height - 8.0).clamp(420.0, 620.0);
    }
    620.0
}

#[cfg(target_os = "macos")]
fn window_height(app: &AppHandle) -> f64 {
    if let Ok(value) = std::env::var("CG_WIN_H").unwrap_or_default().parse::<f64>() {
        return value.clamp(420.0, 1400.0);
    }
    app.primary_monitor()
        .ok()
        .flatten()
        .map(|m| (m.size().to_logical::<f64>(m.scale_factor()).height - 100.0).clamp(420.0, 860.0))
        .unwrap_or(860.0)
}

fn build_window(app: &tauri::App, height: f64, visible: bool) -> tauri::Result<()> {
    let builder =
        tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
            .title("ClaudeGuard")
            .inner_size(
                if cfg!(target_os = "macos") {
                    980.0
                } else {
                    420.0
                },
                height,
            )
            .min_inner_size(
                if cfg!(target_os = "macos") {
                    520.0
                } else {
                    400.0
                },
                420.0,
            )
            .resizable(true)
            .decorations(cfg!(target_os = "macos"))
            .visible(visible)
            .center();
    #[cfg(target_os = "macos")]
    let builder = builder.theme(Some(tauri::Theme::Dark));
    let window = builder.build()?;

    let handle = window.clone();
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            let state = handle.app_handle().state::<Arc<AppState>>();
            if state.config().close_to_tray && !state.stop.load(Ordering::SeqCst) {
                api.prevent_close();
                let _ = handle.hide();
            }
        }
    });
    Ok(())
}

fn build_tray(state: &Arc<AppState>) -> tauri::Result<()> {
    let app = state.app.clone();
    let show = MenuItem::with_id(&app, "cg_show", "显示主窗口", true, None::<&str>)?;
    let recheck = MenuItem::with_id(&app, "cg_recheck", "立即检测", true, None::<&str>)?;
    let pause = MenuItem::with_id(&app, "cg_pause", "暂停守护 30 分钟", true, None::<&str>)?;
    let release = MenuItem::with_id(
        &app,
        "cg_release",
        if cfg!(target_os = "macos") {
            "清除熔断状态（启动仍需检测）"
        } else {
            "解除隔离并恢复网络"
        },
        true,
        None::<&str>,
    )?;
    let data = MenuItem::with_id(&app, "cg_data", "打开数据文件夹", true, None::<&str>)?;
    let quit = MenuItem::with_id(&app, "cg_quit", "退出", true, None::<&str>)?;
    let separator_top = PredefinedMenuItem::separator(&app)?;
    let separator_bottom = PredefinedMenuItem::separator(&app)?;
    let menu = Menu::with_items(
        &app,
        &[
            &show,
            &separator_top,
            &recheck,
            &pause,
            &release,
            &data,
            &separator_bottom,
            &quit,
        ],
    )?;

    let mut builder = TrayIconBuilder::with_id("cg-tray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("ClaudeGuard");
    #[cfg(target_os = "macos")]
    {
        builder = builder
            .icon(tauri::image::Image::from_bytes(include_bytes!(
                "../assets/macos-tray.png"
            ))?)
            .icon_as_template(true);
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder
        .on_menu_event(|app, event| match event.id().as_ref() {
            "cg_show" => show_main(app),
            "cg_recheck" => {
                let state = app.state::<Arc<AppState>>();
                monitor::recheck(state.inner());
            }
            "cg_pause" => {
                let state = app.state::<Arc<AppState>>();
                monitor::toggle_pause(state.inner());
            }
            "cg_release" => {
                let state = app.state::<Arc<AppState>>();
                monitor::release(state.inner());
            }
            "cg_data" => {
                ipc::open_data_folder();
            }
            "cg_quit" => {
                let state = app.state::<Arc<AppState>>();
                state.stop.store(true, Ordering::SeqCst);
                let _ = crate::netcut::restore();
                let _ = crate::guard::firewall_release();
                app.exit(0);
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
                show_main(tray.app_handle());
            }
        })
        .build(&app)?;
    Ok(())
}

/// 冒烟测试钩子：`CG_SMOKE_STATE=pass|fail|trip|paused` 造出对应界面状态。
///
/// 只写内存状态，不触发探测、不杀进程、不碰防火墙/网卡；生产环境永远不会设置。
fn apply_smoke_state(state: &Arc<AppState>, kind: &str) {
    let cfg = state.config();
    let now = crate::model::now();
    let mut statuses: Vec<crate::model::TargetStatus> = cfg
        .enabled_targets()
        .map(|target| {
            let mut status =
                crate::model::TargetStatus::from_target(target, crate::model::TargetState::Pass);
            status.ip = Some("204.1.100.98".into());
            status.country = Some("US".into());
            status.colo = Some("LAX".into());
            status.latency_ms = 286;
            status.checked_at = Some(now);
            status.reason = "出口在允许范围内".into();
            status
        })
        .collect();

    if matches!(kind, "fail" | "trip") {
        for status in statuses.iter_mut().filter(|s| s.id != "antigravity") {
            status.state = crate::model::TargetState::Fail;
            status.fail_streak = 2;
            status.reason = "出口 103.62.49.170 不在白名单".into();
        }
    }
    let failing_ids: Vec<String> = statuses
        .iter()
        .filter(|s| s.state == crate::model::TargetState::Fail)
        .map(|s| s.id.clone())
        .collect();
    state.set_statuses(statuses);
    state.set_last_check(now);
    if matches!(kind, "fail" | "trip") {
        let agents: Vec<String> = crate::guard::agent_ids()
            .into_iter()
            .map(str::to_string)
            .collect();
        state.set_tripped(Some(crate::model::TripInfo {
            since: now,
            reason: "Claude 出口不在白名单".into(),
            failing_ids: failing_ids.clone(),
            killed: 12,
            firewall_rules: 8,
            quarantined_agents: vec!["claude".into(), "chatgpt".into()],
            agents,
            network_cut: crate::model::CutMode::Firewall,
            network_note: "已阻断全部出站流量".into(),
        }));
    }
    if kind == "paused" {
        state.set_paused_until(Some(now + 30 * 60));
    }
    if kind == "checking" {
        state.set_checking(true);
    }
    state.emit_state();
}

fn show_main(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.show();
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// `--settings` 唤起：窗口加载完成后再调前端展开设置卡（重试几次，幂等）。
fn open_settings_ui(app: &AppHandle) {
    show_main(app);
    let app = app.clone();
    std::thread::spawn(move || {
        let script = "(function(){var t=(window.__CG_SETTINGS_REQ||0)+1;window.__CG_SETTINGS_REQ=t;\
            if(window.CG_UI&&window.CG_UI.openSettings&&(!window.__CG_SETTINGS_OPENED_AT||window.__CG_SETTINGS_OPENED_AT<t)){\
            window.__CG_SETTINGS_OPENED_AT=t;window.CG_UI.openSettings();}})()";
        for _ in 0..20 {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.eval(script);
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    });
}
