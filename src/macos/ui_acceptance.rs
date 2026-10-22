//! Opt-in native WebKit acceptance runner. It shares production IPC registration,
//! but starts no guard, updater, notification or messaging workers.
use crate::state::AppState;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use tauri::{Listener, Manager};

pub fn run(context: tauri::Context<tauri::Wry>) {
    let directory = match super::monitor_acceptance::prepare() {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("native UI isolation failed: {error}");
            std::process::exit(1);
        }
    };
    let webview_directory = directory.path().join("webview");
    let done = Arc::new(AtomicBool::new(false));
    let code = Arc::new(AtomicI32::new(1));
    let (setup_done, setup_code) = (done.clone(), code.clone());
    let builder = crate::with_ipc(tauri::Builder::default()).setup(move |app| {
        let handle = app.handle().clone();
        let state = AppState::new(handle.clone());
        let cfg = state.config();
        if cfg.kill_on_fail || !cfg.guarded_agents.is_empty() || cfg.notify.enabled || cfg.cut_network || cfg.quarantine_on_fail || cfg.auto_upd_check {
            return Err("native UI test refused: destructive actions are enabled".into());
        }
        crate::apply_smoke_state(&state, "pass");
        app.manage(state);
        let (completed, status, response_app) = (setup_done.clone(), setup_code.clone(), handle.clone());
        app.listen("guard://acceptance", move |event| {
            if completed.swap(true, Ordering::SeqCst) { return; }
            let mut result: serde_json::Value = serde_json::from_str(event.payload()).unwrap_or_else(|_|serde_json::json!({"passed":false,"error":"invalid browser acceptance response"}));
            if result.get("passed").and_then(|v|v.as_bool()) == Some(true) {
                if response_app.get_webview_window("macos-guide").is_some() {
                    if let Some(cases) = result.get_mut("cases").and_then(|v|v.as_array_mut()) { cases.push("native_local_guide_window_created".into()); }
                } else { result = serde_json::json!({"passed":false,"error":"local guide IPC did not create native window"}); }
            }
            let exit = if result.get("passed").and_then(|v|v.as_bool()) == Some(true) {0} else {1};
            status.store(exit,Ordering::SeqCst);
            println!("{result}");
            response_app.exit(exit);
        });
        tauri::WebviewWindowBuilder::new(app,"main",tauri::WebviewUrl::App("index.html".into()))
            .title("ClaudeGuard · Native UI Acceptance")
            .inner_size(980.0,860.0)
            .data_directory(webview_directory.clone())
            .on_page_load(|window,payload| {
                if payload.event() == tauri::webview::PageLoadEvent::Finished {
                    if let Err(error) = window.eval(include_str!("../../tests/macos-native-ui.js")) {
                        eprintln!("native UI acceptance script failed: {error}");
                        window.app_handle().exit(1);
                    }
                }
            })
            .build()?;
        let (timeout_done, timeout_code, timeout_app) = (setup_done.clone(), setup_code.clone(), handle);
        std::thread::spawn(move || {
            for _ in 0..300 {
                if timeout_done.load(Ordering::SeqCst) { return; }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if !timeout_done.swap(true,Ordering::SeqCst) {
                timeout_code.store(1,Ordering::SeqCst);
                println!("{}",serde_json::json!({"passed":false,"error":"native UI acceptance timed out after 30 seconds"}));
                timeout_app.exit(1);
            }
        });
        Ok(())
    });
    match builder.build(context) {
        Ok(app) => app.run(|_, _| {}),
        Err(error) => eprintln!("native UI launch failed: {error}"),
    }
    done.store(true, Ordering::SeqCst);
    let exit = code.load(Ordering::SeqCst);
    drop(directory);
    if exit != 0 {
        std::process::exit(exit);
    }
}
