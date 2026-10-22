//! Explicit diagnostic: native AppState + real loopback probes, with all destructive
//! operations disabled before AppState construction. No normal workers are started.
use crate::{config::Config, monitor, state::AppState};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

struct Fixture {
    stop: Arc<AtomicBool>,
    reply: Arc<AtomicUsize>,
    seen: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
    port: u16,
}
impl Fixture {
    fn new() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let reply = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(AtomicUsize::new(0));
        let (halt, mode, count) = (stop.clone(), reply.clone(), seen.clone());
        let thread = std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                };
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while request.len() < 16_384 {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                    if request.windows(4).any(|x| x == b"\r\n\r\n") {
                        break;
                    }
                }
                if !request.starts_with(b"GET http://monitor.invalid/") {
                    continue;
                }
                count.fetch_add(1, Ordering::SeqCst);
                let body = match mode.load(Ordering::SeqCst) {
                    0 => "ip=203.0.113.7\nloc=US\n",
                    1 => "ip=198.51.100.8\nloc=GB\n",
                    _ => "no exit information",
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
        Ok(Self {
            stop,
            reply,
            seen,
            thread: Some(thread),
            port,
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn prepare() -> Result<tempfile::TempDir, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    // This branch runs before Tauri/AppState and before any worker is spawned.
    std::env::set_var("CG_DATA_DIR", dir.path());
    std::env::remove_var("CG_SMOKE_STATE");
    let mut cfg = Config {
        guarded_agents: vec![],
        kill_on_fail: false,
        quarantine_on_fail: false,
        cut_network: false,
        disable_network_adapters: false,
        sweep_on_exit: false,
        auto_upd_check: false,
        auto_start_with_system: false,
        first_run: false,
        ..Config::default()
    };
    cfg.notify.enabled = false;
    cfg.save();
    if !crate::config::config_path().starts_with(dir.path())
        || !crate::config::config_path().is_file()
    {
        return Err("隔离测试配置未建立".into());
    }
    Ok(dir)
}

pub fn run(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let fixture = Fixture::new()?;
    let state = AppState::new(app);
    let mut cfg = state.config();
    if cfg.kill_on_fail || !cfg.guarded_agents.is_empty() || cfg.notify.enabled || cfg.cut_network {
        return Err("拒绝运行：测试隔离条件失效".into());
    }
    cfg.proxy_host = "127.0.0.1".into();
    cfg.proxy_port = fixture.port;
    cfg.trip_threshold = 2;
    for t in &mut cfg.targets {
        t.enabled = t.id == "claude";
        t.anchor_url = "http://monitor.invalid/cdn-cgi/trace".into();
        t.expect_ips = vec!["203.0.113.7".into()];
        t.expect_regions.clear();
        t.timeout_secs = 2;
    }
    state.set_config(cfg.clone());
    state.reset_statuses_from_config();
    let mut checked = Vec::new();
    macro_rules! ensure {
        ($condition:expr, $name:literal) => {
            if !$condition {
                return Err(format!("FAIL: {}", $name));
            }
            checked.push($name);
        };
    }
    ensure!(
        monitor::run_round(&state, monitor::Purpose::Monitor).passed,
        "initial_pass"
    );
    fixture.reply.store(1, Ordering::SeqCst);
    ensure!(
        !monitor::run_round(&state, monitor::Purpose::Monitor).passed && !state.is_tripped(),
        "first_failure_debounced"
    );
    monitor::run_round(&state, monitor::Purpose::Monitor);
    ensure!(state.is_tripped(), "second_failure_trips");
    ensure!(
        state
            .tripped()
            .is_some_and(|t| t.network_cut == crate::model::CutMode::Off && t.killed == 0),
        "no_network_or_process_changes"
    );
    monitor::run_round(&state, monitor::Purpose::Monitor);
    ensure!(state.is_tripped(), "ongoing_failure_stays_tripped");
    fixture.reply.store(2, Ordering::SeqCst);
    monitor::run_round(&state, monitor::Purpose::Monitor);
    ensure!(state.is_tripped(), "unverified_does_not_recover");
    ensure!(
        monitor::launch(&state).is_err(),
        "unverified_launch_rejected"
    );
    fixture.reply.store(0, Ordering::SeqCst);
    ensure!(
        monitor::run_round(&state, monitor::Purpose::Monitor).passed && !state.is_tripped(),
        "pass_recovers"
    );
    monitor::pause(&state, 1);
    fixture.reply.store(1, Ordering::SeqCst);
    monitor::run_round(&state, monitor::Purpose::Monitor);
    monitor::run_round(&state, monitor::Purpose::Monitor);
    ensure!(!state.is_tripped(), "paused_failure_does_not_trip");
    ensure!(
        monitor::launch(&state).is_err(),
        "paused_failure_still_rejects_launch"
    );
    monitor::resume(&state);
    monitor::release(&state);
    ensure!(
        monitor::launch(&state).is_err() && state.is_tripped(),
        "manual_release_does_not_bypass_launch_probe"
    );
    fixture.reply.store(0, Ordering::SeqCst);
    ensure!(
        monitor::run_round(&state, monitor::Purpose::Monitor).passed,
        "final_recovery"
    );
    for t in &mut cfg.targets {
        t.enabled = false;
    }
    state.set_config(cfg);
    ensure!(
        monitor::launch(&state).is_err(),
        "no_enabled_targets_rejects_launch"
    );
    ensure!(
        !crate::config::config_dir().join("netcut.json").exists(),
        "no_network_state_created"
    );
    state.stop.store(true, Ordering::SeqCst);
    Ok(
        serde_json::json!({"passed":true,"cases":checked,"proxyRequests":fixture.seen.load(Ordering::SeqCst),"scope":"native scheduler, synthetic loopback probes, destructive actions disabled"}),
    )
}
