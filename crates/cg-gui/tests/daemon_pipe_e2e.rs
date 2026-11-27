//! Live Windows Named Pipe integration tests verifying `cg_gui::ipc::DaemonClient`
//! interoperates cleanly with real `claudeguard-daemon.exe --console`.

use cg_gui::ipc::{DaemonClient, TransportEndpoint, TransportError};
use cg_gui::protocol::{
    AnchorKind, Config, CutMode, Lifecycle, PipeRequest, PipeResponse, PolicyPreset, ThemeMode,
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static E2E_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let n = E2E_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp e2e data dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn locate_daemon_bin() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("CG_DAEMON_BIN") {
        let pb = PathBuf::from(env_path);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join(r"..\..\target-ws\debug\claudeguard-daemon.exe"),
        manifest_dir.join(r"..\..\target-ws\release\claudeguard-daemon.exe"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

fn unique_pipe() -> String {
    let n = E2E_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\cg-gui-e2e-{}-{n}", std::process::id())
}

fn safe_test_config() -> Config {
    let mut cfg = Config {
        first_run: false,
        enforce_access_path: false,
        kill_on_fail: false,
        quarantine_on_fail: false,
        cut_mode: CutMode::Off,
        lockdown_on_uncovered: false,
        sweep_on_exit: false,
        leak_watch: false,
        leak_trip: false,
        env_check: false,
        env_align_tz: false,
        env_align_location: false,
        ..Default::default()
    };
    cfg.notify.enabled = false;
    for target in &mut cfg.targets {
        if target.anchor_kind != AnchorKind::Reachability {
            target.expect_ips = vec!["198.51.100.98".into()];
            target.expect_regions.clear();
        }
    }
    cfg
}

#[test]
fn disconnected_pipe_fails_closed_with_daemon_offline() {
    let missing_pipe = unique_pipe();
    let client = DaemonClient::new(TransportEndpoint::Pipe(missing_pipe));
    let err = client
        .exchange(PipeRequest::GetSnapshot)
        .expect_err("missing daemon pipe must fail closed");
    assert!(
        matches!(err, TransportError::DaemonOffline(_)),
        "expected DaemonOffline, got {err:?}"
    );
}

#[test]
fn gui_daemon_client_roundtrips_live_daemon_over_named_pipe() {
    let daemon_bin = locate_daemon_bin().expect(
        "claudeguard-daemon.exe must exist at D:\\ClaudeGuard-v4\\target-ws\\debug\\claudeguard-daemon.exe or CG_DAEMON_BIN",
    );
    let data_dir = TempDirGuard::new("cg-gui-e2e");
    let pipe = unique_pipe();

    let child = Command::new(&daemon_bin)
        .args([
            "--console",
            "--pipe",
            &pipe,
            "--data-dir",
            &data_dir.path().to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn claudeguard-daemon --console");
    let _child_guard = ChildGuard(child);

    let client = DaemonClient::new(TransportEndpoint::Pipe(pipe.clone()));
    let deadline = Instant::now() + Duration::from_secs(5);
    let initial_snap = loop {
        match client.exchange(PipeRequest::GetSnapshot) {
            Ok(PipeResponse::Snapshot { snapshot }) => break *snapshot,
            Ok(other) => panic!("unexpected GetSnapshot response: {other:?}"),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(err) => panic!("timed out connecting to {pipe}: {err}"),
        }
    };
    assert_eq!(initial_snap.lifecycle, Lifecycle::Unconfigured);

    // Complete onboarding so the daemon enters Lifecycle::Armed.
    let mut cfg = safe_test_config();
    match client
        .exchange(PipeRequest::CompleteOnboarding {
            config: cfg.clone(),
        })
        .expect("CompleteOnboarding")
    {
        PipeResponse::Ack {
            snapshot: Some(snap),
            ..
        } => {
            assert_eq!(snap.lifecycle, Lifecycle::Armed);
        }
        other => panic!("unexpected CompleteOnboarding response: {other:?}"),
    }

    // SaveConfig roundtrip verifies theme/privacy-mask/port persistence.
    cfg.theme_mode = ThemeMode::Dark;
    cfg.privacy_mask_ip = true;
    cfg.proxy_port = 7899;
    match client
        .exchange(PipeRequest::SaveConfig { config: cfg })
        .expect("SaveConfig")
    {
        PipeResponse::Ack {
            snapshot: Some(snap),
            ..
        } => {
            assert_eq!(snap.theme_mode, ThemeMode::Dark);
            assert!(snap.privacy_mask_ip);
            assert_eq!(snap.config.proxy_port, 7899);
        }
        other => panic!("unexpected SaveConfig response: {other:?}"),
    }

    // SetPolicyPreset roundtrip.
    match client
        .exchange(PipeRequest::SetPolicyPreset {
            preset: PolicyPreset::StrictStaticIp,
        })
        .expect("SetPolicyPreset")
    {
        PipeResponse::Ack {
            snapshot: Some(snap),
            ..
        } => {
            assert_eq!(snap.preset, PolicyPreset::StrictStaticIp);
        }
        other => panic!("unexpected SetPolicyPreset response: {other:?}"),
    }

    // DisarmAndRestoreFlowB roundtrip transitions to Disarmed and blocks launch gate.
    match client
        .exchange(PipeRequest::DisarmAndRestoreFlowB {
            reason: Some("gui e2e flow B".into()),
        })
        .expect("DisarmAndRestoreFlowB")
    {
        PipeResponse::Ack {
            snapshot: Some(snap),
            ..
        } => {
            assert_eq!(snap.lifecycle, Lifecycle::Disarmed);
        }
        other => panic!("unexpected DisarmAndRestoreFlowB response: {other:?}"),
    }

    match client
        .exchange(PipeRequest::CheckLaunchGate {
            agent_id: Some("claude".into()),
        })
        .expect("CheckLaunchGate while disarmed")
    {
        PipeResponse::LaunchGate { allowed, .. } => assert!(!allowed),
        other => panic!("unexpected CheckLaunchGate response: {other:?}"),
    }

    // Rearm roundtrip returns to Lifecycle::Armed.
    match client.exchange(PipeRequest::Rearm).expect("Rearm") {
        PipeResponse::Ack {
            snapshot: Some(snap),
            ..
        } => {
            assert_eq!(snap.lifecycle, Lifecycle::Armed);
        }
        other => panic!("unexpected Rearm response: {other:?}"),
    }

    // QueryLogs roundtrip returns structured audit log entries recorded by daemon.
    match client
        .exchange(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(50),
            query: None,
            level: None,
        })
        .expect("QueryLogs")
    {
        PipeResponse::Logs { entries, total } => {
            assert!(!entries.is_empty());
            assert!(total >= entries.len());
        }
        other => panic!("unexpected QueryLogs response: {other:?}"),
    }
}

#[test]
fn onboarding_from_default_config_arms_daemon_without_reprompting() {
    let daemon_bin = locate_daemon_bin().expect(
        "claudeguard-daemon.exe must exist at D:\\ClaudeGuard-v4\\target-ws\\debug\\claudeguard-daemon.exe or CG_DAEMON_BIN",
    );
    let data_dir = TempDirGuard::new("cg-gui-onboard-e2e");
    let pipe = unique_pipe();

    let child = Command::new(&daemon_bin)
        .args([
            "--console",
            "--pipe",
            &pipe,
            "--data-dir",
            &data_dir.path().to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn claudeguard-daemon --console");
    let _child_guard = ChildGuard(child);

    let client = DaemonClient::new(TransportEndpoint::Pipe(pipe.clone()));
    let deadline = Instant::now() + Duration::from_secs(5);
    let initial_snap = loop {
        match client.exchange(PipeRequest::GetSnapshot) {
            Ok(PipeResponse::Snapshot { snapshot }) => break *snapshot,
            Ok(other) => panic!("unexpected GetSnapshot response: {other:?}"),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(err) => panic!("timed out connecting to {pipe}: {err}"),
        }
    };
    assert_eq!(initial_snap.lifecycle, Lifecycle::Unconfigured);
    assert!(initial_snap.config.first_run);

    // Simulate a fresh-install onboarding payload where `local` is disabled and left empty
    // while enabled `claude`/`codex` carry the selected country allowlist.
    let mut cfg = initial_snap.config.clone();
    cfg.first_run = false;
    cfg.enforce_access_path = false;
    cfg.kill_on_fail = false;
    cfg.quarantine_on_fail = false;
    cfg.lockdown_on_uncovered = false;
    cfg.sweep_on_exit = false;
    cfg.leak_watch = false;
    cfg.env_check = false;
    cfg.notify.enabled = false;
    for target in &mut cfg.targets {
        if matches!(target.id.as_str(), "claude" | "codex") {
            target.enabled = true;
            target.expect_regions = vec!["US".into()];
            target.expect_ips.clear();
        }
    }

    match client
        .exchange(PipeRequest::CompleteOnboarding { config: cfg })
        .expect("CompleteOnboarding")
    {
        PipeResponse::Ack {
            snapshot: Some(snap),
            ..
        } => {
            assert_eq!(snap.lifecycle, Lifecycle::Armed);
            assert!(!snap.config.first_run);
        }
        other => panic!("unexpected CompleteOnboarding response: {other:?}"),
    }

    // Subsequent poll must stay Armed so the onboarding modal never re-opens.
    match client
        .exchange(PipeRequest::GetSnapshot)
        .expect("post-onboarding GetSnapshot")
    {
        PipeResponse::Snapshot { snapshot } => {
            assert_eq!(snapshot.lifecycle, Lifecycle::Armed);
            assert!(!snapshot.config.first_run);
        }
        other => panic!("unexpected post-onboarding GetSnapshot response: {other:?}"),
    }
}
