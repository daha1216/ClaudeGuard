//! End-to-end integration tests spawning real `claudeguard-daemon.exe` and `claudeguard-cli.exe`.

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use cg_daemon::disarm;
use cg_daemon::ipc_pipe::PipeClient;
use cg_daemon::journal::{
    BaselineState, FirewallDirection, JournalStore, PlannedStep, TxKind, WalAction,
};
use cg_daemon::protocol::{AnchorKind, Config, PipeRequest, PipeResponse};

static INT_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_pipe() -> String {
    let n = INT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\ClaudeGuardV4-int-{}-{n}", std::process::id())
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn real_daemon_console_and_cli_binaries_roundtrip() {
    let cli_bin = env!("CARGO_BIN_EXE_claudeguard-cli");
    let daemon_bin = env!("CARGO_BIN_EXE_claudeguard-daemon");

    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();

    // Pre-plant a WAL journal to verify daemon --console heals it on startup.
    let store = JournalStore::new(dir.path());
    store
        .begin_tx(
            1,
            TxKind::Quarantine,
            vec![PlannedStep {
                step_id: 1,
                description: "crash residue".into(),
                action: WalAction::AddFirewallRule {
                    rule_name: "ClaudeGuard Block Out (claude)".into(),
                    program: None,
                    direction: FirewallDirection::Outbound,
                },
            }],
            BaselineState::default(),
        )
        .unwrap();
    assert!(store.path().exists());

    let child = Command::new(daemon_bin)
        .env("CG_TEST_NO_OS_FIREWALL", "1")
        .args([
            "--console",
            "--pipe",
            &pipe,
            "--data-dir",
            &dir.path().to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn claudeguard-daemon --console");
    let _guard = ChildGuard(child);

    // Wait up to 8s for Named Pipe endpoint to accept connections (debug builds scan process tree on boot).
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut client = loop {
        match PipeClient::connect(&pipe, 100) {
            Ok(c) => break c,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => panic!("timed out connecting to daemon console pipe {pipe}: {err}"),
        }
    };

    // Journal was healed on startup before pipe server started.
    assert!(!store.path().exists());

    // Complete onboarding via IPC so daemon transitions from Unconfigured -> Armed.
    // Use an RFC 5737 TEST-NET-2 IP so `--check` deterministically returns exit code 2 even if a local proxy exists.
    let mut cfg = Config {
        first_run: false,
        enforce_access_path: false,
        ..Default::default()
    };
    for target in &mut cfg.targets {
        if target.anchor_kind != AnchorKind::Reachability {
            target.expect_ips = vec!["198.51.100.98".into()];
            target.expect_regions.clear();
        }
    }
    let onboard = client
        .call(&PipeRequest::CompleteOnboarding { config: cfg })
        .unwrap();
    assert!(matches!(onboard, PipeResponse::Ack { .. }));
    drop(client);

    // `claudeguard-cli --status` returns exit 0 and JSON daemon_online=true.
    let status_out = Command::new(cli_bin)
        .env("CG_TEST_NO_OS_FIREWALL", "1")
        .args([
            "--status",
            "--pipe",
            &pipe,
            "--data-dir",
            &dir.path().to_string_lossy(),
        ])
        .output()
        .expect("run claudeguard-cli --status");
    assert_eq!(status_out.status.code(), Some(0));
    let status_json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["daemon_online"], true);

    // `claudeguard-cli --check` returns exit 2 because daemon hasn't passed an egress round yet.
    let check_out = Command::new(cli_bin)
        .env("CG_TEST_NO_OS_FIREWALL", "1")
        .args(["--check", "--pipe", &pipe])
        .output()
        .expect("run claudeguard-cli --check");
    assert_eq!(check_out.status.code(), Some(2));
    let check_json: serde_json::Value = serde_json::from_slice(&check_out.stdout).unwrap();
    assert_eq!(check_json["daemon_online"], true);
    assert_eq!(check_json["passed"], false);

    // `claudeguard-cli --restore` hits live pipe -> Flow B disarm -> exit 0.
    let restore_out = Command::new(cli_bin)
        .env("CG_TEST_NO_OS_FIREWALL", "1")
        .args([
            "--restore",
            "--pipe",
            &pipe,
            "--data-dir",
            &dir.path().to_string_lossy(),
        ])
        .output()
        .expect("run claudeguard-cli --restore");
    assert_eq!(restore_out.status.code(), Some(0));
    let restore_json: serde_json::Value = serde_json::from_slice(&restore_out.stdout).unwrap();
    assert_eq!(restore_json["ok"], true);
    assert_eq!(restore_json["mode"], "online_pipe");
    assert!(disarm::read_disarmed(dir.path()).unwrap().is_some());
}

#[test]
fn real_cli_restore_falls_back_to_offline_wal_when_daemon_absent() {
    let cli_bin = env!("CARGO_BIN_EXE_claudeguard-cli");
    let dir = tempfile::tempdir().unwrap();
    let missing_pipe = unique_pipe();

    let store = JournalStore::new(dir.path());
    store
        .begin_tx(
            99,
            TxKind::GlobalCut,
            vec![PlannedStep {
                step_id: 1,
                description: "offline crash cut".into(),
                action: WalAction::GlobalFirewallCut {
                    rule_name: "ClaudeGuard Cut All".into(),
                },
            }],
            BaselineState::default(),
        )
        .unwrap();

    let out = Command::new(cli_bin)
        .env("CG_TEST_NO_OS_FIREWALL", "1")
        .args([
            "--restore",
            "--pipe",
            &missing_pipe,
            "--data-dir",
            &dir.path().to_string_lossy(),
            "--timeout-ms",
            "100",
        ])
        .output()
        .expect("run offline claudeguard-cli --restore");

    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["mode"], "offline_wal");
    assert_eq!(json["verified"], true);
    assert!(!store.path().exists());
    assert!(disarm::read_disarmed(dir.path()).unwrap().is_some());
}
