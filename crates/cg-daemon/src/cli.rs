//! Scriptable and emergency CLI (`claudeguard-cli`) implementation.
//!
//! Commands:
//! - `--check` / `check`: queries daemon snapshot (with optional `--recheck`), prints structured JSON,
//!   exits `0` if passed or `2` if not passed (including offline/unconfigured/disarmed/unverified).
//! - `--restore` / `restore`: contacts live daemon over Named Pipe for Flow B disarm & restore,
//!   automatically falling back to offline WAL journal recovery when the service is down.
//! - `--status` / `status`: prints service, WAL journal, disarm marker, and live snapshot status as JSON.

use std::path::{Path, PathBuf};

use crate::disarm;
use crate::ipc_pipe::{resolve_pipe_name, PipeClient, PipeError};
use crate::journal::{self, JournalStore, LoadedJournal, RecoveryExecutor};
use crate::protocol::{snapshot_is_check_passed, PipeRequest, PipeResponse, DAEMON_VERSION};
use crate::service_win;

/// Parsed CLI command mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    Check { recheck: bool },
    Restore,
    Status,
    Version,
    Help,
}

/// Parsed CLI options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliArgs {
    pub command: CliCommand,
    pub pipe_name: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub timeout_ms: u32,
}

/// Structured output returned by [`run_cli_with_executor`].
#[derive(Clone, Debug)]
pub struct CliOutput {
    pub exit_code: i32,
    pub json: Option<serde_json::Value>,
    pub text: Option<String>,
    pub stderr: Option<String>,
}

const HELP_TEXT: &str = "\
ClaudeGuard v4 CLI (claudeguard-cli)

USAGE:
    claudeguard-cli [--check | --restore | --status] [OPTIONS]

COMMANDS:
    --check,   check     Verify egress compliance via daemon; exit 0=pass, 2=not passed
    --restore, restore   Disarm and restore network/firewall (live pipe or offline WAL fallback)
    --status,  status    Print daemon, Windows Service, and WAL journal status JSON
    --version            Print version
    --help, -h           Print this help

OPTIONS:
    --recheck            With --check: trigger RecheckNow before reading snapshot
    --pipe <NAME>        Override Named Pipe (or set CG_PIPE_NAME)
    --data-dir <PATH>    Override WAL data dir (or set CG_DATA_DIR)
    --timeout-ms <MS>    Pipe connect timeout in milliseconds (default: 3000)
";

/// Parses command-line arguments (excluding `argv[0]`).
pub fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut command: Option<CliCommand> = None;
    let mut recheck = false;
    let mut pipe_name: Option<String> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut timeout_ms: u32 = 3000;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--check" | "check" => command = Some(CliCommand::Check { recheck }),
            "--restore" | "restore" => command = Some(CliCommand::Restore),
            "--status" | "status" => command = Some(CliCommand::Status),
            "--version" | "-V" => command = Some(CliCommand::Version),
            "--help" | "-h" => command = Some(CliCommand::Help),
            "--recheck" => {
                recheck = true;
                if let Some(CliCommand::Check { recheck: ref mut r }) = command {
                    *r = true;
                }
            }
            "--pipe" => {
                i += 1;
                let val = args.get(i).ok_or("--pipe requires a value")?;
                pipe_name = Some(val.clone());
            }
            "--data-dir" => {
                i += 1;
                let val = args.get(i).ok_or("--data-dir requires a value")?;
                data_dir = Some(PathBuf::from(val));
            }
            "--timeout-ms" => {
                i += 1;
                let val = args.get(i).ok_or("--timeout-ms requires a value")?;
                timeout_ms = val
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --timeout-ms value: {val}"))?;
            }
            other => {
                return Err(format!("unknown argument '{other}' (run with --help)"));
            }
        }
        i += 1;
    }

    let command = command.unwrap_or(CliCommand::Help);
    Ok(CliArgs {
        command,
        pipe_name,
        data_dir,
        timeout_ms,
    })
}

/// Executes a CLI invocation with injectable pipe/data-dir defaults and offline [`RecoveryExecutor`].
pub fn run_cli_with_executor(
    args: &[String],
    default_pipe: Option<&str>,
    default_data_dir: Option<&Path>,
    offline_executor: &dyn RecoveryExecutor,
) -> CliOutput {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(err) => {
            return CliOutput {
                exit_code: 1,
                json: Some(serde_json::json!({
                    "ok": false,
                    "error": err,
                })),
                text: None,
                stderr: Some(err),
            };
        }
    };

    let pipe_name = resolve_pipe_name(parsed.pipe_name.as_deref().or(default_pipe));
    let data_dir = journal::resolve_data_dir(parsed.data_dir.as_deref().or(default_data_dir));

    match parsed.command {
        CliCommand::Version => CliOutput {
            exit_code: 0,
            json: None,
            text: Some(format!("claudeguard-cli {DAEMON_VERSION}")),
            stderr: None,
        },
        CliCommand::Help => CliOutput {
            exit_code: 0,
            json: None,
            text: Some(HELP_TEXT.to_string()),
            stderr: None,
        },
        CliCommand::Check { recheck } => run_check(&pipe_name, parsed.timeout_ms, recheck),
        CliCommand::Restore => {
            run_restore(&pipe_name, &data_dir, parsed.timeout_ms, offline_executor)
        }
        CliCommand::Status => run_status(&pipe_name, &data_dir, parsed.timeout_ms),
    }
}

fn run_check(pipe_name: &str, timeout_ms: u32, recheck: bool) -> CliOutput {
    let mut client = match PipeClient::connect(pipe_name, timeout_ms) {
        Ok(c) => c,
        Err(err) => {
            return CliOutput {
                exit_code: 2,
                json: Some(serde_json::json!({
                    "version": DAEMON_VERSION,
                    "daemon_online": false,
                    "passed": false,
                    "pipe": pipe_name,
                    "error": err.to_string(),
                })),
                text: None,
                stderr: None,
            };
        }
    };

    if recheck {
        if let Err(err) = client.call(&PipeRequest::RecheckNow { target_id: None }) {
            return CliOutput {
                exit_code: 2,
                json: Some(serde_json::json!({
                    "version": DAEMON_VERSION,
                    "daemon_online": true,
                    "passed": false,
                    "pipe": pipe_name,
                    "error": format!("recheck IPC error: {err}"),
                })),
                text: None,
                stderr: None,
            };
        }
    }

    match client.call(&PipeRequest::GetSnapshot) {
        Ok(PipeResponse::Snapshot { snapshot }) => {
            let passed = snapshot_is_check_passed(&snapshot);
            CliOutput {
                exit_code: if passed { 0 } else { 2 },
                json: Some(serde_json::json!({
                    "version": DAEMON_VERSION,
                    "daemon_online": true,
                    "passed": passed,
                    "lifecycle": snapshot.lifecycle,
                    "protection": snapshot.protection,
                    "preset": snapshot.preset,
                    "access_level": snapshot.access.level,
                    "last_error": snapshot.last_error,
                    "tripped": snapshot.tripped,
                    "checked_at": snapshot.checked_at,
                    "targets": snapshot.targets,
                })),
                text: None,
                stderr: None,
            }
        }
        Ok(PipeResponse::Error {
            code,
            message,
            receipt: _,
        }) => CliOutput {
            exit_code: 2,
            json: Some(serde_json::json!({
                "version": DAEMON_VERSION,
                "daemon_online": true,
                "passed": false,
                "error_code": code,
                "error": message,
            })),
            text: None,
            stderr: None,
        },
        Ok(other) => CliOutput {
            exit_code: 2,
            json: Some(serde_json::json!({
                "version": DAEMON_VERSION,
                "daemon_online": true,
                "passed": false,
                "error": format!("unexpected IPC response: {other:?}"),
            })),
            text: None,
            stderr: None,
        },
        Err(err) => CliOutput {
            exit_code: 2,
            json: Some(serde_json::json!({
                "version": DAEMON_VERSION,
                "daemon_online": false,
                "passed": false,
                "error": err.to_string(),
            })),
            text: None,
            stderr: None,
        },
    }
}

fn run_restore(
    pipe_name: &str,
    data_dir: &Path,
    timeout_ms: u32,
    offline_executor: &dyn RecoveryExecutor,
) -> CliOutput {
    match PipeClient::connect(pipe_name, timeout_ms) {
        Ok(mut client) => {
            match client.call(&PipeRequest::DisarmAndRestoreFlowB {
                reason: Some("claudeguard-cli --restore".to_string()),
            }) {
                Ok(PipeResponse::Ack { receipt, snapshot }) => {
                    let verified = receipt
                        .as_ref()
                        .is_none_or(|r| r.status.is_verified_or_na());
                    let disarm_marked = verified
                        && snapshot
                            .as_ref()
                            .is_some_and(|s| s.lifecycle == crate::protocol::Lifecycle::Disarmed);
                    let err_msg = if verified {
                        None
                    } else {
                        Some(
                            receipt
                                .as_ref()
                                .and_then(|r| r.error.clone())
                                .unwrap_or_else(|| "Flow B verification failed".to_string()),
                        )
                    };
                    CliOutput {
                        exit_code: if verified { 0 } else { 1 },
                        json: Some(serde_json::json!({
                            "ok": verified,
                            "mode": "online_pipe",
                            "verified": verified,
                            "disarm_marked": disarm_marked,
                            "error": err_msg,
                            "receipt": receipt,
                            "lifecycle": snapshot.map(|s| s.lifecycle),
                        })),
                        text: None,
                        stderr: err_msg,
                    }
                }
                Ok(PipeResponse::Error {
                    code,
                    message,
                    receipt,
                }) => CliOutput {
                    exit_code: 1,
                    json: Some(serde_json::json!({
                        "ok": false,
                        "mode": "online_pipe",
                        "verified": false,
                        "error_code": code,
                        "error": message,
                        "receipt": receipt,
                    })),
                    text: None,
                    stderr: Some(message),
                },
                Ok(other) => CliOutput {
                    exit_code: 1,
                    json: Some(serde_json::json!({
                        "ok": false,
                        "mode": "online_pipe",
                        "verified": false,
                        "error": format!("unexpected IPC response: {other:?}"),
                    })),
                    text: None,
                    stderr: Some("unexpected IPC response".into()),
                },
                Err(err) if should_fallback_offline(&err) => {
                    run_offline_restore(data_dir, offline_executor, Some(err.to_string()))
                }
                Err(err) => CliOutput {
                    exit_code: 1,
                    json: Some(serde_json::json!({
                        "ok": false,
                        "mode": "online_pipe",
                        "verified": false,
                        "error": err.to_string(),
                    })),
                    text: None,
                    stderr: Some(err.to_string()),
                },
            }
        }
        Err(err) if should_fallback_offline(&err) => {
            run_offline_restore(data_dir, offline_executor, Some(err.to_string()))
        }
        Err(err) => CliOutput {
            exit_code: 1,
            json: Some(serde_json::json!({
                "ok": false,
                "mode": "online_pipe",
                "verified": false,
                "error": err.to_string(),
            })),
            text: None,
            stderr: Some(err.to_string()),
        },
    }
}

fn should_fallback_offline(err: &PipeError) -> bool {
    matches!(
        err,
        PipeError::NotFound(_)
            | PipeError::BusyTimeout(_)
            | PipeError::Disconnected
            | PipeError::UnsupportedPlatform
    )
}

fn is_cli_elevated() -> bool {
    cg_platform::access_win::is_elevated().unwrap_or(true)
}

fn run_offline_restore(
    data_dir: &Path,
    offline_executor: &dyn RecoveryExecutor,
    pipe_note: Option<String>,
) -> CliOutput {
    let store = JournalStore::new(data_dir);
    let report = journal::heal_offline(&store, offline_executor);
    let _ = cg_platform::leak_shield_win::clear_leak_shield();
    let env_rollback_err = crate::diagnostics::rollback_env_alignment(data_dir).err();

    let mut disarm_marked = false;
    let mut disarm_error = None;

    if report.ok && report.verified && env_rollback_err.is_none() {
        match disarm::mark_disarmed(data_dir, "claudeguard-cli --restore (offline)") {
            Ok(()) => disarm_marked = true,
            Err(err) => disarm_error = Some(err),
        }
    }

    let ok = report.ok && report.verified && env_rollback_err.is_none() && disarm_error.is_none();
    let elevated = is_cli_elevated();
    let elevation_hint = if !ok && !elevated {
        Some(
            "离线清理防火墙规则或还原系统设置需要管理员权限，请以管理员身份重新运行 `claudeguard-cli --restore` (Administrator privileges required: please re-run `claudeguard-cli --restore` in an elevated terminal).".to_string(),
        )
    } else {
        None
    };

    let stderr = if ok {
        None
    } else {
        let base_err = disarm_error
            .clone()
            .or_else(|| env_rollback_err.clone())
            .unwrap_or_else(|| report.summary.clone());
        Some(match &elevation_hint {
            Some(hint) => format!("{base_err}\n{hint}"),
            None => base_err,
        })
    };

    CliOutput {
        exit_code: if ok { 0 } else { 1 },
        json: Some(serde_json::json!({
            "ok": ok,
            "mode": "offline_wal",
            "verified": report.verified,
            "elevated": elevated,
            "elevation_hint": elevation_hint,
            "env_rollback_error": env_rollback_err,
            "disarm_marked": disarm_marked,
            "disarm_error": disarm_error,
            "pipe_fallback_reason": pipe_note,
            "data_dir": data_dir.display().to_string(),
            "report": report,
        })),
        text: None,
        stderr,
    }
}

fn run_status(pipe_name: &str, data_dir: &Path, timeout_ms: u32) -> CliOutput {
    let service_state = service_win::query_service_status()
        .map(|s| serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!("unknown")))
        .unwrap_or_else(|e| serde_json::json!({"error": e}));

    let store = JournalStore::new(data_dir);
    let journal_state = match store.load() {
        LoadedJournal::NotFound => serde_json::json!({"state": "clean"}),
        LoadedJournal::Uncommitted(j) => serde_json::json!({
            "state": "uncommitted",
            "tx_id": j.tx_id,
            "epoch": j.epoch,
            "kind": j.kind,
        }),
        LoadedJournal::Committed(j) => serde_json::json!({
            "state": "committed_active",
            "tx_id": j.tx_id,
            "epoch": j.epoch,
            "kind": j.kind,
        }),
        LoadedJournal::Corrupt(err) => serde_json::json!({"state": "corrupt", "error": err}),
        LoadedJournal::Unreadable(err) => serde_json::json!({"state": "unreadable", "error": err}),
    };

    let disarm_marker = disarm::read_disarmed(data_dir).ok().flatten();

    match PipeClient::connect(pipe_name, timeout_ms)
        .and_then(|mut client| client.call(&PipeRequest::GetSnapshot))
    {
        Ok(PipeResponse::Snapshot { snapshot }) => CliOutput {
            exit_code: 0,
            json: Some(serde_json::json!({
                "version": DAEMON_VERSION,
                "daemon_online": true,
                "pipe": pipe_name,
                "data_dir": data_dir.display().to_string(),
                "service_state": service_state,
                "journal": journal_state,
                "disarmed": disarm_marker,
                "snapshot": snapshot,
            })),
            text: None,
            stderr: None,
        },
        Ok(other) => CliOutput {
            exit_code: 1,
            json: Some(serde_json::json!({
                "version": DAEMON_VERSION,
                "daemon_online": false,
                "pipe": pipe_name,
                "data_dir": data_dir.display().to_string(),
                "service_state": service_state,
                "journal": journal_state,
                "disarmed": disarm_marker,
                "error": format!("unexpected response: {other:?}"),
            })),
            text: None,
            stderr: None,
        },
        Err(err) => CliOutput {
            exit_code: 1,
            json: Some(serde_json::json!({
                "version": DAEMON_VERSION,
                "daemon_online": false,
                "pipe": pipe_name,
                "data_dir": data_dir.display().to_string(),
                "service_state": service_state,
                "journal": journal_state,
                "disarmed": disarm_marker,
                "error": err.to_string(),
            })),
            text: None,
            stderr: None,
        },
    }
}

/// Convenience entrypoint used by `src/bin/claudeguard-cli.rs`.
pub fn run_from_env(offline_executor: &dyn RecoveryExecutor) -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = run_cli_with_executor(&args, None, None, offline_executor);
    if let Some(json) = out.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string())
        );
    } else if let Some(text) = out.text {
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
    }
    if let Some(err) = out.stderr {
        eprintln!("{err}");
    }
    out.exit_code
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::engine_runtime::ProbeRunner;
    use crate::journal::tests::{MockRecoveryExecutor, MockRecoveryState};
    use crate::journal::{BaselineState, PlannedStep, TxKind, WalAction};
    use crate::protocol::{
        AccessEvidence, AccessLevel, Config, Lifecycle, ProbeResult, ProtectionState, Target,
        TargetState,
    };
    use crate::service_win::{DaemonConfig, DaemonRuntime, ShutdownPolicy, StopBehavior};
    use cg_platform::{PlatformDriver, UnsupportedPlatformDriver};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    static CLI_PIPE_SEQ: AtomicU64 = AtomicU64::new(1);

    fn test_pipe() -> String {
        let n = CLI_PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\ClaudeGuardV4-cli-{}-{n}", std::process::id())
    }

    struct SwitchableProbeRunner {
        pass: Arc<AtomicBool>,
    }

    impl ProbeRunner for SwitchableProbeRunner {
        fn inspect_and_probe(
            &self,
            _driver: &dyn PlatformDriver,
            _cfg: &Config,
            cfg_rev: u64,
            targets: &[Target],
            _enforce_access_path: bool,
            _skip_network_probes: bool,
            now_secs: u64,
        ) -> (AccessEvidence, Vec<(String, ProbeResult)>) {
            let passing = self.pass.load(Ordering::Acquire);
            let access = AccessEvidence {
                level: AccessLevel::Tun,
                observed_at: now_secs,
                revision: cfg_rev,
                note: "test tun".into(),
                ..AccessEvidence::default()
            };
            let results = targets
                .iter()
                .filter(|t| t.enabled)
                .map(|t| {
                    let probe = if passing {
                        ProbeResult {
                            reachable: true,
                            status: Some(200),
                            ip: Some("198.51.100.98".into()),
                            country: Some("US".into()),
                            raw_region: Some("US".into()),
                            colo: Some("SJC".into()),
                            city: None,
                            latency_ms: 25,
                            parsed_as: "trace".into(),
                            detail: "ok".into(),
                        }
                    } else {
                        ProbeResult {
                            reachable: true,
                            status: Some(200),
                            ip: Some("203.0.113.45".into()),
                            country: Some("CN".into()),
                            raw_region: Some("CN".into()),
                            colo: None,
                            city: None,
                            latency_ms: 80,
                            parsed_as: "trace".into(),
                            detail: "region mismatch".into(),
                        }
                    };
                    (t.id.clone(), probe)
                })
                .collect();
            (access, results)
        }
    }

    fn valid_test_config() -> Config {
        let mut cfg = Config {
            first_run: false,
            enforce_access_path: false,
            trip_threshold: 1,
            ..Default::default()
        };
        for target in &mut cfg.targets {
            target.expect_regions = vec!["US".into()];
        }
        cfg
    }

    #[test]
    fn cli_check_returns_0_on_pass_and_2_on_fail_or_offline() {
        let dir = tempfile::tempdir().unwrap();
        let pipe = test_pipe();
        let exec = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let driver: Arc<dyn PlatformDriver> = Arc::new(UnsupportedPlatformDriver::default());
        let pass_flag = Arc::new(AtomicBool::new(true));
        let runner: Arc<dyn ProbeRunner> = Arc::new(SwitchableProbeRunner {
            pass: pass_flag.clone(),
        });

        // Offline daemon => exit code 2.
        let offline_out = run_cli_with_executor(
            &["--check".into(), "--timeout-ms".into(), "100".into()],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(offline_out.exit_code, 2);
        assert_eq!(offline_out.json.unwrap()["passed"], false);

        let rt = DaemonRuntime::start(
            DaemonConfig {
                pipe_name: pipe.clone(),
                data_dir: dir.path().to_path_buf(),
                shutdown_policy: ShutdownPolicy::default(),
                service_mode: false,
                enable_background_loop: false,
            },
            driver,
            runner,
            exec.clone(),
        )
        .unwrap();

        // Unconfigured => exit code 2.
        let uncfg_out =
            run_cli_with_executor(&["--check".into()], Some(&pipe), Some(dir.path()), &*exec);
        assert_eq!(uncfg_out.exit_code, 2);

        // Complete onboarding with valid config, then RecheckNow => Pass (exit 0).
        let mut client = PipeClient::connect(&pipe, 2000).unwrap();
        let resp = client
            .call(&PipeRequest::CompleteOnboarding {
                config: valid_test_config(),
            })
            .unwrap();
        assert!(matches!(resp, PipeResponse::Ack { .. }));
        drop(client);

        let pass_out = run_cli_with_executor(
            &["--check".into(), "--recheck".into()],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(pass_out.exit_code, 0);
        let pass_json = pass_out.json.unwrap();
        assert_eq!(pass_json["passed"], true);
        assert_eq!(pass_json["lifecycle"], serde_json::json!("armed"));

        // Flip probe to mismatching region and recheck => fails check (exit 2).
        pass_flag.store(false, Ordering::Release);
        let fail_out = run_cli_with_executor(
            &["--check".into(), "--recheck".into()],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(fail_out.exit_code, 2);
        assert_eq!(fail_out.json.unwrap()["passed"], false);

        // Unverified target also fails check via snapshot.
        rt.coordinator().update_snapshot(|s| {
            s.protection = ProtectionState::Monitoring;
            for t in &mut s.targets {
                t.state = TargetState::Pass;
            }
            if let Some(first) = s.targets.iter_mut().find(|t| t.id == "claude") {
                first.state = TargetState::Unverified;
            }
        });
        let unverified_out =
            run_cli_with_executor(&["--check".into()], Some(&pipe), Some(dir.path()), &*exec);
        assert_eq!(unverified_out.exit_code, 2);
        assert_eq!(unverified_out.json.unwrap()["passed"], false);

        // Status returns exit 0 while online.
        let status_out =
            run_cli_with_executor(&["--status".into()], Some(&pipe), Some(dir.path()), &*exec);
        assert_eq!(status_out.exit_code, 0);
        assert_eq!(status_out.json.unwrap()["daemon_online"], true);

        rt.shutdown_graceful(StopBehavior::RunFlowBCleanup).unwrap();
    }

    #[test]
    fn cli_restore_works_online_via_pipe_and_falls_back_to_offline_wal_when_down() {
        let dir = tempfile::tempdir().unwrap();
        let pipe = test_pipe();

        // 1) Offline WAL fallback when daemon pipe does not exist.
        let store = JournalStore::new(dir.path());
        store
            .begin_tx(
                12,
                TxKind::GlobalCut,
                vec![PlannedStep {
                    step_id: 1,
                    description: "global cut".into(),
                    action: WalAction::GlobalFirewallCut {
                        rule_name: "ClaudeGuard Cut All".into(),
                    },
                }],
                BaselineState::default(),
            )
            .unwrap();
        let exec = Arc::new(MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec!["ClaudeGuard Cut All".into()],
            ..Default::default()
        }));

        let offline_restore = run_cli_with_executor(
            &["--restore".into(), "--timeout-ms".into(), "100".into()],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(offline_restore.exit_code, 0);
        let json = offline_restore.json.unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["mode"], "offline_wal");
        assert_eq!(json["verified"], true);
        assert!(!store.path().exists());
        assert!(exec.state.lock().unwrap().firewall_rules.is_empty());
        assert!(disarm::read_disarmed(dir.path()).unwrap().is_some());

        // Clear disarm marker, then test online --restore via Named Pipe.
        disarm::clear_disarmed(dir.path()).unwrap();
        let driver: Arc<dyn PlatformDriver> = Arc::new(UnsupportedPlatformDriver::default());
        let runner: Arc<dyn ProbeRunner> = Arc::new(SwitchableProbeRunner {
            pass: Arc::new(AtomicBool::new(true)),
        });

        let rt = DaemonRuntime::start(
            DaemonConfig {
                pipe_name: pipe.clone(),
                data_dir: dir.path().to_path_buf(),
                shutdown_policy: ShutdownPolicy::default(),
                service_mode: false,
                enable_background_loop: false,
            },
            driver,
            runner,
            exec.clone(),
        )
        .unwrap();

        let mut client = PipeClient::connect(&pipe, 2000).unwrap();
        assert!(matches!(
            client
                .call(&PipeRequest::CompleteOnboarding {
                    config: valid_test_config(),
                })
                .unwrap(),
            PipeResponse::Ack { .. }
        ));
        drop(client);

        // Simulate a managed firewall rule present during runtime so online Flow B has cleanup work to verify.
        exec.state
            .lock()
            .unwrap()
            .firewall_rules
            .push("ClaudeGuard Block Out (claude)".into());

        let online_restore =
            run_cli_with_executor(&["--restore".into()], Some(&pipe), Some(dir.path()), &*exec);
        assert_eq!(online_restore.exit_code, 0);
        let online_json = online_restore.json.unwrap();
        assert_eq!(online_json["mode"], "online_pipe");
        assert_eq!(online_json["ok"], true);
        assert_eq!(rt.coordinator().snapshot().lifecycle, Lifecycle::Disarmed);
        assert!(exec.state.lock().unwrap().firewall_rules.is_empty());
        assert!(should_fallback_offline(&PipeError::Disconnected));

        rt.shutdown_graceful(StopBehavior::PreserveFailClosed)
            .unwrap();
    }
}
