//! Scriptable, sub-2ms CLI Hook Gate, and emergency CLI (`claudeguard-cli`) implementation.
//!
//! Commands:
//! - `--hook-gate` / `hook-gate`: sub-2ms O(1) Pre-Prompt CLI / IDE Hook gate (`PipeRequest::FastHookGate`),
//!   emitting official Claude Code hook JSON (`{"decision":"block","reason":"..."}`) on block
//!   (or exit code `2` with `--exit-code-block` for PowerShell `$PROFILE` wrappers) and honoring
//!   configured `HookFailMode` when the daemon is offline.
//! - `--launch-vault <id>` / `vault launch --vault <id> --app <app>`: launches an app inside a Sovereign Vault.
//! - `--cleanroom-scan` / `cleanroom-scan`: runs a 100% read-only local residue scan.
//! - `--check` / `check`: queries daemon snapshot (with optional `--recheck`), prints structured JSON,
//!   exits `0` if passed or `2` if not passed (including offline/unconfigured/disarmed/unverified).
//! - `--restore` / `restore`: contacts live daemon over Named Pipe for Flow B disarm & restore,
//!   automatically falling back to offline WAL journal + persistent WFP cleanup when the service is down.
//! - `--status` / `status`: prints service, WAL journal, disarm marker, and live snapshot status as JSON.

use std::path::{Path, PathBuf};

use crate::config_store::{ConfigStore, LoadedConfig};
use crate::disarm;
use crate::ipc_pipe::{resolve_pipe_name, PipeClient, PipeError};
use crate::journal::{self, JournalStore, LoadedJournal, RecoveryExecutor};
use crate::protocol::{
    snapshot_is_check_passed, CleanRoomScope, HookDecision, HookFailMode, PipeRequest,
    PipeResponse, VaultAppTarget, DAEMON_VERSION,
};
use crate::service_win;

/// Parsed CLI command mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    Check {
        recheck: bool,
    },
    HookGate {
        agent: String,
        vault: Option<String>,
        hook_event: Option<String>,
        exit_code_block: bool,
    },
    LaunchVault {
        vault_id: String,
        app: VaultAppTarget,
        extra_args: Vec<String>,
    },
    CleanRoomScan,
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
    pub timeout_explicit: bool,
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
ClaudeGuard v5 CLI (claudeguard-cli)

USAGE:
    claudeguard-cli [--hook-gate | --check | --launch-vault <ID> | --cleanroom-scan | --restore | --status] [OPTIONS]
    claudeguard-cli vault launch --vault <ID> [--app <APP>] [OPTIONS]

COMMANDS:
    --hook-gate, hook-gate         Sub-2ms Pre-Prompt CLI Hook gate (Claude Code JSON or --exit-code-block)
    --launch-vault <ID>            Safe-launch an app inside a Sovereign Account Vault
    vault launch --vault <ID>      Alias invoked by desktop .lnk vault shortcuts
    --cleanroom-scan               Run 100% read-only local Clean-Room residue scan
    --check,   check               Verify egress compliance via daemon; exit 0=pass, 2=not passed
    --restore, restore             Disarm and restore network/firewall/WFP (live pipe or offline WAL fallback)
    --status,  status              Print daemon, Windows Service, and WAL journal status JSON
    --version                      Print version
    --help, -h                     Print this help

OPTIONS:
    --agent <ID>                   With --hook-gate: CLI agent ID (default: claude-code)
    --vault <ID>                   With --hook-gate / vault launch: Sovereign Vault ID (or CG_VAULT_ID env)
    --hook-event, --event <NAME>   With --hook-gate: hook lifecycle event (UserPromptSubmit | PreToolUse)
    --exit-code-block              With --hook-gate: emit stderr and exit 2 on block (for PowerShell wrappers)
    --app <TARGET>                 With --launch-vault / vault launch: claude_desktop | chatgpt_desktop | antigravity_ide | claude_code_cli | codex_cli
    --recheck                      With --check: trigger RecheckNow before reading snapshot
    --pipe <NAME>                  Override Named Pipe (or set CG_PIPE_NAME)
    --data-dir <PATH>              Override WAL data dir (or set CG_DATA_DIR)
    --timeout-ms <MS>              Pipe connect timeout in milliseconds (default: 3000; 500 for --hook-gate)
";

/// Parses a `VaultAppTarget` from a CLI flag value.
pub fn parse_vault_app_target(raw: &str) -> Result<VaultAppTarget, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "claude_desktop" | "claude-desktop" | "claude" => Ok(VaultAppTarget::ClaudeDesktop),
        "chatgpt_desktop" | "chatgpt-desktop" | "chatgpt" => Ok(VaultAppTarget::ChatgptDesktop),
        "antigravity_ide" | "antigravity-ide" | "antigravity" => Ok(VaultAppTarget::AntigravityIde),
        "claude_code_cli" | "claude-code-cli" | "claude-code" | "claude_code" => {
            Ok(VaultAppTarget::ClaudeCodeCli)
        }
        "codex_cli" | "codex-cli" | "codex" => Ok(VaultAppTarget::CodexCli),
        other => Err(format!("unknown vault app target '{other}'")),
    }
}

/// Parses command-line arguments (excluding `argv[0]`).
pub fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut mode: Option<&str> = None;
    let mut recheck = false;
    let mut agent = "claude-code".to_string();
    let mut vault: Option<String> = None;
    let mut hook_event: Option<String> = None;
    let mut exit_code_block = false;
    let mut vault_app = VaultAppTarget::ClaudeDesktop;
    let mut extra_args: Vec<String> = Vec::new();
    let mut pipe_name: Option<String> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut timeout_ms: u32 = 3000;
    let mut timeout_explicit = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--" => {
                extra_args.extend(args[i + 1..].iter().cloned());
                break;
            }
            "--check" | "check" => mode = Some("check"),
            "--hook-gate" | "hook-gate" => mode = Some("hook_gate"),
            "--cleanroom-scan" | "cleanroom-scan" => mode = Some("cleanroom_scan"),
            "--launch-vault" => {
                i += 1;
                let val = args.get(i).ok_or("--launch-vault requires a vault ID")?;
                vault = Some(val.clone());
                mode = Some("launch_vault");
            }
            "vault" => {
                if args.get(i + 1).map(String::as_str) == Some("launch") {
                    i += 1;
                    mode = Some("launch_vault");
                } else {
                    return Err("expected `vault launch --vault <ID>` (run with --help)".into());
                }
            }
            "--restore" | "restore" => mode = Some("restore"),
            "--status" | "status" => mode = Some("status"),
            "--version" | "-V" => mode = Some("version"),
            "--help" | "-h" => mode = Some("help"),
            "--recheck" => {
                recheck = true;
            }
            "--agent" => {
                i += 1;
                let val = args.get(i).ok_or("--agent requires a value")?;
                agent = val.clone();
            }
            "--vault" => {
                i += 1;
                let val = args.get(i).ok_or("--vault requires a value")?;
                vault = Some(val.clone());
            }
            "--hook-event" | "--event" => {
                i += 1;
                let val = args.get(i).ok_or("--hook-event requires a value")?;
                hook_event = Some(val.clone());
            }
            "--exit-code-block" => {
                exit_code_block = true;
            }
            "--app" => {
                i += 1;
                let val = args.get(i).ok_or("--app requires a value")?;
                vault_app = parse_vault_app_target(val)?;
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
                timeout_explicit = true;
            }
            other => {
                return Err(format!("unknown argument '{other}' (run with --help)"));
            }
        }
        i += 1;
    }

    let command = match mode {
        Some("check") => CliCommand::Check { recheck },
        Some("hook_gate") => CliCommand::HookGate {
            agent,
            vault,
            hook_event,
            exit_code_block,
        },
        Some("launch_vault") => {
            let vault_id = vault
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or("vault launch requires --vault <ID>")?
                .to_string();
            CliCommand::LaunchVault {
                vault_id,
                app: vault_app,
                extra_args,
            }
        }
        Some("cleanroom_scan") => CliCommand::CleanRoomScan,
        Some("restore") => CliCommand::Restore,
        Some("status") => CliCommand::Status,
        Some("version") => CliCommand::Version,
        Some("help") | None => CliCommand::Help,
        _ => CliCommand::Help,
    };

    Ok(CliArgs {
        command,
        pipe_name,
        data_dir,
        timeout_ms,
        timeout_explicit,
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
        CliCommand::HookGate {
            agent,
            vault,
            hook_event,
            exit_code_block,
        } => {
            // Fast 500ms connect timeout detects an offline daemon immediately, while a 6,500ms
            // RPC call timeout gives `FastHookGate::NeedsSyncProbe` enough headroom to complete
            // live HTTPS egress checks comfortably inside Claude Code's 8s hook budget.
            let connect_timeout_ms = if parsed.timeout_explicit {
                parsed.timeout_ms
            } else {
                500
            };
            let call_timeout_ms = if parsed.timeout_explicit {
                parsed.timeout_ms.max(500)
            } else {
                6_500
            };
            let resolved_vault = vault.or_else(|| {
                std::env::var("CG_VAULT_ID")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            });
            run_hook_gate(
                &pipe_name,
                &data_dir,
                connect_timeout_ms,
                call_timeout_ms,
                &agent,
                resolved_vault,
                hook_event,
                exit_code_block,
            )
        }
        CliCommand::LaunchVault {
            vault_id,
            app,
            extra_args,
        } => run_launch_vault(&pipe_name, parsed.timeout_ms, vault_id, app, extra_args),
        CliCommand::CleanRoomScan => run_cleanroom_scan(&pipe_name, parsed.timeout_ms),
        CliCommand::Check { recheck } => run_check(&pipe_name, parsed.timeout_ms, recheck),
        CliCommand::Restore => {
            run_restore(&pipe_name, &data_dir, parsed.timeout_ms, offline_executor)
        }
        CliCommand::Status => run_status(&pipe_name, &data_dir, parsed.timeout_ms),
    }
}

fn read_configured_hook_fail_mode(data_dir: &Path) -> HookFailMode {
    match ConfigStore::new(data_dir).load_readonly() {
        LoadedConfig::Loaded(outcome) => outcome.config.hook_fail_mode,
        _ => HookFailMode::FailClosed,
    }
}

fn format_hook_block_output(
    reason: String,
    safety_score: u8,
    latency_path: &str,
    exit_code_block: bool,
) -> CliOutput {
    if exit_code_block {
        CliOutput {
            exit_code: 2,
            json: None,
            text: None,
            stderr: Some(reason),
        }
    } else {
        // Official Claude Code UserPromptSubmit / PreToolUse JSON hook contract:
        // exit 0 + stdout `{"decision":"block","reason":"..."}`.
        CliOutput {
            exit_code: 0,
            json: Some(serde_json::json!({
                "decision": "block",
                "reason": reason,
                "safety_score": safety_score,
                "latency_path": latency_path,
            })),
            text: None,
            stderr: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_hook_gate(
    pipe_name: &str,
    data_dir: &Path,
    connect_timeout_ms: u32,
    call_timeout_ms: u32,
    agent_id: &str,
    vault_id: Option<String>,
    hook_event: Option<String>,
    exit_code_block: bool,
) -> CliOutput {
    let req = PipeRequest::FastHookGate {
        agent_id: agent_id.to_string(),
        vault_id,
        hook_event,
    };

    let call_res = PipeClient::connect(pipe_name, connect_timeout_ms).and_then(|mut c| {
        c.set_call_timeout_ms(call_timeout_ms.max(500));
        c.call(&req)
    });

    match call_res {
        Ok(PipeResponse::FastGateVerdict {
            allowed,
            decision,
            safety_score,
            reason,
            latency_path,
        }) => {
            if allowed && decision == HookDecision::Allow {
                CliOutput {
                    exit_code: 0,
                    json: None,
                    text: None,
                    stderr: None,
                }
            } else {
                format_hook_block_output(reason, safety_score, &latency_path, exit_code_block)
            }
        }
        Ok(PipeResponse::Error { message, .. }) => format_hook_block_output(
            format!("🛡️ [ClaudeGuard 门禁错误] {message}"),
            0,
            "ipc_error",
            exit_code_block,
        ),
        Ok(other) => format_hook_block_output(
            format!("🛡️ [ClaudeGuard 门禁协议异常] 收到非预期响应：{other:?}"),
            0,
            "ipc_unexpected",
            exit_code_block,
        ),
        Err(err) => {
            let fail_mode = read_configured_hook_fail_mode(data_dir);
            match fail_mode {
                HookFailMode::FailOpenWithWarn => CliOutput {
                    exit_code: 0,
                    json: None,
                    text: None,
                    stderr: Some(format!(
                        "[ClaudeGuard 警告] 守护服务暂不可达（{err}），已按 FailOpenWithWarn 放行提示词"
                    )),
                },
                HookFailMode::FailClosed => format_hook_block_output(
                    format!(
                        "🛡️ [ClaudeGuard 离线防裸连拦截] 守护服务未响应（{err}），已按 FailClosed 安全策略拦截提示词发送。请先启动 ClaudeGuard。"
                    ),
                    0,
                    "offline_fail_closed",
                    exit_code_block,
                ),
            }
        }
    }
}

fn run_launch_vault(
    pipe_name: &str,
    timeout_ms: u32,
    vault_id: String,
    app: VaultAppTarget,
    extra_args: Vec<String>,
) -> CliOutput {
    let res = PipeClient::connect(pipe_name, timeout_ms).and_then(|mut c| {
        c.call(&PipeRequest::LaunchVault {
            vault_id: vault_id.clone(),
            app,
            extra_args,
        })
    });
    match res {
        Ok(PipeResponse::Ack { receipt, .. }) => CliOutput {
            exit_code: 0,
            json: Some(serde_json::json!({
                "ok": true,
                "vault_id": vault_id,
                "app": app,
                "receipt": receipt,
            })),
            text: None,
            stderr: None,
        },
        Ok(PipeResponse::Error {
            code,
            message,
            receipt,
        }) => CliOutput {
            exit_code: 2,
            json: Some(serde_json::json!({
                "ok": false,
                "vault_id": vault_id,
                "app": app,
                "error_code": code,
                "error": message,
                "receipt": receipt,
            })),
            text: None,
            stderr: Some(message),
        },
        Ok(other) => CliOutput {
            exit_code: 2,
            json: Some(serde_json::json!({
                "ok": false,
                "error": format!("unexpected IPC response: {other:?}"),
            })),
            text: None,
            stderr: Some("unexpected IPC response".into()),
        },
        Err(err) => CliOutput {
            exit_code: 2,
            json: Some(serde_json::json!({
                "ok": false,
                "error": err.to_string(),
            })),
            text: None,
            stderr: Some(err.to_string()),
        },
    }
}

fn run_cleanroom_scan(pipe_name: &str, timeout_ms: u32) -> CliOutput {
    let scope = CleanRoomScope {
        claude: true,
        chatgpt_codex: true,
        antigravity: true,
    };
    let res = PipeClient::connect(pipe_name, timeout_ms)
        .and_then(|mut c| c.call(&PipeRequest::ScanCleanRoom { scope }));
    match res {
        Ok(PipeResponse::CleanRoomScan { report }) => CliOutput {
            exit_code: 0,
            json: Some(serde_json::to_value(report).unwrap_or_else(|_| serde_json::json!({}))),
            text: None,
            stderr: None,
        },
        Ok(PipeResponse::Error { code, message, .. }) => CliOutput {
            exit_code: 1,
            json: Some(serde_json::json!({
                "ok": false,
                "error_code": code,
                "error": message,
            })),
            text: None,
            stderr: Some(message),
        },
        Ok(other) => CliOutput {
            exit_code: 1,
            json: Some(serde_json::json!({
                "ok": false,
                "error": format!("unexpected IPC response: {other:?}"),
            })),
            text: None,
            stderr: Some("unexpected IPC response".into()),
        },
        Err(err) => CliOutput {
            exit_code: 1,
            json: Some(serde_json::json!({
                "ok": false,
                "error": err.to_string(),
            })),
            text: None,
            stderr: Some(err.to_string()),
        },
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
                    "safety_score": snapshot.risk_assessment.score,
                    "safety_grade": snapshot.risk_assessment.grade,
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
    // Guarantee persistent boot-time WFP filters are purged even if no WAL remained.
    let wfp_cleared = offline_executor.clear_wfp_persistent_filters().ok();
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
            "wfp_persistent_cleared": wfp_cleared,
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
        // Keep `--hook-gate` output compact single-line JSON for Claude Code hooks.
        let is_hook_json = json.get("decision").is_some() && json.get("version").is_none();
        let rendered = if is_hook_json {
            serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())
        } else {
            serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string())
        };
        println!("{rendered}");
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
    fn cli_parses_v5_hook_gate_vault_launch_and_cleanroom_scan_args() {
        let parsed = parse_args(&[
            "--hook-gate".into(),
            "--agent".into(),
            "codex".into(),
            "--vault".into(),
            "work-us".into(),
            "--hook-event".into(),
            "PreToolUse".into(),
            "--exit-code-block".into(),
        ])
        .unwrap();
        assert_eq!(
            parsed.command,
            CliCommand::HookGate {
                agent: "codex".into(),
                vault: Some("work-us".into()),
                hook_event: Some("PreToolUse".into()),
                exit_code_block: true,
            }
        );

        let vault_cmd = parse_args(&[
            "vault".into(),
            "launch".into(),
            "--vault".into(),
            "jp-max".into(),
            "--app".into(),
            "claude_code_cli".into(),
        ])
        .unwrap();
        assert_eq!(
            vault_cmd.command,
            CliCommand::LaunchVault {
                vault_id: "jp-max".into(),
                app: VaultAppTarget::ClaudeCodeCli,
                extra_args: Vec::new(),
            }
        );

        let cr = parse_args(&["--cleanroom-scan".into()]).unwrap();
        assert_eq!(cr.command, CliCommand::CleanRoomScan);
    }

    #[test]
    fn cli_hook_gate_allows_blocks_and_honors_exit_code_block_and_offline_fail_mode() {
        let dir = tempfile::tempdir().unwrap();
        let pipe = test_pipe();
        let exec = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));

        // 1) Offline daemon with default FailClosed => Claude Code JSON block (exit 0) and --exit-code-block (exit 2).
        let off_json = run_cli_with_executor(
            &[
                "--hook-gate".into(),
                "--agent".into(),
                "claude-code".into(),
                "--timeout-ms".into(),
                "80".into(),
            ],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(off_json.exit_code, 0);
        let j = off_json.json.expect("Claude Code block JSON");
        assert_eq!(j["decision"], "block");
        assert!(j["reason"].as_str().unwrap().contains("FailClosed"));

        let off_exit2 = run_cli_with_executor(
            &[
                "--hook-gate".into(),
                "--agent".into(),
                "claude-code".into(),
                "--exit-code-block".into(),
                "--timeout-ms".into(),
                "80".into(),
            ],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(off_exit2.exit_code, 2);
        assert!(off_exit2.stderr.is_some());

        // 2) Offline daemon with persisted FailOpenWithWarn => allow (exit 0, no block JSON, stderr warn).
        let mut open_cfg = valid_test_config();
        open_cfg.hook_fail_mode = HookFailMode::FailOpenWithWarn;
        ConfigStore::new(dir.path())
            .save_verified(&open_cfg)
            .unwrap();
        let off_warn = run_cli_with_executor(
            &[
                "--hook-gate".into(),
                "--agent".into(),
                "claude-code".into(),
                "--timeout-ms".into(),
                "80".into(),
            ],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(off_warn.exit_code, 0);
        assert!(off_warn.json.is_none());
        assert!(off_warn.stderr.unwrap().contains("FailOpenWithWarn"));

        // 3) Online daemon: Armed + Pass => silent exit 0; Tripped => block JSON / exit 2.
        let driver: Arc<dyn PlatformDriver> = Arc::new(UnsupportedPlatformDriver::default());
        let pass_flag = Arc::new(AtomicBool::new(true));
        let runner: Arc<dyn ProbeRunner> = Arc::new(SwitchableProbeRunner {
            pass: pass_flag.clone(),
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
                .call(&PipeRequest::RecheckNow { target_id: None })
                .unwrap(),
            PipeResponse::Ack { .. }
        ));
        drop(client);

        let allow_out = run_cli_with_executor(
            &["--hook-gate".into(), "--agent".into(), "claude-code".into()],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(allow_out.exit_code, 0);
        assert!(allow_out.json.is_none());

        // Trigger mismatch -> tripped -> blocked by FastHookGate!
        pass_flag.store(false, Ordering::Release);
        let mut client2 = PipeClient::connect(&pipe, 2000).unwrap();
        let _ = client2.call(&PipeRequest::RecheckNow { target_id: None });
        drop(client2);

        let block_json = run_cli_with_executor(
            &["--hook-gate".into(), "--agent".into(), "claude-code".into()],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(block_json.exit_code, 0);
        assert_eq!(block_json.json.unwrap()["decision"], "block");

        let block_pwsh = run_cli_with_executor(
            &[
                "--hook-gate".into(),
                "--agent".into(),
                "claude-code".into(),
                "--exit-code-block".into(),
            ],
            Some(&pipe),
            Some(dir.path()),
            &*exec,
        );
        assert_eq!(block_pwsh.exit_code, 2);
        assert!(block_pwsh.stderr.is_some());

        rt.shutdown_graceful(StopBehavior::RunFlowBCleanup).unwrap();
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

        let online_restore =
            run_cli_with_executor(&["--restore".into()], Some(&pipe), Some(dir.path()), &*exec);
        assert_eq!(online_restore.exit_code, 0);
        let ojson = online_restore.json.unwrap();
        assert_eq!(ojson["ok"], true);
        assert_eq!(ojson["mode"], "online_pipe");
        assert_eq!(ojson["verified"], true);
        assert_eq!(ojson["lifecycle"], serde_json::json!("disarmed"));
        assert_eq!(rt.coordinator().snapshot().lifecycle, Lifecycle::Disarmed);
        assert!(disarm::read_disarmed(dir.path()).unwrap().is_some());

        rt.shutdown_graceful(StopBehavior::RunFlowBCleanup).unwrap();
    }
}
