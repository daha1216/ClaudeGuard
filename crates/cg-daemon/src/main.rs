//! `claudeguard-daemon.exe` binary entrypoint.
//!
//! - Default (no mode flag): enters Win32 `StartServiceCtrlDispatcherW` as `ClaudeGuardService`.
//! - `--console`: runs in foreground console mode for development and integration testing.
//! - `--install-service` / `--uninstall-service` / `--service-status`: SCM management helpers.

use std::path::PathBuf;
use std::sync::Arc;

use cg_daemon::engine_runtime::PlatformProbeRunner;
use cg_daemon::ipc_pipe::resolve_pipe_name;
use cg_daemon::journal::{self, PlatformRecoveryExecutor};
use cg_daemon::protocol::DAEMON_VERSION;
use cg_daemon::service_win::{self, DaemonConfig, ShutdownPolicy, StopBehavior};

enum DaemonMode {
    Service,
    Console,
    InstallService { start_now: bool },
    UninstallService,
    ServiceStatus,
    Version,
    Help,
}

const HELP_TEXT: &str = "\
ClaudeGuard v4 Daemon (claudeguard-daemon)

USAGE:
    claudeguard-daemon [MODE] [OPTIONS]

MODES:
    (default)              Run as Windows Service ClaudeGuardService via SCM
    --console              Run in foreground console mode
    --install-service      Register ClaudeGuardService (LocalSystem, auto-start)
    --uninstall-service    Stop and remove ClaudeGuardService
    --service-status       Query SCM service state (JSON)
    --version              Print version
    --help, -h             Print this help

OPTIONS:
    --start                With --install-service: start the service immediately
    --pipe <NAME>          Override Named Pipe (or set CG_PIPE_NAME)
    --data-dir <PATH>      Override WAL data dir (or set CG_DATA_DIR)
    --shutdown-policy <P>  Service shutdown policy: restore | preserve (default: preserve)
";

fn parse_args(args: &[String]) -> Result<(DaemonMode, DaemonConfig), String> {
    let mut mode = DaemonMode::Service;
    let mut start_now = false;
    let mut pipe_override: Option<String> = None;
    let mut dir_override: Option<PathBuf> = None;
    let mut shutdown_policy = ShutdownPolicy::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--console" => mode = DaemonMode::Console,
            "--install-service" => mode = DaemonMode::InstallService { start_now },
            "--uninstall-service" => mode = DaemonMode::UninstallService,
            "--service-status" => mode = DaemonMode::ServiceStatus,
            "--version" | "-V" => mode = DaemonMode::Version,
            "--help" | "-h" => mode = DaemonMode::Help,
            "--start" => {
                start_now = true;
                if let DaemonMode::InstallService {
                    start_now: ref mut s,
                } = mode
                {
                    *s = true;
                }
            }
            "--pipe" => {
                i += 1;
                let val = args.get(i).ok_or("--pipe requires a value")?;
                pipe_override = Some(val.clone());
            }
            "--data-dir" => {
                i += 1;
                let val = args.get(i).ok_or("--data-dir requires a value")?;
                dir_override = Some(PathBuf::from(val));
            }
            "--shutdown-policy" => {
                i += 1;
                let val = args.get(i).ok_or("--shutdown-policy requires a value")?;
                shutdown_policy.on_shutdown = match val.as_str() {
                    "restore" => StopBehavior::RunFlowBCleanup,
                    "preserve" => StopBehavior::PreserveFailClosed,
                    other => {
                        return Err(format!(
                            "invalid --shutdown-policy '{other}' (expected restore|preserve)"
                        ));
                    }
                };
            }
            other => return Err(format!("unknown argument '{other}' (run with --help)")),
        }
        i += 1;
    }

    let config = DaemonConfig {
        pipe_name: resolve_pipe_name(pipe_override.as_deref()),
        data_dir: journal::resolve_data_dir(dir_override.as_deref()),
        shutdown_policy,
        service_mode: matches!(mode, DaemonMode::Service),
        enable_background_loop: true,
    };
    Ok((mode, config))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, config) = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let code = match mode {
        DaemonMode::Version => {
            println!("claudeguard-daemon {DAEMON_VERSION}");
            0
        }
        DaemonMode::Help => {
            print!("{HELP_TEXT}");
            0
        }
        DaemonMode::ServiceStatus => match service_win::query_service_status() {
            Ok(state) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "service": service_win::SERVICE_NAME,
                        "state": state,
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
                0
            }
            Err(err) => {
                eprintln!("{err}");
                1
            }
        },
        DaemonMode::InstallService { start_now } => {
            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("failed to locate current_exe: {err}");
                    std::process::exit(1);
                }
            };
            match service_win::install_service(&exe, start_now) {
                Ok(status) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".to_string())
                    );
                    0
                }
                Err(err) => {
                    eprintln!("{err}");
                    1
                }
            }
        }
        DaemonMode::UninstallService => match service_win::uninstall_service() {
            Ok(removed) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "service": service_win::SERVICE_NAME,
                        "removed": removed,
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
                0
            }
            Err(err) => {
                eprintln!("{err}");
                1
            }
        },
        DaemonMode::Console => {
            let driver: Arc<dyn cg_platform::PlatformDriver> =
                Arc::new(cg_platform::default_platform_driver());
            let probe_runner = Arc::new(PlatformProbeRunner);
            let recovery = Arc::new(PlatformRecoveryExecutor::new(driver.clone()));
            if let Err(err) =
                service_win::run_console_until(config, driver, probe_runner, recovery, None)
            {
                eprintln!("{err}");
                1
            } else {
                0
            }
        }
        DaemonMode::Service => {
            let factory: service_win::PlatformFactory = Box::new(|| {
                let driver: Arc<dyn cg_platform::PlatformDriver> =
                    Arc::new(cg_platform::default_platform_driver());
                let probe_runner: Arc<dyn cg_daemon::engine_runtime::ProbeRunner> =
                    Arc::new(PlatformProbeRunner);
                let recovery: Arc<dyn cg_daemon::journal::RecoveryExecutor> =
                    Arc::new(PlatformRecoveryExecutor::new(driver.clone()));
                (driver, probe_runner, recovery)
            });
            if let Err(err) = service_win::run_as_windows_service(config, factory) {
                eprintln!("{err}");
                1
            } else {
                0
            }
        }
    };

    std::process::exit(code);
}
