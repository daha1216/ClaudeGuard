//! Windows Service (`ClaudeGuardService`) host, SCM installer helpers, and `--console` mode.
//!
//! Runs `claudeguard-daemon.exe` as an auto-start `LocalSystem` Windows Service via
//! `StartServiceCtrlDispatcherW` / `RegisterServiceCtrlHandlerExW` / `SetServiceStatus`,
//! or in foreground `--console` mode for local development and integration testing.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;

use crate::coordinator::{start_coordinator_with, CoordinatorHandle};
use crate::engine_runtime::{BackgroundMonitorHandle, ProbeRunner, RealEngineActor};
use crate::ipc_pipe::PipeServer;
use crate::journal::{HealReport, RecoveryExecutor};
use cg_platform::PlatformDriver;

/// Windows Service internal name (`ClaudeGuardService`).
pub const SERVICE_NAME: &str = "ClaudeGuardService";

/// Human-readable display name shown in `services.msc`.
pub const SERVICE_DISPLAY_NAME: &str = "ClaudeGuard Daemon Service";

/// Service description registered in SCM.
pub const SERVICE_DESCRIPTION: &str =
    "ClaudeGuard v4 network egress guard, WAL crash recovery, and Named Pipe IPC coordinator";

/// Behavior on Windows Service stop or OS shutdown control signals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopBehavior {
    /// Run graceful Flow B network/firewall restoration and verify 0 rules before stopping.
    #[default]
    RunFlowBCleanup,
    /// Preserve active isolation and WAL journal on disk so next boot `heal_on_startup` handles recovery fail-closed.
    PreserveFailClosed,
}

/// Configurable shutdown policy for `SERVICE_CONTROL_STOP` vs `SERVICE_CONTROL_SHUTDOWN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownPolicy {
    pub on_stop: StopBehavior,
    pub on_shutdown: StopBehavior,
}

impl Default for ShutdownPolicy {
    fn default() -> Self {
        Self {
            on_stop: StopBehavior::RunFlowBCleanup,
            on_shutdown: StopBehavior::PreserveFailClosed,
        }
    }
}

/// Pure decision helper mapping Win32 SCM control codes to [`StopBehavior`].
pub fn plan_shutdown_action(control_code: u32, policy: ShutdownPolicy) -> Option<StopBehavior> {
    const CTRL_STOP: u32 = 1;
    const CTRL_SHUTDOWN: u32 = 5;
    const CTRL_PRESHUTDOWN: u32 = 0x0000_000F;
    match control_code {
        CTRL_STOP => Some(policy.on_stop),
        CTRL_SHUTDOWN | CTRL_PRESHUTDOWN => Some(policy.on_shutdown),
        _ => None,
    }
}

/// Encodes Win32 SCM service names into a double-NUL-terminated UTF-16 `MULTI_SZ` buffer
/// suitable for `CreateServiceW` / `ChangeServiceConfigW` `lpDependencies` (e.g. `BFE\0MpsSvc\0\0`).
pub fn encode_service_dependencies(deps: &[&str]) -> Vec<u16> {
    let mut buf = Vec::new();
    for dep in deps {
        let trimmed = dep.trim();
        if trimmed.is_empty() {
            continue;
        }
        buf.extend(trimmed.encode_utf16().filter(|&ch| ch != 0));
        buf.push(0);
    }
    if buf.is_empty() {
        buf.push(0);
    }
    buf.push(0);
    buf
}

/// Sanitizes a canonicalized executable string into a quoted SCM `lpBinaryPathName`.
fn sanitize_service_exe_str(raw: &str) -> Result<String, String> {
    if raw.contains('"') || raw.contains(['\0', '\r', '\n']) {
        return Err(format!(
            "invalid character in service executable path: {raw}"
        ));
    }
    let bytes = raw.as_bytes();
    let is_unc = bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(br"\\?\UNC\");
    let stripped = if is_unc {
        raw
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest
    } else {
        raw
    };
    if stripped.trim().is_empty() {
        return Err("service executable path cannot be empty".to_string());
    }
    Ok(format!("\"{stripped}\""))
}

/// Canonicalizes and validates `exe_path` for SCM registration (`MED-03`).
pub fn format_service_binary_path(exe_path: &Path) -> Result<String, String> {
    let abs_exe = std::fs::canonicalize(exe_path).map_err(|e| {
        format!(
            "failed to canonicalize service executable {}: {e}",
            exe_path.display()
        )
    })?;
    let raw = abs_exe.to_str().ok_or_else(|| {
        format!(
            "service executable path is not valid UTF-8: {}",
            abs_exe.display()
        )
    })?;
    sanitize_service_exe_str(raw)
}

/// Returns true when `event_type` under `SERVICE_CONTROL_POWEREVENT` indicates OS sleep/hibernate wake.
pub fn is_power_resume_event(control_code: u32, event_type: u32) -> bool {
    const CTRL_POWEREVENT: u32 = 0x0000_000D;
    const PBT_APMRESUMESUSPEND: u32 = 0x0000_0007;
    const PBT_APMRESUMEAUTOMATIC: u32 = 0x0000_0012;
    control_code == CTRL_POWEREVENT
        && matches!(event_type, PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND)
}

/// Observed SCM service status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

/// Outcome returned by [`install_service`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInstallStatus {
    pub service_name: String,
    pub binary_path: String,
    pub created_new: bool,
    pub started: bool,
}

/// Factory constructing the runtime [`PlatformDriver`], [`ProbeRunner`], and [`RecoveryExecutor`]
/// inside Windows Service initialization.
pub type PlatformFactory = Box<
    dyn FnOnce() -> (
            Arc<dyn PlatformDriver>,
            Arc<dyn ProbeRunner>,
            Arc<dyn RecoveryExecutor>,
        ) + Send,
>;

/// Runtime configuration for daemon startup.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub pipe_name: String,
    pub data_dir: PathBuf,
    pub shutdown_policy: ShutdownPolicy,
    pub service_mode: bool,
    pub enable_background_loop: bool,
}

/// Live daemon runtime assembling WAL startup heal, `RealEngineActor`, background monitor, and Named Pipe server.
pub struct DaemonRuntime {
    config: DaemonConfig,
    heal_report: HealReport,
    coordinator: CoordinatorHandle,
    pipe_server: PipeServer,
    monitor: Option<BackgroundMonitorHandle>,
}

impl DaemonRuntime {
    /// Initializes the daemon:
    /// 1. Bootstraps [`RealEngineActor`] (which runs `journal::heal_on_startup()` deterministically BEFORE opening IPC).
    /// 2. Starts the single-writer mutation coordinator holding O(1) `GuardSnapshot`.
    /// 3. Starts the SDDL-secured Named Pipe IPC server.
    /// 4. Optionally starts the background monitor & telemetry scheduler loop.
    pub fn start(
        config: DaemonConfig,
        driver: Arc<dyn PlatformDriver>,
        probe_runner: Arc<dyn ProbeRunner>,
        recovery_executor: Arc<dyn RecoveryExecutor>,
    ) -> Result<Self, String> {
        crate::journal::ensure_secure_data_dir(&config.data_dir)?;
        let data_dir = config.data_dir.clone();
        let bg_driver = driver.clone();
        let (coordinator, (heal_report, process_scanner)) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap(
                data_dir,
                driver,
                probe_runner,
                recovery_executor,
                event_tx,
            );
            (
                boot.initial_snapshot,
                Box::new(boot.actor),
                (boot.heal_report, boot.process_scanner),
            )
        });

        let pipe_server = match PipeServer::start(&config.pipe_name, coordinator.clone()) {
            Ok(srv) => srv,
            Err(err) => {
                coordinator.shutdown();
                return Err(format!(
                    "failed to start Named Pipe server {}: {err}",
                    config.pipe_name
                ));
            }
        };

        let monitor = if config.enable_background_loop {
            Some(BackgroundMonitorHandle::start(
                coordinator.clone(),
                bg_driver,
                process_scanner,
                config.data_dir.clone(),
                true,
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            heal_report,
            coordinator,
            pipe_server,
            monitor,
        })
    }

    /// Returns the startup WAL heal report.
    pub fn heal_report(&self) -> &HealReport {
        &self.heal_report
    }

    /// Returns the active daemon configuration.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Returns a handle to the coordinator & O(1) snapshot store.
    pub fn coordinator(&self) -> &CoordinatorHandle {
        &self.coordinator
    }

    /// Returns the bound Named Pipe name.
    pub fn pipe_name(&self) -> &str {
        self.pipe_server.pipe_name()
    }

    /// Performs graceful daemon shutdown according to `behavior`.
    ///
    /// - [`StopBehavior::RunFlowBCleanup`]: Stops background loop and pipe server, then executes
    ///   `BeginStopping` deterministic WAL/firewall/NIC cleanup and post-cleanup verification
    ///   (without marking permanent `disarmed` intent).
    /// - [`StopBehavior::PreserveFailClosed`]: Stops background loop, pipe server, and coordinator
    ///   while preserving active protection and WAL journal on disk for next-boot `heal_on_startup()`.
    pub fn shutdown_graceful(self, behavior: StopBehavior) -> Result<(), String> {
        if let Some(monitor) = self.monitor {
            monitor.shutdown();
        }
        // Signal pipe stop first without blocking on slow/in-flight client workers so
        // Flow B cleanup runs immediately inside SCM's 15s SERVICE_STOP_PENDING budget.
        self.pipe_server.signal_stop();

        let result = match behavior {
            StopBehavior::RunFlowBCleanup => match self.coordinator.begin_stopping_flow_b() {
                Ok(receipt) if receipt.status.is_verified_or_na() => Ok(()),
                Ok(receipt) => Err(receipt.error.unwrap_or_else(|| {
                    format!(
                        "graceful Flow B cleanup incomplete (status={:?})",
                        receipt.status
                    )
                })),
                Err(err) => Err(err),
            },
            StopBehavior::PreserveFailClosed => {
                let _ = self
                    .coordinator
                    .dispatch(crate::protocol::PipeRequest::NotifySystemShutdown);
                Ok(())
            }
        };

        self.coordinator.shutdown();
        self.pipe_server.shutdown();
        result
    }
}

/// Runs the daemon in foreground `--console` mode until `stop_rx` receives a signal (or forever if `None`).
pub fn run_console_until(
    config: DaemonConfig,
    driver: Arc<dyn PlatformDriver>,
    probe_runner: Arc<dyn ProbeRunner>,
    recovery_executor: Arc<dyn RecoveryExecutor>,
    stop_rx: Option<mpsc::Receiver<StopBehavior>>,
) -> Result<(), String> {
    let runtime = DaemonRuntime::start(config.clone(), driver, probe_runner, recovery_executor)?;
    eprintln!(
        "claudeguard-daemon --console listening on {} (data_dir={}; heal={:?})",
        runtime.pipe_name(),
        config.data_dir.display(),
        runtime.heal_report().status
    );

    let behavior = match stop_rx {
        Some(rx) => rx.recv().unwrap_or(config.shutdown_policy.on_stop),
        None => loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
    };
    runtime.shutdown_graceful(behavior)
}

#[cfg(windows)]
mod win_service {
    use super::*;
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
    use std::sync::{Mutex, OnceLock};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_EXISTS, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
    };
    use windows::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
        CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        StartServiceW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_ALL_ACCESS,
        SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_POWEREVENT,
        SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
        SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_POWEREVENT,
        SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
        SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    struct ScHandleGuard(SC_HANDLE);

    impl Drop for ScHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
            }
        }
    }

    struct ServiceBootstrap {
        config: DaemonConfig,
        factory: PlatformFactory,
    }

    static SERVICE_BOOTSTRAP: OnceLock<Mutex<Option<ServiceBootstrap>>> = OnceLock::new();
    static SERVICE_CTRL_CTX: OnceLock<ServiceCtrlContext> = OnceLock::new();

    struct ServiceCtrlContext {
        status_handle: AtomicIsize,
        policy: Mutex<ShutdownPolicy>,
        current_state: AtomicU32,
        checkpoint: AtomicU32,
        stop_tx: Mutex<Option<mpsc::SyncSender<StopBehavior>>>,
        coordinator: Mutex<Option<CoordinatorHandle>>,
    }

    impl ServiceCtrlContext {
        fn new() -> Self {
            Self {
                status_handle: AtomicIsize::new(0),
                policy: Mutex::new(ShutdownPolicy::default()),
                current_state: AtomicU32::new(SERVICE_START_PENDING.0),
                checkpoint: AtomicU32::new(0),
                stop_tx: Mutex::new(None),
                coordinator: Mutex::new(None),
            }
        }

        fn reset_for_run(&self, policy: ShutdownPolicy, stop_tx: mpsc::SyncSender<StopBehavior>) {
            self.status_handle.store(0, Ordering::Release);
            if let Ok(mut g) = self.policy.lock() {
                *g = policy;
            }
            self.current_state
                .store(SERVICE_START_PENDING.0, Ordering::Release);
            self.checkpoint.store(0, Ordering::Release);
            if let Ok(mut g) = self.stop_tx.lock() {
                *g = Some(stop_tx);
            }
            if let Ok(mut g) = self.coordinator.lock() {
                *g = None;
            }
        }

        fn report_status(
            &self,
            state: SERVICE_STATUS_CURRENT_STATE,
            controls_accepted: u32,
            win32_exit: u32,
            specific_exit: u32,
            wait_hint_ms: u32,
        ) {
            self.current_state.store(state.0, Ordering::SeqCst);
            let raw_handle = self.status_handle.load(Ordering::Acquire);
            if raw_handle == 0 {
                return;
            }
            let checkpoint = if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
                self.checkpoint.fetch_add(1, Ordering::SeqCst) + 1
            } else {
                0
            };
            let status = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: state,
                dwControlsAccepted: controls_accepted,
                dwWin32ExitCode: win32_exit,
                dwServiceSpecificExitCode: specific_exit,
                dwCheckPoint: checkpoint,
                dwWaitHint: wait_hint_ms,
            };
            let handle = SERVICE_STATUS_HANDLE(raw_handle as *mut c_void);
            unsafe {
                let _ = SetServiceStatus(handle, &status);
            }
        }
    }

    unsafe extern "system" fn service_ctrl_handler(
        dwcontrol: u32,
        dweventtype: u32,
        _lpeventdata: *mut c_void,
        lpcontext: *mut c_void,
    ) -> u32 {
        if lpcontext.is_null() {
            return NO_ERROR.0;
        }
        let ctx = &*(lpcontext as *const ServiceCtrlContext);
        match dwcontrol {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
                ctx.report_status(SERVICE_STOP_PENDING, 0, NO_ERROR.0, 0, 15_000);
                if matches!(
                    dwcontrol,
                    SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN
                ) {
                    if let Ok(guard) = ctx.coordinator.lock() {
                        if let Some(ref coord) = *guard {
                            coord.notify_system_shutting_down();
                        }
                    }
                }
                let policy = ctx.policy.lock().map(|g| *g).unwrap_or_default();
                if let Some(behavior) = plan_shutdown_action(dwcontrol, policy) {
                    if let Ok(mut guard) = ctx.stop_tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(behavior);
                        }
                    }
                }
                NO_ERROR.0
            }
            SERVICE_CONTROL_POWEREVENT => {
                if is_power_resume_event(dwcontrol, dweventtype) {
                    if let Ok(guard) = ctx.coordinator.lock() {
                        if let Some(ref coord) = *guard {
                            coord.notify_system_resumed();
                        }
                    }
                }
                NO_ERROR.0
            }
            SERVICE_CONTROL_INTERROGATE => {
                let state = SERVICE_STATUS_CURRENT_STATE(ctx.current_state.load(Ordering::SeqCst));
                let accepted = if state == SERVICE_RUNNING {
                    SERVICE_ACCEPT_STOP
                        | SERVICE_ACCEPT_SHUTDOWN
                        | SERVICE_ACCEPT_PRESHUTDOWN
                        | SERVICE_ACCEPT_POWEREVENT
                } else {
                    0
                };
                ctx.report_status(state, accepted, NO_ERROR.0, 0, 0);
                NO_ERROR.0
            }
            _ => NO_ERROR.0,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
        let bootstrap = SERVICE_BOOTSTRAP
            .get()
            .and_then(|m| m.lock().ok().and_then(|mut g| g.take()));
        let Some(boot) = bootstrap else {
            return;
        };

        let (stop_tx, stop_rx) = mpsc::sync_channel::<StopBehavior>(1);
        let svc_name_wide = to_wide_null(SERVICE_NAME);

        let ctx: &'static ServiceCtrlContext =
            SERVICE_CTRL_CTX.get_or_init(ServiceCtrlContext::new);
        ctx.reset_for_run(boot.config.shutdown_policy, stop_tx);

        let handle = match RegisterServiceCtrlHandlerExW(
            PCWSTR(svc_name_wide.as_ptr()),
            Some(service_ctrl_handler),
            Some((ctx as *const ServiceCtrlContext).cast::<c_void>()),
        ) {
            Ok(h) => h,
            Err(_) => {
                return;
            }
        };

        ctx.status_handle
            .store(handle.0 as isize, Ordering::Release);
        ctx.report_status(SERVICE_START_PENDING, 0, NO_ERROR.0, 0, 10_000);

        let (driver, probe_runner, recovery_executor) = (boot.factory)();
        let mut config = boot.config;
        config.service_mode = true;

        let runtime = match DaemonRuntime::start(config, driver, probe_runner, recovery_executor) {
            Ok(rt) => rt,
            Err(_) => {
                ctx.report_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR.0, 1, 0);
                return;
            }
        };

        if let Ok(mut g) = ctx.coordinator.lock() {
            *g = Some(runtime.coordinator().clone());
        }

        ctx.report_status(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP
                | SERVICE_ACCEPT_SHUTDOWN
                | SERVICE_ACCEPT_PRESHUTDOWN
                | SERVICE_ACCEPT_POWEREVENT,
            NO_ERROR.0,
            0,
            0,
        );

        let behavior = stop_rx.recv().unwrap_or(StopBehavior::PreserveFailClosed);
        ctx.report_status(SERVICE_STOP_PENDING, 0, NO_ERROR.0, 0, 15_000);
        if let Ok(mut g) = ctx.coordinator.lock() {
            *g = None;
        }

        let shutdown_res = runtime.shutdown_graceful(behavior);
        match shutdown_res {
            Ok(()) => {
                ctx.report_status(SERVICE_STOPPED, 0, NO_ERROR.0, 0, 0);
            }
            Err(_) => {
                ctx.report_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR.0, 2, 0);
            }
        }
    }

    /// Runs the process as a Windows Service under the Service Control Manager (`StartServiceCtrlDispatcherW`).
    pub fn run_as_windows_service(
        config: DaemonConfig,
        factory: PlatformFactory,
    ) -> Result<(), String> {
        let cell = SERVICE_BOOTSTRAP.get_or_init(|| Mutex::new(None));
        {
            let mut guard = cell
                .lock()
                .map_err(|_| "service bootstrap mutex poisoned".to_string())?;
            *guard = Some(ServiceBootstrap { config, factory });
        }

        let mut svc_name_wide = to_wide_null(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(svc_name_wide.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];

        unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|e| {
            let code = e.code().0 as u32 & 0xFFFF;
            if code == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.0 {
                "not started by Windows Service Control Manager (use --console for foreground mode)"
                    .to_string()
            } else {
                format!("StartServiceCtrlDispatcherW failed: {e}")
            }
        })
    }

    /// Installs or updates `ClaudeGuardService` (`LocalSystem`, `SERVICE_AUTO_START`) and optionally starts it.
    pub fn install_service(
        exe_path: &Path,
        start_now: bool,
    ) -> Result<ServiceInstallStatus, String> {
        const SERVICE_DEPENDENCIES: &[&str] = &["BFE", "MpsSvc"];
        let binary_cmd = format_service_binary_path(exe_path)?;
        let svc_name_w = to_wide_null(SERVICE_NAME);
        let display_w = to_wide_null(SERVICE_DISPLAY_NAME);
        let binary_w = to_wide_null(&binary_cmd);
        let deps_w = encode_service_dependencies(SERVICE_DEPENDENCIES);

        let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) }
            .map_err(|e| format!("OpenSCManagerW failed (admin required): {e}"))?;
        let scm_guard = ScHandleGuard(scm);

        let (service, created_new) = match unsafe {
            CreateServiceW(
                scm_guard.0,
                PCWSTR(svc_name_w.as_ptr()),
                PCWSTR(display_w.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(binary_w.as_ptr()),
                PCWSTR::null(),
                None,
                PCWSTR(deps_w.as_ptr()),
                PCWSTR::null(), // LocalSystem
                PCWSTR::null(),
            )
        } {
            Ok(h) => (ScHandleGuard(h), true),
            Err(e) if (e.code().0 as u32 & 0xFFFF) == ERROR_SERVICE_EXISTS.0 => {
                let h = unsafe {
                    OpenServiceW(scm_guard.0, PCWSTR(svc_name_w.as_ptr()), SERVICE_ALL_ACCESS)
                }
                .map_err(|oe| format!("OpenServiceW failed: {oe}"))?;
                let guard = ScHandleGuard(h);
                unsafe {
                    ChangeServiceConfigW(
                        guard.0,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        PCWSTR(binary_w.as_ptr()),
                        PCWSTR::null(),
                        None,
                        PCWSTR(deps_w.as_ptr()),
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR(display_w.as_ptr()),
                    )
                }
                .map_err(|ce| format!("ChangeServiceConfigW failed: {ce}"))?;
                (guard, false)
            }
            Err(e) => return Err(format!("CreateServiceW failed: {e}")),
        };

        let mut desc_w = to_wide_null(SERVICE_DESCRIPTION);
        let desc = SERVICE_DESCRIPTIONW {
            lpDescription: PWSTR(desc_w.as_mut_ptr()),
        };
        unsafe {
            let _ = ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_DESCRIPTION,
                Some((&desc as *const SERVICE_DESCRIPTIONW).cast()),
            );
        }

        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 15_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 30_000,
            },
        ];
        let failure_actions = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86_400,
            lpRebootMsg: PWSTR::null(),
            lpCommand: PWSTR::null(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        unsafe {
            let _ = ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                Some((&failure_actions as *const SERVICE_FAILURE_ACTIONSW).cast()),
            );
        }

        let mut started = false;
        if start_now {
            match query_service_handle_state(service.0)? {
                ServiceState::Running => started = true,
                _ => {
                    unsafe { StartServiceW(service.0, None) }
                        .map_err(|e| format!("StartServiceW failed: {e}"))?;
                    started = true;
                }
            }
        }

        Ok(ServiceInstallStatus {
            service_name: SERVICE_NAME.to_string(),
            binary_path: binary_cmd,
            created_new,
            started,
        })
    }

    /// Stops (if running) and deletes `ClaudeGuardService` from SCM (idempotent if absent).
    pub fn uninstall_service() -> Result<bool, String> {
        let svc_name_w = to_wide_null(SERVICE_NAME);
        let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) }
            .map_err(|e| format!("OpenSCManagerW failed (admin required): {e}"))?;
        let scm_guard = ScHandleGuard(scm);

        let service = match unsafe {
            OpenServiceW(scm_guard.0, PCWSTR(svc_name_w.as_ptr()), SERVICE_ALL_ACCESS)
        } {
            Ok(h) => ScHandleGuard(h),
            Err(e) if (e.code().0 as u32 & 0xFFFF) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
                return Ok(false);
            }
            Err(e) => return Err(format!("OpenServiceW failed: {e}")),
        };

        let mut current = query_service_handle_state(service.0)?;
        if current != ServiceState::Stopped {
            let mut status = SERVICE_STATUS::default();
            let _ = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while current != ServiceState::Stopped && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(200));
                current = query_service_handle_state(service.0)?;
            }
        }

        unsafe { DeleteService(service.0) }.map_err(|e| format!("DeleteService failed: {e}"))?;
        Ok(true)
    }

    /// Queries the current status of `ClaudeGuardService` from SCM without requiring admin rights.
    pub fn query_service_status() -> Result<ServiceState, String> {
        let svc_name_w = to_wide_null(SERVICE_NAME);
        let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map_err(|e| format!("OpenSCManagerW failed: {e}"))?;
        let scm_guard = ScHandleGuard(scm);

        let service = match unsafe {
            OpenServiceW(
                scm_guard.0,
                PCWSTR(svc_name_w.as_ptr()),
                SERVICE_QUERY_STATUS,
            )
        } {
            Ok(h) => ScHandleGuard(h),
            Err(e) if (e.code().0 as u32 & 0xFFFF) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
                return Ok(ServiceState::NotInstalled);
            }
            Err(e) => return Err(format!("OpenServiceW failed: {e}")),
        };
        query_service_handle_state(service.0)
    }

    fn query_service_handle_state(service: SC_HANDLE) -> Result<ServiceState, String> {
        let mut buf = [0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
        let mut needed = 0u32;
        unsafe {
            QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, Some(&mut buf), &mut needed)
        }
        .map_err(|e| format!("QueryServiceStatusEx failed: {e}"))?;
        let info: SERVICE_STATUS_PROCESS = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        Ok(match info.dwCurrentState.0 {
            1 => ServiceState::Stopped,
            2 => ServiceState::StartPending,
            3 => ServiceState::StopPending,
            4 => ServiceState::Running,
            5 => ServiceState::ContinuePending,
            6 => ServiceState::PausePending,
            7 => ServiceState::Paused,
            _ => ServiceState::Unknown,
        })
    }
}

#[cfg(not(windows))]
mod stub_service {
    use super::*;

    pub fn run_as_windows_service(
        _config: DaemonConfig,
        _factory: PlatformFactory,
    ) -> Result<(), String> {
        Err("Windows Service Control Manager is only supported on Windows".to_string())
    }

    pub fn install_service(
        _exe_path: &Path,
        _start_now: bool,
    ) -> Result<ServiceInstallStatus, String> {
        Err("Windows Service installation is only supported on Windows".to_string())
    }

    pub fn uninstall_service() -> Result<bool, String> {
        Err("Windows Service uninstallation is only supported on Windows".to_string())
    }

    pub fn query_service_status() -> Result<ServiceState, String> {
        Ok(ServiceState::NotInstalled)
    }
}

#[cfg(windows)]
pub use win_service::{
    install_service, query_service_status, run_as_windows_service, uninstall_service,
};

#[cfg(not(windows))]
pub use stub_service::{
    install_service, query_service_status, run_as_windows_service, uninstall_service,
};

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::disarm;
    use crate::engine_runtime::PlatformProbeRunner;
    use crate::ipc_pipe::PipeClient;
    use crate::journal::tests::{MockRecoveryExecutor, MockRecoveryState};
    use crate::journal::{
        BaselineState, FirewallDirection, HealStatus, JournalStore, PlannedStep, TxKind, WalAction,
    };
    use crate::protocol::PipeRequest;
    use cg_platform::UnsupportedPlatformDriver;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SVC_TEST_PIPE_SEQ: AtomicU64 = AtomicU64::new(1);

    fn test_pipe() -> String {
        let n = SVC_TEST_PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\ClaudeGuardV4-svc-{}-{n}", std::process::id())
    }

    #[test]
    fn shutdown_policy_maps_stop_and_shutdown_controls() {
        let policy = ShutdownPolicy {
            on_stop: StopBehavior::RunFlowBCleanup,
            on_shutdown: StopBehavior::PreserveFailClosed,
        };
        assert_eq!(
            plan_shutdown_action(1, policy),
            Some(StopBehavior::RunFlowBCleanup)
        );
        assert_eq!(
            plan_shutdown_action(5, policy),
            Some(StopBehavior::PreserveFailClosed)
        );
        assert_eq!(
            plan_shutdown_action(0x0000_000F, policy),
            Some(StopBehavior::PreserveFailClosed)
        );
        assert_eq!(plan_shutdown_action(4, policy), None);

        // Win32 MULTI_SZ dependency encoding (`BFE\0MpsSvc\0\0`).
        let deps = encode_service_dependencies(&["BFE", "MpsSvc"]);
        let expected: Vec<u16> = "BFE\0MpsSvc\0\0".encode_utf16().collect();
        assert_eq!(deps, expected);
        assert_eq!(encode_service_dependencies(&[]), vec![0u16, 0u16]);

        // Power resume event classification.
        assert!(is_power_resume_event(0x0D, 0x12));
        assert!(is_power_resume_event(0x0D, 0x07));
        assert!(!is_power_resume_event(0x0D, 0x04)); // PBT_APMSUSPEND
        assert!(!is_power_resume_event(0x01, 0x12));

        // ImagePath sanitization & canonicalization.
        assert_eq!(
            sanitize_service_exe_str(r"\\?\C:\Program Files\ClaudeGuard\claudeguard-daemon.exe")
                .unwrap(),
            r#""C:\Program Files\ClaudeGuard\claudeguard-daemon.exe""#
        );
        assert_eq!(
            sanitize_service_exe_str(r"\\?\UNC\server\share\claudeguard-daemon.exe").unwrap(),
            r#""\\?\UNC\server\share\claudeguard-daemon.exe""#
        );
        assert!(sanitize_service_exe_str("中文路径\\claudeguard-daemon.exe").is_ok());
        assert!(sanitize_service_exe_str(r#"C:\bad"quote\daemon.exe"#).is_err());
        assert!(
            format_service_binary_path(Path::new(r"C:\nonexistent-cg-test\daemon.exe")).is_err()
        );
    }

    #[test]
    fn daemon_runtime_startup_heals_wal_then_serves_pipe_and_honors_stop_policies() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());
        store
            .begin_tx(
                3,
                TxKind::Lockdown,
                vec![PlannedStep {
                    step_id: 1,
                    description: "leftover lockdown".into(),
                    action: WalAction::AddFirewallRule {
                        rule_name: "ClaudeGuard Lockdown (claude)".into(),
                        program: None,
                        direction: FirewallDirection::Outbound,
                    },
                }],
                BaselineState::default(),
            )
            .unwrap();

        let exec = Arc::new(MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec!["ClaudeGuard Lockdown (claude)".into()],
            ..Default::default()
        }));
        let driver: Arc<dyn PlatformDriver> = Arc::new(UnsupportedPlatformDriver::default());
        let runner: Arc<dyn ProbeRunner> = Arc::new(PlatformProbeRunner);

        let pipe = test_pipe();
        let cfg = DaemonConfig {
            pipe_name: pipe.clone(),
            data_dir: dir.path().to_path_buf(),
            shutdown_policy: ShutdownPolicy::default(),
            service_mode: false,
            enable_background_loop: false,
        };

        let runtime =
            DaemonRuntime::start(cfg.clone(), driver.clone(), runner.clone(), exec.clone())
                .unwrap();
        assert_eq!(runtime.heal_report().status, HealStatus::RecoveredFromCrash);
        assert!(!store.path().exists());

        let mut client = PipeClient::connect(&pipe, 2000).unwrap();
        let resp = client.call(&PipeRequest::GetSnapshot).unwrap();
        assert!(matches!(
            resp,
            crate::protocol::PipeResponse::Snapshot { .. }
        ));
        drop(client);

        // Now simulate a new mutation WAL written during runtime, stopped with PreserveFailClosed.
        store
            .begin_tx(
                4,
                TxKind::GlobalCut,
                vec![PlannedStep {
                    step_id: 1,
                    description: "active cut".into(),
                    action: WalAction::GlobalFirewallCut {
                        rule_name: "ClaudeGuard Cut All".into(),
                    },
                }],
                BaselineState::default(),
            )
            .unwrap();
        exec.state
            .lock()
            .unwrap()
            .firewall_rules
            .push("ClaudeGuard Cut All".into());

        runtime
            .shutdown_graceful(StopBehavior::PreserveFailClosed)
            .unwrap();
        assert!(
            store.path().exists(),
            "PreserveFailClosed must preserve WAL journal across shutdown"
        );

        // Next boot heals it and then graceful Flow B stop cleans everything cleanly without disarming.
        let runtime2 = DaemonRuntime::start(cfg, driver, runner, exec.clone()).unwrap();
        assert_eq!(
            runtime2.heal_report().status,
            HealStatus::RecoveredFromCrash
        );
        assert!(!store.path().exists());
        assert!(exec.state.lock().unwrap().firewall_rules.is_empty());

        exec.state
            .lock()
            .unwrap()
            .firewall_rules
            .push("ClaudeGuard Block Out (claude)".into());
        runtime2
            .shutdown_graceful(StopBehavior::RunFlowBCleanup)
            .unwrap();
        assert!(exec.state.lock().unwrap().firewall_rules.is_empty());
        assert!(
            disarm::read_disarmed(dir.path()).unwrap().is_none(),
            "service stop Flow B must NOT write permanent disarm marker"
        );
    }
}
