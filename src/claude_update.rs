//! Official Claude and Codex MSIX updates. Never removes packages, resets data, or closes Claude.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::model::TargetState;
use crate::state::AppState;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Claude,
    Codex,
}
impl Product {
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::Codex => "Codex",
        }
    }
    fn key(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
    fn updater(self, state: &AppState) -> &Updater {
        match self {
            Self::Claude => &state.claude_update,
            Self::Codex => &state.codex_update,
        }
    }
}

const CHECK_INTERVAL: u64 = 7 * 24 * 60 * 60;

fn check_due(last_check: u64, timestamp: u64) -> bool {
    last_check == 0 || timestamp.saturating_sub(last_check) >= CHECK_INTERVAL
}

/// 与 v2 的「最近一轮全部启用目标通过且未熔断」等价；自动安装前的安全门。
fn guard_healthy(app: &AppState) -> bool {
    if app.is_tripped() {
        return false;
    }
    let statuses = app.statuses();
    let enabled: Vec<_> = statuses
        .iter()
        .filter(|s| s.state != TargetState::Disabled)
        .collect();
    !enabled.is_empty() && enabled.iter().all(|s| s.state == TargetState::Pass)
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Status {
    pub enabled: bool,
    pub phase: String,
    pub installed_version: String,
    pub latest_version: String,
    // Retain an accepted deployment across restarts. A second submission requires
    // the explicit finish action and consumes its authorization before deployment.
    pub pending_version: String,
    pub pending_since: u64,
    pub resume_pending: bool,
    pub resume_after_boot: String,
    pub pending_attention_sent: bool,
    pub last_check: u64,
    pub last_updated: u64,
    pub downloaded: u64,
    pub total: u64,
    pub error: String,
    pub failure_stage: String,
    pub wait_reason: String,
    pub next_check: u64,
}

impl Status {
    fn recover(&mut self) {
        if self.phase == "failed" && registration_error(&self.error) {
            self.error = package_error(&self.error);
        }
        if self.phase == "installing" {
            self.phase = "failed".into();
            // The interrupted operation was deployment, even if a previous
            // network failure left a retryable stage in persisted state.
            self.failure_stage = "installing".into();
            self.resume_pending = false;
            self.error =
                "上次安装过程中守护器退出，结果尚未确认；请点击检查更新核对，未自动重复安装。"
                    .into();
        } else if !self.pending_version.is_empty() && self.phase != "failed" {
            if self.pending_since == 0 {
                self.pending_since = if self.last_check == 0 {
                    now()
                } else {
                    self.last_check
                };
            }
            self.phase = if self.resume_pending {
                "resume_waiting"
            } else {
                "deferred"
            }
            .into();
        } else if matches!(
            self.phase.as_str(),
            "checking" | "downloading" | "verifying"
        ) {
            self.phase = "idle".into();
            self.last_check = 0;
        }
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.error.clear();
        if !enabled {
            self.resume_pending = false;
            self.resume_after_boot.clear();
        }
        if self.pending_version.is_empty() {
            self.phase = "idle".into();
            self.last_check = 0;
        } else {
            // This switch controls future work, not a deployment Windows accepted.
            self.phase = "deferred".into();
        }
    }
    fn should_check(&self, timestamp: u64, healthy: bool) -> bool {
        if self.phase == "failed" {
            return self.pending_version.is_empty()
                && self.enabled
                && healthy
                && matches!(self.failure_stage.as_str(), "checking" | "downloading")
                && check_due(self.last_check, timestamp);
        }
        !self.pending_version.is_empty()
            || (self.enabled
                && healthy
                && (check_due(self.last_check, timestamp)
                    || matches!(self.phase.as_str(), "waiting" | "available")))
    }
    fn observe_pending(
        &mut self,
        installed: &str,
        healthy: bool,
        timestamp: u64,
    ) -> Result<bool, String> {
        let completed = healthy && version(installed)? >= version(&self.pending_version)?;
        self.installed_version = installed.into();
        self.error.clear();
        if completed {
            self.phase = "updated".into();
            self.pending_version.clear();
            self.pending_since = 0;
            self.pending_attention_sent = false;
            self.resume_pending = false;
            self.resume_after_boot.clear();
            self.last_updated = timestamp;
        } else {
            self.phase = "deferred".into();
        }
        Ok(completed)
    }
    fn pending_action(
        &mut self,
        package: &Package,
        timestamp: u64,
        finish: bool,
    ) -> Result<PendingAction, String> {
        if self.observe_pending(&package.version, package.healthy, timestamp)? {
            return Ok(PendingAction::Completed);
        }
        if self.pending_since == 0 {
            self.pending_since = timestamp;
        }
        if finish && !self.resume_pending {
            if package.reboot_required && package.boot_id.is_empty() {
                return Err(
                    "Windows 存在待重启状态，但无法读取系统启动时间；请重启电脑后重试。".into(),
                );
            }
            self.resume_pending = true;
            self.resume_after_boot = if package.reboot_required {
                package.boot_id.clone()
            } else {
                String::new()
            };
        }
        if self.resume_pending {
            if !self.resume_after_boot.is_empty()
                && (package.boot_id.is_empty() || self.resume_after_boot == package.boot_id)
            {
                self.phase = "resume_restart".into();
            } else if package.running {
                self.phase = "resume_waiting".into();
            } else {
                if !package.healthy {
                    return Err(unhealthy_package(&package.package_status));
                }
                self.phase = "resume_waiting".into();
                return Ok(PendingAction::Finish);
            }
        } else if timestamp.saturating_sub(self.pending_since) >= 600 {
            self.phase = if package.reboot_required {
                "restart_required"
            } else {
                "pending_stalled"
            }
            .into();
        }
        Ok(PendingAction::Observe)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PendingAction {
    Observe,
    Completed,
    Finish,
}

#[derive(Default, Deserialize)]
struct Package {
    version: String,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    running: bool,
    #[serde(default)]
    state: String,
    #[serde(default)]
    healthy: bool,
    #[serde(default)]
    package_status: String,
    #[serde(default)]
    reboot_required: bool,
    #[serde(default)]
    boot_id: String,
    #[serde(default)]
    blockers: Vec<String>,
}

fn running_reason(product: Product, package: &Package) -> String {
    let names = package
        .blockers
        .iter()
        .map(|name| match name.to_ascii_lowercase().as_str() {
            "chatgpt" => "Codex 桌面".to_string(),
            "codex" | "codex-command-runner" => "Codex 命令行任务".to_string(),
            _ => name.clone(),
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        format!("等待 {} 和相关任务正常退出；不会自动强退。", product.name())
    } else {
        format!("仍在运行：{}。请保存工作后正常退出。", names.join("、"))
    }
}

pub struct Updater {
    product: Product,
    state: Mutex<Status>,
    busy: AtomicBool,
    pub installing: AtomicBool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn state_path(product: Product) -> PathBuf {
    crate::config::config_dir().join(format!("{}-update.json", product.key()))
}

fn version(value: &str) -> Result<[u32; 4], String> {
    let parts: Vec<_> = value.split('.').collect();
    if !(3..=4).contains(&parts.len()) {
        return Err("版本号格式无效".into());
    }
    let mut result = [0; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) {
            return Err("版本号格式无效".into());
        }
        result[index] = part.parse().map_err(|_| "版本号超出范围")?;
    }
    Ok(result)
}

fn registration_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("0x80073cf9") && lower.contains("0x80070643")
}

fn package_error(error: &str) -> String {
    if registration_error(error) {
        "Windows 应用注册失败（0x80073CF9 / 0x80070643），本次更新未完成。请保存工作并重启 Windows，再点击检查更新；若仍失败需继续排查系统注册状态。不会卸载、重置或清理登录数据。".into()
    } else {
        format!(
            "Windows 更新处理失败：{}",
            error.trim().chars().take(1200).collect::<String>()
        )
    }
}

fn unhealthy_package(status: &str) -> String {
    format!("Windows 应用状态尚未恢复正常（{status}），不能确认更新完成，未提交新的安装。请保存工作并重启 Windows 后再检查；不会卸载或重置登录数据。")
}

fn launch_package_ready(result: Result<Package, String>) -> Result<(), String> {
    let installed = result.map_err(|error| {
        if error.contains("Expected exactly one installed official package") {
            "无法确认当前 Windows 账户下有效的 Claude 安装注册。请在 Windows 开始菜单检查 Claude；若此前更新未完成，请保存工作并重启 Windows 后再试。".to_string()
        } else {
            let detail = error
                .trim_start_matches("Windows 更新处理失败：")
                .chars()
                .take(300)
                .collect::<String>();
            format!("暂时无法检查 Claude 的 Windows 安装状态，未发送启动请求。请稍后重试；若持续失败，请查看运行日志。详情：{detail}")
        }
    })?;
    let status = installed.package_status.trim();
    if installed.healthy && status == "Ok" && version(&installed.version).is_ok() {
        return Ok(());
    }
    if status.to_ascii_lowercase().contains("servicing") {
        Err("Claude 更新尚未完成，Windows 仍在维护应用（Servicing），目前无法正常启动。请保存工作并重启 Windows，再从守护器启动 Claude；仅退出 Claude 或重启守护器不能完成系统重启。".into())
    } else {
        let status = if status.is_empty() { "未知" } else { status };
        Err(format!("Claude 的 Windows 安装状态异常（{status}），未发送启动请求。请保存工作并重启 Windows 后再试；若仍打不开，请继续检查系统应用注册错误。"))
    }
}

/// Read-only preflight. This never installs, repairs, or resets the application.
pub fn check_claude_launch_ready() -> Result<(), String> {
    launch_package_ready(package(Product::Claude, "inspect", None, ""))
}

fn release_version(url: &str, arch: &str) -> Result<String, String> {
    if !matches!(arch, "x64" | "arm64") {
        return Err("不支持此 Claude 架构".into());
    }
    let prefix = format!("https://downloads.claude.ai/releases/win32/{arch}/");
    let tail = url
        .strip_prefix(&prefix)
        .ok_or("更新地址不是官方发布地址")?;
    let (v, file) = tail.split_once('/').ok_or("官方更新地址格式变化")?;
    version(v)?;
    let hash = file
        .strip_prefix("Claude-")
        .and_then(|f| f.strip_suffix(".msix"))
        .ok_or("更新包格式无效")?;
    if hash.len() != 40 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("更新包地址格式无效".into());
    }
    Ok(v.into())
}

fn cache_file(product: Product, v: &str) -> Result<PathBuf, String> {
    version(v)?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(exe
        .parent()
        .ok_or("程序目录无效")?
        .join(format!("{}Updates", product.name()))
        .join(format!("{}-{v}.msix", product.name())))
}

/// Bound only read-only inspection. Never terminate an installer on a timer.
fn inspect_output(cmd: &mut Command, timeout: Duration) -> Result<Output, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("无法调用 Windows 包状态检查：{e}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("无法读取 Windows 包状态检查结果：{e}"));
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            state => {
                // This handle belongs only to our read-only PowerShell probe.
                // No application, installer, or Windows service is terminated.
                let _ = child.kill();
                let _ = child.wait();
                return Err(match state {
                    Err(error) => format!("无法确认 Windows 包状态检查结果：{error}"),
                    _ => "读取 Windows 应用状态超时，已停止本次只读检查。请稍后重试；未提交安装或修改登录数据。".into(),
                });
            }
        }
    }
}

fn package(
    product: Product,
    action: &str,
    file: Option<&Path>,
    v: &str,
) -> Result<Package, String> {
    let script = include_str!("claude_package.ps1").trim_start_matches('\u{feff}');
    let encoded = STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let v = if v.is_empty() {
        String::new()
    } else {
        version(v)?
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    };
    let mut cmd = Command::new(crate::guard::sys32(
        r"WindowsPowerShell\v1.0\powershell.exe",
    ));
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-OutputFormat",
        "Text",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &encoded,
    ])
    .env("CG_UPDATE_PRODUCT", product.key())
    .env_remove("PSModulePath")
    .env("CG_UPDATE_ACTION", action)
    .env("CG_UPDATE_VERSION", v)
    .creation_flags(0x08000000);
    if let Some(file) = file {
        cmd.env("CG_UPDATE_FILE", file);
    }
    let result = if action == "inspect" {
        inspect_output(&mut cmd, Duration::from_secs(10))?
    } else {
        cmd.output()
            .map_err(|e| format!("无法调用 Windows 包管理：{e}"))?
    };
    if !result.status.success() {
        let error = String::from_utf8_lossy(&result.stderr);
        return Err(package_error(&error));
    }
    let text = String::from_utf8_lossy(&result.stdout);
    serde_json::from_str(text.trim().trim_start_matches('\u{feff}'))
        .map_err(|_| "Windows 返回的包状态无效".into())
}

fn agent(cfg: &Config) -> Result<ureq::Agent, String> {
    let proxy = ureq::Proxy::new(format!("http://{}:{}", cfg.proxy_host, cfg.proxy_port))
        .map_err(|_| "代理地址无效")?;
    Ok(ureq::AgentBuilder::new()
        .proxy(proxy)
        .try_proxy_from_env(false)
        .max_idle_connections(0)
        .redirects(0)
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(45))
        .timeout(Duration::from_secs(600))
        .build())
}

fn discover(product: Product, agent: &ureq::Agent, arch: &str) -> Result<(String, String), String> {
    if !matches!(arch, "x64" | "arm64") {
        return Err("不支持此 Claude 架构".into());
    }
    if product == Product::Codex {
        let url = format!("https://persistent.oaistatic.com/codex-app-prod/ChatGPT-{arch}.msix");
        let response = call_retry(agent.head(&url).timeout(Duration::from_secs(30)))
            .map_err(|_| "无法连接 OpenAI 官方更新接口")?;
        if response.status() != 200
            || response.header("x-ms-meta-package_identity") != Some("OpenAI.Codex")
            || response.header("x-ms-meta-architecture") != Some(arch)
        {
            return Err("OpenAI 更新包元数据不匹配，请稍后重试".into());
        }
        let v = response
            .header("x-ms-meta-package_version")
            .ok_or("OpenAI 更新接口缺少包版本")?;
        version(v)?;
        return Ok((v.into(), url));
    }
    let url = format!("https://claude.ai/api/desktop/win32/{arch}/msix/latest/redirect");
    let response = call_retry(agent.get(&url).timeout(Duration::from_secs(30)))
        .map_err(|_| "无法连接 Claude 官方更新接口，请检查代理".to_string())?;
    if !matches!(response.status(), 301 | 302 | 303 | 307 | 308) {
        return Err("官方更新接口未返回下载地址".into());
    }
    let url = response
        .header("Location")
        .ok_or("官方更新接口缺少下载地址")?
        .to_string();
    let v = release_version(&url, arch)?;
    Ok((v, url))
}

impl Updater {
    pub fn load(product: Product) -> Self {
        let mut state: Status = fs::read_to_string(state_path(product))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        state.recover();
        Self {
            product,
            state: Mutex::new(state),
            busy: AtomicBool::new(false),
            installing: AtomicBool::new(false),
        }
    }
    pub fn status(&self) -> Status {
        let mut state = self.state.lock().unwrap().clone();
        state.next_check = if state.enabled
            && state.pending_version.is_empty()
            && !matches!(
                state.phase.as_str(),
                "checking" | "downloading" | "verifying" | "installing" | "waiting" | "available"
            )
            && (state.phase != "failed"
                || matches!(state.failure_stage.as_str(), "checking" | "downloading"))
        {
            if state.last_check == 0 {
                now()
            } else {
                state.last_check.saturating_add(CHECK_INTERVAL)
            }
        } else {
            0
        };
        state
    }
    fn persist(&self) -> Result<(), String> {
        let state = self.status();
        let path = state_path(self.product);
        fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        fs::rename(tmp, path).map_err(|e| e.to_string())
    }
    pub fn configure(&self, enabled: bool) -> Result<Status, String> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("更新任务正在处理，请完成后再切换".into());
        }
        let before = self.status();
        {
            let mut state = self.state.lock().unwrap();
            state.set_enabled(enabled);
        }
        let result = self.persist();
        if result.is_err() {
            *self.state.lock().unwrap() = before;
        }
        self.busy.store(false, Ordering::SeqCst);
        result.map(|_| self.status())
    }
    fn phase(&self, phase: &str) {
        let mut state = self.state.lock().unwrap();
        state.phase = phase.into();
        state.wait_reason.clear();
    }
    pub fn request(state: &Arc<AppState>, product: Product, finish: bool) -> Result<(), String> {
        Self::request_inner(state, product, true, finish)
    }
    fn request_inner(
        state: &Arc<AppState>,
        product: Product,
        manual: bool,
        finish: bool,
    ) -> Result<(), String> {
        if product
            .updater(state)
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("正在检查或更新客户端".into());
        }
        let state = Arc::clone(state);
        std::thread::spawn(move || {
            let updater = product.updater(&state);
            let name = product.name();
            let outcome = updater.run(&state, manual, finish);
            if let Err(error) = outcome {
                {
                    let mut state = updater.state.lock().unwrap();
                    state.failure_stage = state.phase.clone();
                    state.phase = "failed".into();
                    state.resume_pending = false;
                    state.error = error.clone();
                    state.last_check = now();
                }
                state.log(format!("{name} 更新已停止：{error}"));
                if updater.status().pending_version.is_empty() {
                    let schedule = if updater.status().next_check > 0 {
                        "本次检查或下载已停止，下周按计划再检查；也可手动立即重试。"
                    } else {
                        "已停止自动安装重试，请在守护器查看原因后手动处理。"
                    };
                    let _ = state.notify(
                        "client_update",
                        &format!("{name} 更新失败"),
                        &format!("{error}\n{schedule}\n未卸载、重置或清理登录数据。"),
                    );
                } else {
                    let _ = state.notify(
                        "client_update",
                        &format!("{name} 更新尚未完成"),
                        &format!("{error}\n已停止自动重试。待生效目标已保留，未卸载、重置或清理登录数据；请在守护器查看具体原因。"),
                    );
                }
            }
            if let Err(error) = updater.persist() {
                state.log(format!("无法保存 {name} 更新状态：{error}"));
            }
            updater.installing.store(false, Ordering::SeqCst);
            updater.busy.store(false, Ordering::SeqCst);
            state.emit_state();
        });
        Ok(())
    }
    pub fn start(state: &Arc<AppState>, product: Product) {
        let state = Arc::clone(state);
        std::thread::spawn(move || {
            while !state.stop.load(Ordering::SeqCst) {
                let s = product.updater(&state).status();
                let healthy = guard_healthy(&state);
                // Unsafe installation failures stay stopped. Read-only checks may
                // recover on the next weekly schedule; never fall back to repair.
                if s.should_check(now(), healthy) {
                    let _ = Self::request_inner(&state, product, false, false);
                }
                for _ in 0..30 {
                    if state.stop.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }
    fn run(&self, app: &AppState, manual: bool, finish: bool) -> Result<(), String> {
        let name = self.product.name();
        let previous = self.status();
        self.state.lock().unwrap().wait_reason.clear();
        // Ordinary checks only observe. Finishing a stuck update is a separate,
        // explicit action, performed once after the required reboot / clean exit.
        if !previous.pending_version.is_empty() {
            let installed = package(self.product, "inspect", None, "")?;
            let action = self
                .state
                .lock()
                .unwrap()
                .pending_action(&installed, now(), finish)?;
            if self.status().phase == "resume_waiting" && installed.running {
                self.state.lock().unwrap().wait_reason = running_reason(self.product, &installed);
            }
            let attention = {
                let mut state = self.state.lock().unwrap();
                if !state.pending_attention_sent
                    && matches!(state.phase.as_str(), "restart_required" | "pending_stalled")
                {
                    state.pending_attention_sent = true;
                    Some(state.phase.clone())
                } else {
                    None
                }
            };
            self.persist()?;
            if let Some(phase) = attention {
                let next = if phase == "restart_required" {
                    "Windows 存在待重启状态。请在守护器中安排完成已下载更新，保存工作并重启电脑。"
                } else {
                    "请在守护器中点击完成已下载更新，安排一次原位安装尝试。"
                };
                let _ = app.notify(
                    "client_update",
                    &format!("{name} 更新需要处理"),
                    &format!("新版长时间尚未完成注册，当前仍未确认更新成功。{next}"),
                );
            }
            if finish && !previous.resume_pending && self.status().resume_pending {
                app.log(format!(
                    "{name} 已安排完成已下载更新；只尝试一次，等待重启或程序正常退出"
                ));
            }
            match action {
                PendingAction::Completed => self.notify_completed(app, &installed.version),
                PendingAction::Finish => self.finish_pending(app, &previous.pending_version)?,
                PendingAction::Observe => {}
            }
            return Ok(());
        }
        if finish {
            return Ok(());
        }
        self.phase("checking");
        self.state.lock().unwrap().error.clear();
        self.persist()?;
        let installed = package(self.product, "inspect", None, "")?;
        self.state.lock().unwrap().installed_version = installed.version.clone();
        if !installed.healthy {
            self.phase("blocked");
            return Err(unhealthy_package(&installed.package_status));
        }
        let cfg = app.config();
        let agent = agent(&cfg)?;
        // While waiting for an already verified package, avoid repeated network checks.
        let reuse_pending = !manual
            && previous.phase == "waiting"
            && !previous.latest_version.is_empty()
            && !check_due(previous.last_check, now());
        let (latest, url) = if reuse_pending {
            (previous.latest_version.clone(), String::new())
        } else {
            discover(self.product, &agent, &installed.architecture)?
        };
        {
            let mut state = self.state.lock().unwrap();
            state.latest_version = latest.clone();
            if !reuse_pending {
                state.last_check = now();
            }
        }
        if version(&latest)? <= version(&installed.version)? {
            self.phase("current");
            if matches!(previous.phase.as_str(), "waiting" | "failed")
                && version(&previous.latest_version).is_ok_and(|target| {
                    version(&installed.version).is_ok_and(|current| current >= target)
                })
            {
                self.phase("updated");
                self.state.lock().unwrap().last_updated = now();
                self.persist()?;
                self.notify_completed(app, &installed.version);
            }
            return Ok(());
        }
        if !self.status().enabled {
            self.phase("available");
            return Ok(());
        }
        if reuse_pending && installed.running {
            self.phase("waiting");
            self.state.lock().unwrap().wait_reason = running_reason(self.product, &installed);
            return Ok(());
        }
        let healthy = guard_healthy(app);
        if !healthy {
            self.phase("available");
            self.state.lock().unwrap().wait_reason =
                "等待守护检查通过后继续；当前不提交安装。".into();
            return Ok(());
        }
        let file = cache_file(self.product, &latest)?;
        fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
        if !file.exists() {
            if url.is_empty() {
                return Err("已下载的更新包丢失，请手动重新检查".into());
            }
            self.phase("downloading");
            self.download(&agent, &url, &file)?;
        }
        self.phase("verifying");
        if let Err(error) = package(self.product, "verify", Some(&file), &latest) {
            // Quarantine only a package that failed verification. Deployment failures
            // must not discard a previously verified download.
            let _ = fs::rename(&file, file.with_extension("msix.rejected"));
            return Err(error);
        }
        if installed.running {
            self.phase("waiting");
            self.state.lock().unwrap().wait_reason = running_reason(self.product, &installed);
            if previous.phase != "waiting" {
                let _ = app.notify(
                    "client_update",
                    &format!("{name} 更新已准备"),
                    &format!(
                        "{} → {latest}\n官方签名已验证。等待客户端和相关任务退出后自动原位升级，保留登录数据。",
                        installed.version
                    ),
                );
            }
            return Ok(());
        }
        // A download can outlast a healthy egress check. Recheck before deployment.
        if !guard_healthy(app) {
            self.phase("waiting");
            self.state.lock().unwrap().wait_reason =
                "等待守护检查通过后继续；当前不提交安装。".into();
            return Ok(());
        }
        self.installing.store(true, Ordering::SeqCst);
        self.phase("installing");
        self.persist()?;
        let result = package(self.product, "install", Some(&file), &latest)?;
        match result.state.as_str() {
            "unavailable" => return Err(unhealthy_package(&result.package_status)),
            "blocked" => return Err("Windows 未接受延后更新，仍报告应用被占用（0x80073D02）。请正常退出相关程序后手动检查；本次已停止，不会强制关闭、卸载或重置。".into()),
            "waiting" => {
                self.phase("waiting");
            }
            "deferred" => {
                {
                    let mut state = self.state.lock().unwrap();
                    state.phase = "deferred".into();
                    state.pending_version = latest.clone();
                    state.pending_since = now();
                    state.pending_attention_sent = false;
                    state.installed_version = result.version;
                }
                self.persist()?;
                let _ = app.notify(
                    "client_update",
                    &format!("{name} 更新尚未生效"),
                    &format!("目标版本：{latest}\nWindows 已接收延后更新，但尚未完成新版注册。守护器会核对结果；如长时间未完成，可在设置中选择“完成已下载更新”。未强制关闭程序或清理登录数据。"),
                );
                app.log(format!("{name} 更新已交给 Windows，等待版本 {latest} 注册生效"));
            }
            "updated" | "current" => {
                if !result.healthy || version(&result.version)? < version(&latest)? {
                    return Err("Windows 尚未注册目标版本，不能确认更新完成".into());
                }
                let mut state = self.state.lock().unwrap();
                state.phase = "updated".into();
                state.installed_version = result.version.clone();
                state.last_updated = now();
                drop(state);
                self.persist()?;
                self.notify_completed(app, &result.version);
            }
            _ => return Err("Windows 返回了未知更新结果".into()),
        }
        Ok(())
    }
    fn finish_pending(&self, app: &AppState, target: &str) -> Result<(), String> {
        if !guard_healthy(app) {
            self.state.lock().unwrap().wait_reason =
                "等待守护检查通过后完成更新；当前不提交安装。".into();
            return Ok(());
        }
        let file = cache_file(self.product, target)?;
        // Persist consumption first: a crash or unknown result must not replay it.
        {
            let mut state = self.state.lock().unwrap();
            state.resume_pending = false;
            state.phase = "installing".into();
        }
        self.persist()?;
        self.installing.store(true, Ordering::SeqCst);
        let result = package(self.product, "finish", Some(&file), target)?;
        match result.state.as_str() {
            "waiting" => {
                // The script checks processes before invoking any deployment API.
                let mut state = self.state.lock().unwrap();
                state.resume_pending = true;
                state.phase = "resume_waiting".into();
            }
            "updated" | "current" => {
                if !self.state.lock().unwrap().observe_pending(&result.version, result.healthy, now())? {
                    return Err("Windows 尚未完成新版注册，本次尝试已停止；请重启电脑后核对结果。".into());
                }
                self.persist()?;
                self.notify_completed(app, &result.version);
            }
            "unavailable" => return Err(unhealthy_package(&result.package_status)),
            "blocked" => return Err("Windows 仍报告应用占用（0x80073D02），本次完成更新的尝试已停止。请保存工作并重启电脑，再核对结果；未强制关闭程序。".into()),
            _ => return Err("Windows 尚未完成新版注册，本次尝试已停止；请重启电脑后核对结果。".into()),
        }
        Ok(())
    }
    fn notify_completed(&self, app: &AppState, installed: &str) {
        let name = self.product.name();
        let _ = app.notify(
            "client_update",
            &format!("{name} 更新完成"),
            &format!("当前版本：{installed}\n已确认新版注册生效，未清理登录数据。"),
        );
        app.log(format!("{name} 更新结果已确认：{installed}"));
    }
    fn download(&self, agent: &ureq::Agent, url: &str, file: &Path) -> Result<(), String> {
        let head = call_retry(agent.head(url).timeout(Duration::from_secs(30)))
            .map_err(|_| "无法读取更新包大小")?;
        if head.status() != 200 {
            return Err("无法读取官方更新包".into());
        }
        let size: u64 = head
            .header("Content-Length")
            .and_then(|v| v.parse().ok())
            .ok_or("更新包大小无效")?;
        if size == 0 || size > 1_073_741_824 {
            return Err("更新包大小超出限制".into());
        }
        let etag = head
            .header("ETag")
            .filter(|v| v.starts_with('"') && v.ends_with('"'))
            .ok_or("更新包缺少文件标识")?
            .to_string();
        let part = file.with_extension("msix.part");
        let meta = file.with_extension("msix.part.json");
        let identity = serde_json::to_vec(&(url, size, &etag)).map_err(|e| e.to_string())?;
        let existing = fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        let resume = fs::read(&meta).ok().as_deref() == Some(identity.as_slice())
            && existing <= size
            && (existing == size || existing.is_multiple_of(CHUNK_SIZE));
        let mut received = if resume { existing } else { 0 };
        let mut output = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(!resume)
            .open(&part)
            .map_err(|e| e.to_string())?;
        use std::io::{Seek, SeekFrom};
        output
            .seek(SeekFrom::Start(received))
            .map_err(|e| e.to_string())?;
        fs::write(&meta, identity).map_err(|e| e.to_string())?;
        {
            let mut state = self.state.lock().unwrap();
            state.downloaded = received;
            state.total = size;
        }
        while received < size {
            let chunks = std::thread::scope(|scope| {
                let mut workers = Vec::new();
                for index in 0..4 {
                    let start = received + index * CHUNK_SIZE;
                    if start >= size {
                        break;
                    }
                    let end = (start + CHUNK_SIZE - 1).min(size - 1);
                    let tag = etag.as_str();
                    workers
                        .push(scope.spawn(move || fetch_range(agent, url, start, end, size, tag)));
                }
                workers
                    .into_iter()
                    .map(|worker| worker.join().map_err(|_| "下载线程异常".to_string())?)
                    .collect::<Result<Vec<_>, String>>()
            })?;
            for bytes in chunks {
                output.write_all(&bytes).map_err(|e| e.to_string())?;
                received += bytes.len() as u64;
                self.state.lock().unwrap().downloaded = received;
            }
        }
        output.sync_all().map_err(|e| e.to_string())?;
        drop(output);
        fs::rename(part, file).map_err(|e| e.to_string())
    }
}

const CHUNK_SIZE: u64 = 1024 * 1024;
fn call_retry(request: ureq::Request) -> Result<ureq::Response, ()> {
    for _ in 0..3 {
        if let Ok(response) = request.clone().call() {
            return Ok(response);
        }
    }
    Err(())
}
fn fetch_range(
    agent: &ureq::Agent,
    url: &str,
    start: u64,
    end: u64,
    size: u64,
    etag: &str,
) -> Result<Vec<u8>, String> {
    let mut last = String::new();
    // GET is read-only. Retry a transient range failure at most three times;
    // package deployment is never automatically retried after an unknown outcome.
    for _ in 0..3 {
        match fetch_range_once(agent, url, start, end, size, etag) {
            Ok(bytes) => return Ok(bytes),
            Err(error) => last = error,
        }
    }
    Err(last)
}
fn fetch_range_once(
    agent: &ureq::Agent,
    url: &str,
    start: u64,
    end: u64,
    size: u64,
    etag: &str,
) -> Result<Vec<u8>, String> {
    let response = agent
        .get(url)
        .set("Range", &format!("bytes={start}-{end}"))
        .set("Accept-Encoding", "identity")
        .set("If-Match", etag)
        .timeout(Duration::from_secs(45))
        .call()
        .map_err(|_| "下载连接中断，可点击检查继续下载")?;
    if response.status() != 206
        || response.header("ETag") != Some(etag)
        || content_range(response.header("Content-Range").unwrap_or(""), start, end)? != (end, size)
    {
        return Err("更新包分段或文件标识发生变化，请重新检查".into());
    }
    let expected = end - start + 1;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(expected + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "下载读取中断，可点击检查继续下载")?;
    if bytes.len() as u64 != expected {
        return Err("更新包分段不完整".into());
    }
    Ok(bytes)
}

fn content_range(value: &str, start: u64, requested_end: u64) -> Result<(u64, u64), String> {
    let bad = || "更新包分段范围无效".to_string();
    let (span, size) = value
        .strip_prefix("bytes ")
        .and_then(|v| v.split_once('/'))
        .ok_or_else(bad)?;
    let (first, last) = span.split_once('-').ok_or_else(bad)?;
    let first: u64 = first.parse().map_err(|_| bad())?;
    let last: u64 = last.parse().map_err(|_| bad())?;
    let size: u64 = size.parse().map_err(|_| bad())?;
    if size == 0
        || size > 1_073_741_824
        || first != start
        || first > last
        || last != requested_end.min(size - 1)
    {
        return Err(bad());
    }
    Ok((last, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_timeout_stops_only_its_read_only_probe() {
        let mut cmd = Command::new(crate::guard::sys32(
            r"WindowsPowerShell\v1.0\powershell.exe",
        ));
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 3",
        ])
        .creation_flags(0x08000000);
        assert!(inspect_output(&mut cmd, Duration::from_millis(100))
            .unwrap_err()
            .contains("超时"));
    }
    #[test]
    fn inspection_preserves_output_and_exit_status() {
        let mut cmd = Command::new(crate::guard::sys32(
            r"WindowsPowerShell\v1.0\powershell.exe",
        ));
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::Write('inspect-ok')\n[Console]::Error.Write('inspect-error')\nexit 7",
        ])
        .creation_flags(0x08000000);
        let result = inspect_output(&mut cmd, Duration::from_secs(5)).unwrap();
        assert_eq!(result.status.code(), Some(7));
        assert_eq!(result.stdout, b"inspect-ok");
        assert_eq!(result.stderr, b"inspect-error");
    }
    #[test]
    fn launch_requires_a_healthy_registered_package() {
        let healthy = Package {
            version: "2.37337.1.0".into(),
            healthy: true,
            package_status: "Ok".into(),
            ..Package::default()
        };
        assert!(launch_package_ready(Ok(healthy)).is_ok());
        for (status, healthy, expected) in [
            ("Servicing", false, "重启 Windows"),
            ("Modified", false, "状态异常"),
            ("", false, "未知"),
            ("", true, "未知"),
            ("Ok", false, "状态异常"),
        ] {
            let result = launch_package_ready(Ok(Package {
                version: "2.37337.1.0".into(),
                healthy,
                package_status: status.into(),
                ..Package::default()
            }));
            assert!(result.unwrap_err().contains(expected));
        }
    }
    #[test]
    fn launch_explains_missing_registration_and_failed_inspection() {
        let missing = launch_package_ready(Err(
            "Windows 更新处理失败：Expected exactly one installed official package".into(),
        ))
        .unwrap_err();
        assert!(missing.contains("安装注册"));
        let unknown = launch_package_ready(Err("Windows 返回的包状态无效".into())).unwrap_err();
        assert!(unknown.contains("未发送启动请求"));
        assert!(unknown.contains("包状态无效"));
    }
    #[test]
    fn network_ranges_reject_changed_objects_and_short_bodies() {
        use std::net::TcpListener;
        for (tag, body, accepted) in [
            ("\"release\"", "abcd", true),
            ("\"other\"", "abcd", false),
            ("\"release\"", "abc", false),
        ] {
            let server = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = server.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let (mut socket, _) = server.accept().unwrap();
                let mut request = [0; 4096];
                let _ = socket.read(&mut request).unwrap();
                let response = format!("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/4\r\nETag: {tag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                socket.write_all(response.as_bytes()).unwrap();
            });
            let agent = ureq::AgentBuilder::new().try_proxy_from_env(false).build();
            let result = fetch_range_once(
                &agent,
                &format!("http://{address}/package"),
                0,
                3,
                4,
                "\"release\"",
            );
            assert_eq!(result.is_ok(), accepted);
            worker.join().unwrap();
        }
    }
    #[test]
    fn ranges_reject_truncation_and_wrong_offsets() {
        assert_eq!(content_range("bytes 0-9/10", 0, 100).unwrap(), (9, 10));
        for bad in [
            "bytes 1-9/10",
            "bytes 0-8/10",
            "bytes 0-9/0",
            "bytes 0-9/2147483648",
            "garbage",
        ] {
            assert!(content_range(bad, 0, 100).is_err());
        }
    }
    #[test]
    fn automatic_checks_wait_a_full_week() {
        assert!(check_due(0, 100));
        assert!(!check_due(100, 100 + 3600));
        assert!(!check_due(100, 100 + 604799));
        assert!(check_due(100, 100 + 604800));
        assert!(!check_due(100, 99));
    }
    #[test]
    fn network_failure_keeps_weekly_schedule_but_installation_failure_stays_stopped() {
        let mut state = Status {
            enabled: true,
            phase: "failed".into(),
            failure_stage: "downloading".into(),
            last_check: 100,
            ..Status::default()
        };
        assert!(!state.should_check(100 + 604799, true));
        assert!(state.should_check(100 + 604800, true));
        assert!(!state.should_check(100 + 604800, false));
        state.failure_stage = "installing".into();
        assert!(!state.should_check(100 + 604800, true));
        state.failure_stage = "verifying".into();
        assert!(!state.should_check(100 + 604800, true));
        state.failure_stage = "checking".into();
        state.pending_version = "26.1007.9446.0".into();
        assert!(!state.should_check(100 + 604800, true));
    }
    #[test]
    fn stalled_update_requires_an_explicit_finish_and_real_reboot() {
        let mut state = Status {
            pending_version: "26.1007.9446.0".into(),
            pending_since: 100,
            ..Status::default()
        };
        let mut installed = Package {
            version: "26.928.1915.0".into(),
            healthy: true,
            reboot_required: true,
            boot_id: "boot-one".into(),
            ..Package::default()
        };
        assert_eq!(
            state.pending_action(&installed, 800, false).unwrap(),
            PendingAction::Observe
        );
        assert_eq!(state.phase, "restart_required");
        assert!(!state.resume_pending);
        assert_eq!(
            state.pending_action(&installed, 800, true).unwrap(),
            PendingAction::Observe
        );
        assert_eq!(state.phase, "resume_restart");
        let mut restored: Status =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        restored.recover();
        // Relaunching the guard or Codex is not a Windows reboot.
        assert_eq!(
            restored.pending_action(&installed, 900, false).unwrap(),
            PendingAction::Observe
        );
        installed.boot_id = "boot-two".into();
        installed.running = true;
        assert_eq!(
            restored.pending_action(&installed, 1000, false).unwrap(),
            PendingAction::Observe
        );
        assert_eq!(restored.phase, "resume_waiting");
        installed.running = false;
        assert_eq!(
            restored.pending_action(&installed, 1100, false).unwrap(),
            PendingAction::Finish
        );
        restored.set_enabled(false);
        assert_eq!(
            restored.pending_action(&installed, 1200, false).unwrap(),
            PendingAction::Observe
        );
        assert!(!restored.resume_pending);
    }
    #[test]
    fn windows_completion_cancels_armed_install_and_crash_does_not_replay() {
        let mut state = Status {
            phase: "installing".into(),
            pending_version: "26.1007.9446.0".into(),
            resume_pending: true,
            ..Status::default()
        };
        state.recover();
        assert_eq!(state.phase, "failed");
        assert!(!state.resume_pending);
        assert!(!state.should_check(1_000_000, true));
        state.resume_pending = true;
        let installed = Package {
            version: "26.1007.9446.0".into(),
            healthy: true,
            running: true,
            ..Package::default()
        };
        assert_eq!(
            state.pending_action(&installed, 100, false).unwrap(),
            PendingAction::Completed
        );
        assert!(!state.resume_pending);
        assert!(state.pending_version.is_empty());
    }
    #[test]
    fn finish_cannot_bypass_maintenance_or_unknown_reboot_time() {
        let mut state = Status {
            pending_version: "2.37337.1".into(),
            ..Status::default()
        };
        let mut installed = Package {
            version: "2.37337.1.0".into(),
            healthy: false,
            package_status: "Servicing".into(),
            ..Package::default()
        };
        assert!(state
            .pending_action(&installed, 100, true)
            .unwrap_err()
            .contains("Servicing"));
        assert_eq!(state.last_updated, 0);
        state.resume_pending = false;
        installed.reboot_required = true;
        assert!(state
            .pending_action(&installed, 100, true)
            .unwrap_err()
            .contains("启动时间"));
        assert!(!state.resume_pending);
    }
    #[test]
    fn deferred_update_survives_restart_and_disabled_schedule() {
        let mut state = Status {
            enabled: true,
            phase: "deferred".into(),
            pending_version: "2.37337.1".into(),
            last_check: 100,
            ..Status::default()
        };
        state.set_enabled(false);
        let mut restored: Status =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        restored.recover();
        assert!(!restored.enabled);
        assert!(
            restored.should_check(200, false),
            "Pending observation is read-only"
        );
        assert!(!restored.observe_pending("2.31226.0.0", true, 200).unwrap());
        assert_eq!(restored.phase, "deferred");
        assert_eq!(
            restored.last_updated, 0,
            "Acceptance is not completed registration"
        );
        assert_eq!(restored.pending_version, "2.37337.1");
        assert!(
            !restored.observe_pending("2.37337.1.0", false, 250).unwrap(),
            "Matching version while Windows is servicing is not complete"
        );
        assert_eq!(restored.last_updated, 0);
        assert!(restored.observe_pending("2.37337.1.0", true, 300).unwrap());
        assert_eq!(restored.phase, "updated");
        assert_eq!(restored.last_updated, 300);
        assert!(restored.pending_version.is_empty());
        assert!(!restored.should_check(400, true));
    }
    #[test]
    fn pending_inspection_failure_does_not_lose_windows_deployment() {
        let mut state = Status {
            enabled: true,
            phase: "failed".into(),
            pending_version: "26.1007.9446.0".into(),
            ..Status::default()
        };
        state.recover();
        assert!(!state.should_check(1_000_000, true));
        assert!(!state.observe_pending("26.928.1915.0", true, 100).unwrap());
        assert_eq!(state.pending_version, "26.1007.9446.0");
        assert!(state.observe_pending("26.1008.1.0", true, 200).unwrap());
    }
    #[test]
    fn interrupted_install_is_not_automatically_resubmitted() {
        for previous_failure in ["", "checking", "downloading"] {
            let mut state = Status {
                enabled: true,
                phase: "installing".into(),
                failure_stage: previous_failure.into(),
                ..Status::default()
            };
            state.recover();
            assert_eq!(state.phase, "failed");
            assert_eq!(state.failure_stage, "installing");
            assert!(!state.should_check(1_000_000, true));
        }
        let old: Status = serde_json::from_str(r#"{"enabled":true,"phase":"waiting"}"#).unwrap();
        assert!(old.pending_version.is_empty());
        assert!(old.should_check(1_000_000, true));
    }
    #[test]
    fn registration_failure_reports_failure_and_stays_stopped_after_restart() {
        let mut state = Status {
            enabled: true,
            phase: "failed".into(),
            error: "Deployment 0x80073CF9 inner HRESULT 0x80070643".into(),
            ..Status::default()
        };
        state.recover();
        assert!(state.error.contains("重启 Windows"));
        assert!(!state.should_check(1_000_000, true));
        assert_eq!(state.last_updated, 0);
        assert!(!registration_error("signature invalid"));
        assert!(!registration_error("0x80073CF9, insufficient disk space"));
    }
    #[test]
    fn versions_are_numeric_and_strict() {
        assert!(version("2.37337.1").unwrap() > version("2.31226.0.0").unwrap());
        assert!(version("26.1007.9446.0").unwrap() > version("26.928.1915.0").unwrap());
        assert_eq!(
            version("2.37337.1").unwrap(),
            version("2.37337.1.0").unwrap()
        );
        for value in ["../x", "2.3", "2.a.1", "2.3.4;exit", "2.3.4.5.6"] {
            assert!(version(value).is_err());
        }
    }
    #[test]
    fn download_identity_is_pinned() {
        let good = "https://downloads.claude.ai/releases/win32/x64/2.37337.1/Claude-ba51ab579cc4029765083ec9f9f0bd23d37a32ee.msix";
        assert_eq!(release_version(good, "x64").unwrap(), "2.37337.1");
        for bad in [
            good.replace("https:", "http:"),
            good.replace("downloads.claude.ai", "downloads.claude.ai.evil"),
            format!("{good}?redirect=evil"),
            good.replace(".msix", ".exe"),
        ] {
            assert!(release_version(&bad, "x64").is_err());
        }
        assert!(release_version(good, "arm64").is_err());
    }
    #[test]
    fn deployment_has_no_destructive_fallback() {
        let script = include_str!("claude_package.ps1");
        for forbidden in [
            "Remove-AppxPackage",
            "Reset-AppxPackage",
            "Stop-Process",
            "-ForceApplicationShutdown",
            "-ForceTargetApplicationShutdown",
            "-ForceUpdateFromAnyVersion",
            "ClaudeSetup.exe",
        ] {
            assert!(!script.contains(forbidden));
        }
        assert!(script.contains("-DeferRegistrationWhenPackagesAreInUse -RetainFilesOnFailure"));
    }
}
