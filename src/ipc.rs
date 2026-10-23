//! 前端 IPC 命令：UI 与后端之间唯一的调用面。
//!
//! 命名与参数以 `docs/SPEC-v3.md` §7 为准；Tauri 2 会把 JS 的 camelCase 参数映射到 Rust 的 snake_case。

use crate::model::{Target, UpdState};
use crate::monitor::{self, DryResult};
use crate::state::{AppState, StateView};
use std::sync::Arc;
#[cfg(target_os = "macos")]
use tauri::Manager;
use tauri::State;

/// 打开数据目录（资源管理器）。
fn open_folder() {
    let dir = crate::config::config_dir();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("/usr/bin/open").arg(dir).spawn();
    #[cfg(not(target_os = "macos"))]
    let _ = std::process::Command::new("explorer.exe").arg(dir).spawn();
}

#[cfg(not(target_os = "macos"))]
fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("/usr/bin/open").arg(url).spawn();
    #[cfg(not(target_os = "macos"))]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
}

// ---------- 状态 / 配置 ----------

#[tauri::command]
pub fn get_state(state: State<'_, Arc<AppState>>) -> StateView {
    state.state_view()
}

#[tauri::command]
pub fn get_config(state: State<'_, Arc<AppState>>) -> crate::config::Config {
    state.config()
}

#[tauri::command]
pub fn update_settings(
    state: State<'_, Arc<AppState>>,
    patch: serde_json::Value,
) -> Result<StateView, String> {
    // apply_patch 先把改动原子落盘，失败时直接返回错误——内存配置保持原样。
    let next = match state.config().apply_patch(&patch) {
        Ok(next) => next,
        Err(err) => {
            state.set_error(err.clone());
            return Err(err);
        }
    };
    state.clear_error();
    state.set_config(next);
    state.reset_statuses_from_config();
    state.emit_state();
    Ok(state.state_view())
}

#[tauri::command]
pub fn save_targets(
    state: State<'_, Arc<AppState>>,
    targets: Vec<Target>,
) -> Result<StateView, String> {
    let targets = crate::targets::validate(targets)?;
    let mut cfg = state.config();
    cfg.targets = targets;
    if let Err(err) = cfg.save() {
        state.set_error(err.clone());
        return Err(err);
    }
    state.clear_error();
    state.set_config(cfg);
    state.reset_statuses_from_config();
    state.log("监控目标已保存");
    state.emit_state();
    Ok(state.state_view())
}

#[tauri::command]
pub fn reset_targets(state: State<'_, Arc<AppState>>) -> Result<StateView, String> {
    let mut cfg = state.config();
    let (ips, regions) = cfg
        .target("claude")
        .map(|t| (t.expect_ips.clone(), t.expect_regions.clone()))
        .unwrap_or_default();
    cfg.targets = crate::targets::default_targets(&ips, &regions);
    if let Err(err) = cfg.save() {
        state.set_error(err.clone());
        return Err(err);
    }
    state.clear_error();
    state.set_config(cfg);
    state.reset_statuses_from_config();
    state.log("监控目标已恢复默认锚点（白名单保留）");
    state.emit_state();
    Ok(state.state_view())
}

// ---------- 检查 / 熔断 ----------

#[tauri::command]
pub fn recheck(state: State<'_, Arc<AppState>>) {
    monitor::recheck(state.inner());
}

/// v3.10 R06：停止保护（只检测、不动作）。用于"我知道有风险，先别动我的进程"。
#[tauri::command]
pub fn disarm(state: State<'_, Arc<AppState>>, reason: Option<String>) -> Result<(), String> {
    let reason = reason.unwrap_or_else(|| "用户手动停止保护".to_string());
    state.inner().disarm(&reason)
}

/// v3.10 R06：重新布防，恢复守护动作。
#[tauri::command]
pub fn rearm(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    state.inner().rearm()
}

#[tauri::command]
pub fn launch(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    monitor::launch(state.inner())
}

#[tauri::command]
pub fn recheck_target(state: State<'_, Arc<AppState>>, id: String) -> Result<DryResult, String> {
    let cfg = state.config();
    let target = cfg
        .target(&id)
        .cloned()
        .ok_or_else(|| "目标不存在".to_string())?;
    let (route, access) = crate::access::resolve(&cfg);
    let enforced = cfg!(target_os = "windows") && cfg.enforce_access_path;
    if enforced && !access.is_known() {
        let reason = if access.is_uncovered() {
            "未接入代理链路，已跳过探测".to_string()
        } else {
            format!("接入路径无法确认，已跳过探测：{}", access.note)
        };
        return Ok(crate::monitor::dry_skipped_with(&target, &reason));
    }
    let proxy = match route {
        crate::access::ProbeRoute::Proxy(url) => Some(url),
        _ => None,
    };
    let probe = crate::anchors::probe(proxy.as_deref(), &target);
    let eval = crate::policy::evaluate(&target, &probe);
    Ok(DryResult {
        id: target.id.clone(),
        name: target.name.clone(),
        pass: eval.verdict == crate::model::Verdict::Pass,
        verdict: eval.verdict,
        reason: eval.reason,
        ip: probe.ip,
        country: probe.country,
        latency_ms: probe.latency_ms,
    })
}

#[tauri::command]
pub fn release(state: State<'_, Arc<AppState>>) {
    monitor::release(state.inner());
}

#[tauri::command]
pub fn pause(state: State<'_, Arc<AppState>>) {
    monitor::pause(state.inner(), monitor::PAUSE_MINUTES);
}

#[tauri::command]
pub fn resume(state: State<'_, Arc<AppState>>) {
    monitor::resume(state.inner());
}

/// v3.9 一键防火墙兜底封锁：on=立即封锁守护对象出站，off=立即解除。
/// 自动逻辑（未接入时维持）在下一轮检查继续接管。
#[tauri::command]
pub fn lockdown(state: State<'_, Arc<AppState>>, on: bool) -> bool {
    let cfg = state.config();
    state.lockdown_now(on, &cfg);
    state.emit_state();
    on
}

/// 一键扫描并结束全部 Claude 进程（桌面端 + Claude Code CLI）。
#[tauri::command]
pub fn sweep_claude(state: State<'_, Arc<AppState>>) -> crate::guard::SweepReport {
    let report = crate::guard::sweep_claude(crate::guard::SweepMode::Manual);
    if report.killed > 0 {
        state.log(format!(
            "一键清理：结束 {} 个 Claude 进程（桌面 {} / CLI {}）",
            report.killed, report.desktop_killed, report.cli_killed
        ));
    } else {
        state.log("一键清理：未发现 Claude 进程");
    }
    state.emit_state();
    report
}

// ---------- 日志 / 数据 ----------

#[tauri::command]
pub fn recent_logs(state: State<'_, Arc<AppState>>, limit: Option<usize>) -> Vec<String> {
    state.recent_logs(limit.unwrap_or(200))
}

#[tauri::command]
pub fn open_data_folder() {
    open_folder();
}

#[tauri::command]
pub fn open_guide(app: tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    {
        if let Some(window) = app.get_webview_window("macos-guide") {
            let _ = window.show();
            let _ = window.set_focus();
        } else if let Err(error) = tauri::WebviewWindowBuilder::new(
            &app,
            "macos-guide",
            tauri::WebviewUrl::App("macos-guide.html".into()),
        )
        .title("ClaudeGuard macOS 使用说明")
        .inner_size(700.0, 620.0)
        .theme(Some(tauri::Theme::Dark))
        .build()
        {
            crate::guard::log_line(&format!("打开使用说明失败：{error}"));
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        open_url("https://github.com/daha1216/ClaudeGuard/blob/master/docs/GUIDE.md");
    }
}

#[tauri::command]
pub fn js_log(state: State<'_, Arc<AppState>>, level: String, msg: String) {
    state.log(format!("ui[{level}] {msg}"));
}

// ---------- 安装 / 自启 ----------

#[tauri::command]
pub fn install_app() -> Result<String, String> {
    crate::install::install().map(|path| path.display().to_string())
}

#[tauri::command]
pub fn set_autostart(state: State<'_, Arc<AppState>>, on: bool) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    let ok = {
        crate::macos::autostart::set_enabled(on)?;
        true
    };
    #[cfg(not(target_os = "macos"))]
    let ok = crate::install::set_autostart(on);
    if ok {
        let mut cfg = state.config();
        cfg.auto_start_with_system = on;
        if let Err(err) = cfg.save() {
            state.set_error(err.clone());
            return Err(err);
        }
        state.clear_error();
        state.set_config(cfg);
        state.emit_state();
    }
    Ok(ok)
}

// ---------- 自身更新 ----------

#[tauri::command]
pub fn upd_state(state: State<'_, Arc<AppState>>) -> UpdState {
    state.upd()
}

#[tauri::command]
pub fn upd_check(state: State<'_, Arc<AppState>>) {
    crate::update::spawn_check(state.inner());
}

#[tauri::command]
pub fn upd_download(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    match state.upd() {
        UpdState::Available { url, size, .. } => {
            crate::update::spawn_download(state.inner(), url, size);
            Ok(())
        }
        _ => Err("当前没有可下载的更新".into()),
    }
}

// ---------- 飞书 ----------

#[tauri::command]
pub fn feishu_status(state: State<'_, Arc<AppState>>) -> crate::feishu::Status {
    state.feishu.status()
}

#[tauri::command]
pub fn feishu_save(
    state: State<'_, Arc<AppState>>,
    cfg_json: String,
) -> Result<crate::feishu::Status, String> {
    let settings: crate::feishu::Settings =
        serde_json::from_str(&cfg_json).map_err(|err| format!("飞书设置无效：{err}"))?;
    state.feishu.configure(settings)
}

#[tauri::command]
pub fn feishu_test(state: State<'_, Arc<AppState>>) -> Result<crate::feishu::Status, String> {
    state.feishu.test()
}

#[tauri::command]
pub fn feishu_retry_failed(
    state: State<'_, Arc<AppState>>,
) -> Result<crate::feishu::Status, String> {
    state.feishu.retry_failed()
}

// ---------- 客户端更新 ----------

#[tauri::command]
pub fn claude_update_status(state: State<'_, Arc<AppState>>) -> crate::claude_update::Status {
    state.claude_update.status()
}

#[tauri::command]
pub fn claude_update_configure(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
) -> Result<(), String> {
    state.claude_update.configure(enabled).map(|_| ())
}

#[tauri::command]
pub fn claude_update_check(
    state: State<'_, Arc<AppState>>,
    finish: Option<bool>,
) -> Result<(), String> {
    crate::claude_update::Updater::request(
        state.inner(),
        crate::claude_update::Product::Claude,
        finish.unwrap_or(false),
    )
}

#[tauri::command]
pub fn codex_update_status(state: State<'_, Arc<AppState>>) -> crate::claude_update::Status {
    state.codex_update.status()
}

#[tauri::command]
pub fn codex_update_configure(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
) -> Result<(), String> {
    state.codex_update.configure(enabled).map(|_| ())
}

#[tauri::command]
pub fn codex_update_check(
    state: State<'_, Arc<AppState>>,
    finish: Option<bool>,
) -> Result<(), String> {
    crate::claude_update::Updater::request(
        state.inner(),
        crate::claude_update::Product::Codex,
        finish.unwrap_or(false),
    )
}

// ---------- 通知 ----------

#[tauri::command]
pub async fn notify_test(kind: Option<String>) -> Result<(), String> {
    let kind = kind.unwrap_or_else(|| "trip".to_string());
    // 发一条 Toast 要起 powershell，最多阻塞十几秒；扔到阻塞线程池，别冻界面。
    tauri::async_runtime::spawn_blocking(move || {
        let (title, body) = crate::notify::test_message(&kind);
        #[cfg(target_os = "macos")]
        {
            crate::notify::test_blocking(title, &body)
        }
        #[cfg(not(target_os = "macos"))]
        {
            crate::notify::send_blocking(title, &body)
        }
    })
    .await
    .map_err(|e| format!("测试通知执行失败：{e}"))?
}
