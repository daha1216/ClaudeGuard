//! GitHub Releases 更新检查与自替换。
//!
//! 更新源: https://github.com/daha1216/ClaudeGuard (公开仓, 匿名 API)。
//! 网络路径: 优先走用户配置的本地代理(国内直连 GitHub 不稳), 失败回退直连。

use crate::config::Config;
use crate::model::UpdState;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "macos")]
#[path = "macos/self_update.rs"]
mod self_update;

pub const GITHUB_REPO: &str = "daha1216/ClaudeGuard";
const USER_AGENT: &str = "ClaudeGuard-Updater";

/// 检查超时
const T_CHECK: Duration = Duration::from_secs(10);
/// 下载超时(整体)
#[cfg(windows)]
const T_DOWNLOAD: Duration = Duration::from_secs(300);

// ------------------------------------------------------------------ 数据结构

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Release {
    pub tag_name: String,
    /// 更新说明用（暂未在 UI 展示，保留给后续版本）
    #[allow(dead_code)]
    pub name: Option<String>,
    /// 更新说明(markdown 源码)
    #[allow(dead_code)]
    pub body: Option<String>,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
}

impl Release {
    // Mac updates require a pinned key and a full signed-manifest asset set.
    // A Windows EXE can never satisfy this selector.
    #[cfg(target_os = "macos")]
    pub fn exe_asset(&self) -> Option<&Asset> {
        self_update::asset(self)
    }

    /// 语义化版本号(去掉 v 前缀)
    pub fn version(&self) -> &str {
        self.tag_name.trim_start_matches('v')
    }

    /// 找主程序资产: 名字含 ClaudeGuard 且以 .exe 结尾, 但排除 Inno 安装包(-setup)——
    /// 自更新下载的必须是裸版 exe, 拿到安装包会把它当主程序写盘。
    #[cfg(windows)]
    pub fn exe_asset(&self) -> Option<&Asset> {
        self.assets.iter().find(|a| {
            a.name.ends_with(".exe") && a.name.contains("ClaudeGuard") && !a.name.contains("-setup")
        })
    }
}

// ------------------------------------------------------------------ 版本比较

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// remote 是否比 current 新。宽容解析: "v1.3.0"/"1.3.0"/"1.3.0-beta" 均可,
/// 非数字段按 0 处理。
pub fn is_newer(remote: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches('v')
            .split('-')
            .next()
            .unwrap_or("")
            .split('.')
            .map(|p| p.trim().parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (r, c) = (parse(remote), parse(current));
    for i in 0..r.len().max(c.len()) {
        let a = r.get(i).copied().unwrap_or(0);
        let b = c.get(i).copied().unwrap_or(0);
        if a != b {
            return a > b;
        }
    }
    false
}

// ------------------------------------------------------------------ 网络构建

/// 统一按外发策略取 Agent（R14 / D5）。代理不可用时不回退直连。
fn agent(cfg: &Config) -> ureq::Agent {
    crate::netpol::agent(cfg, T_CHECK)
}

// ------------------------------------------------------------------ 检查更新

/// 查询最新 release。代理优先, 失败回退直连。
pub fn check_latest(cfg: &Config) -> Result<Release, String> {
    let api = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let fetch = |agent: &ureq::Agent| -> Result<Release, String> {
        let resp = agent
            .get(&api)
            .set("User-Agent", USER_AGENT)
            .set("Accept", "application/vnd.github+json")
            .timeout(T_CHECK)
            .call()
            .map_err(|e| format!("GitHub API: {e}"))?;
        let text = resp.into_string().map_err(|e| format!("读取响应: {e}"))?;
        serde_json::from_str::<Release>(&text).map_err(|e| format!("解析 release: {e}"))
    };

    // R14 / D5：代理不可用就如实失败。旧实现会在这里静默直连，
    // 结果是把家宽 IP 直接送到 GitHub——这正是要禁止的泄漏。
    fetch(&agent(cfg)).map_err(|e| {
        if crate::netpol::route(cfg) == crate::netpol::Route::Direct {
            e
        } else {
            crate::netpol::proxy_required_error(&e)
        }
    })
}

// ------------------------------------------------------------------ 下载

/// 下载到临时文件, 返回路径。progress(已下载字节, 总字节)。
#[cfg(windows)]
pub fn download(
    cfg: &Config,
    url: &str,
    expected_size: u64,
    mut progress: impl FnMut(u64, u64),
) -> Result<PathBuf, String> {
    let tmp = std::env::temp_dir().join("ClaudeGuard-update.exe");

    let do_download =
        |agent: &ureq::Agent, progress: &mut dyn FnMut(u64, u64)| -> Result<(), String> {
            let resp = agent
                .get(url)
                .set("User-Agent", USER_AGENT)
                .timeout(T_DOWNLOAD)
                .call()
                .map_err(|e| format!("下载失败: {e}"))?;
            let mut reader = resp.into_reader();
            let mut buf = Vec::with_capacity(expected_size as usize + 4096);
            let mut chunk = [0u8; 65536];
            loop {
                let n = reader.read(&mut chunk).map_err(|e| format!("读取: {e}"))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                progress(buf.len() as u64, expected_size);
            }
            if expected_size > 0 && buf.len() as u64 != expected_size {
                return Err(format!(
                    "大小不符: 期望 {expected_size}, 实得 {}",
                    buf.len()
                ));
            }
            std::fs::write(&tmp, &buf).map_err(|e| format!("写临时文件: {e}"))?;
            Ok(())
        };

    let prog = &mut progress;
    do_download(&agent(cfg), prog).map_err(|e| {
        if crate::netpol::route(cfg) == crate::netpol::Route::Direct {
            e
        } else {
            crate::netpol::proxy_required_error(&e)
        }
    })?;
    Ok(tmp)
}

// ------------------------------------------------------------------ 自替换

/// 用新 exe 替换当前进程的 exe 并重启。
///
/// 流程: 当前 exe 改名为 .old → 新文件复制到原路径(失败则回滚) → 启动新实例。
/// 安装版以管理员运行, 重命名/复制/启动均无权限问题; 便携版在可写目录同样适用。
/// `spawn_new=false` 供自测使用: 只做替换不启动。
#[cfg(windows)]
pub fn apply_update(new_exe: &Path, spawn_new: bool) -> Result<(), String> {
    let cur = std::env::current_exe().map_err(|e| format!("定位自身: {e}"))?;
    let old = cur.with_extension("exe.old");

    // 清理上次残留
    let _ = std::fs::remove_file(&old);

    std::fs::rename(&cur, &old).map_err(|e| format!("重命名旧版本: {e}"))?;

    if let Err(e) = std::fs::copy(new_exe, &cur) {
        // 回滚: 把 .old 改回原名, 让程序继续可用
        let _ = std::fs::rename(&old, &cur);
        return Err(format!("复制新版本: {e}"));
    }

    if !spawn_new {
        return Ok(());
    }

    // 启动新实例(分离)。提权进程下直接 CreateProcess 即可;
    // 未提权进程遇到带管理员清单的 exe 会得到 ERROR_ELEVATION_REQUIRED,
    // 此时经 explorer(ShellExecute 语义)触发 UAC 弹窗启动。
    if std::process::Command::new(&cur).spawn().is_err() {
        let expl = std::env::var("SystemRoot")
            .map(|r| format!(r"{r}\explorer.exe"))
            .unwrap_or_else(|_| "explorer.exe".to_string());
        std::process::Command::new(expl)
            .arg(&cur)
            .spawn()
            .map_err(|e| format!("启动新版本: {e}"))?;
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn apply_update(new_exe: &Path, spawn_new: bool) -> Result<(), String> {
    self_update::apply_update(new_exe, spawn_new)
}

#[cfg(target_os = "macos")]
pub fn download(
    cfg: &Config,
    url: &str,
    size: u64,
    progress: impl FnMut(u64, u64),
) -> Result<PathBuf, String> {
    self_update::download(cfg, url, size, progress)
}

/// 启动时清理上次更新残留的 .old 文件。
pub fn cleanup_old() {
    #[cfg(target_os = "macos")]
    if let Err(error) = self_update::recover_current() {
        eprintln!("macOS 自更新恢复未完成：{error}");
    }
    #[cfg(windows)]
    if let Ok(cur) = std::env::current_exe() {
        let old = cur.with_extension("exe.old");
        let _ = std::fs::remove_file(&old);
    }
}

// ------------------------------------------------------------------ 后台编排

/// 后台检查 GitHub 最新版本，结果写入 `AppState::upd` 并推给 UI。
pub fn spawn_check(state: &Arc<AppState>) {
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        state.set_upd(UpdState::Checking);
        state.emit_state();
        state.log("检查更新…");
        match check_latest(&state.config()) {
            Ok(release) => {
                let ver = release.version().to_string();
                if !is_newer(&ver, current_version()) {
                    state.set_upd(UpdState::UpToDate);
                    state.log(format!("已是最新版本 v{ver}"));
                } else if let Some(asset) = release.exe_asset() {
                    state.set_upd(UpdState::Available {
                        ver: ver.clone(),
                        url: asset.browser_download_url.clone(),
                        size: asset.size,
                    });
                    state.log(format!("发现新版本 v{ver}"));
                } else {
                    state.set_upd(UpdState::Failed {
                        msg: missing_asset_message(&ver),
                    });
                    state.log("发现新版本，但发布页缺少可下载的主程序");
                }
            }
            Err(err) => {
                state.set_upd(UpdState::Failed { msg: err.clone() });
                state.log(format!("检查更新失败：{err}"));
            }
        }
        state.emit_state();
    });
}

// ------------------------------------------------------------------ 静默周期检查

/// 已提醒过的版本号落在 %APPDATA%\ClaudeGuard\upd-notify.json，
/// 同一个新版本跨重启只弹一次桌面通知。
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct UpdNotify {
    #[serde(default)]
    ver: String,
}

fn upd_notify_path() -> PathBuf {
    crate::config::config_dir().join("upd-notify.json")
}

fn notified_ver() -> String {
    std::fs::read_to_string(upd_notify_path())
        .ok()
        .and_then(|text| serde_json::from_str::<UpdNotify>(&text).ok())
        .map(|n| n.ver)
        .unwrap_or_default()
}

fn mark_notified(ver: &str) {
    let path = upd_notify_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(json) = serde_json::to_string(&UpdNotify {
        ver: ver.to_string(),
    }) {
        let _ = std::fs::write(&path, json);
    }
}

/// 发现新版本时弹一次桌面通知；`upd-notify.json` 里记过的版本不再提醒。
/// 分类开关关闭时不标记（用户之后打开开关仍能收到这一次提醒）；
/// 真正尝试过发送就标记，避免持续失败时每 6 小时重复打扰。
fn notify_new_version(state: &Arc<AppState>, ver: &str) {
    if notified_ver() == ver {
        return;
    }
    let prefs = state.config().notify;
    if !crate::notify::send(
        &prefs,
        "self_update",
        "ClaudeGuard 有新版本",
        &format!("v{ver} 已发布，打开 设置 → 更新 一键升级。"),
    ) {
        return;
    }
    state.log(format!("已发送新版本桌面通知（v{ver}）"));
    mark_notified(ver);
}

/// 可被 stop 打断的休眠；返回 false 表示应当退出线程。
fn sleep_stop(state: &Arc<AppState>, mut ms: u64) -> bool {
    while ms > 0 {
        if state.stop.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        let chunk = ms.min(1_000);
        std::thread::sleep(Duration::from_millis(chunk));
        ms -= chunk;
    }
    !state.stop.load(std::sync::atomic::Ordering::Relaxed)
}

/// 测试/调试用的延时覆盖：`CG_UPD_FIRST_DELAY_MS` / `CG_UPD_INTERVAL_MS`。
fn env_ms(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v >= 100)
        .unwrap_or(default)
}

/// 后台静默检查自身更新：启动 90 秒后首查，此后每 6 小时一轮。
///
/// 与手动「检查更新」共用 `check_latest`，但静默模式不打 `Checking` 状态、
/// 失败不写 `Failed`（只记日志，下一轮重试），避免界面无端闪烁。
/// 发现新版本时写入 `Available` 状态并弹一次桌面通知（同版本跨重启只提醒一次）。
pub fn spawn_periodic_check(state: &Arc<AppState>) {
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        let first_ms = env_ms("CG_UPD_FIRST_DELAY_MS", 90_000);
        let interval_ms = env_ms("CG_UPD_INTERVAL_MS", 6 * 3_600_000);
        let mut first = true;
        loop {
            let wait = if first { first_ms } else { interval_ms };
            if !sleep_stop(&state, wait) {
                return;
            }
            first = false;
            if !state.config().auto_upd_check {
                continue;
            }
            match check_latest(&state.config()) {
                Ok(release) => {
                    let ver = release.version().to_string();
                    if !is_newer(&ver, current_version()) {
                        state.set_upd(UpdState::UpToDate);
                        state.log(format!("静默检查：已是最新版本 v{ver}"));
                        state.emit_state();
                    } else if let Some(asset) = release.exe_asset() {
                        state.set_upd(UpdState::Available {
                            ver: ver.clone(),
                            url: asset.browser_download_url.clone(),
                            size: asset.size,
                        });
                        state.log(format!("发现新版本 v{ver}"));
                        state.emit_state();
                        notify_new_version(&state, &ver);
                    }
                    // 有新版本但发布页没有裸 exe 资产：静默跳过，手动检查会给出原因
                }
                Err(err) => {
                    state.log(format!("静默检查更新失败（下一轮重试）：{err}"));
                }
            }
        }
    });
}

/// 后台下载并自替换重启；下载进度写入 `AppState::upd`。
#[cfg(target_os = "macos")]
static MACOS_DOWNLOAD_BUSY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "macos")]
struct MacDownloadGuard;
#[cfg(target_os = "macos")]
impl Drop for MacDownloadGuard {
    fn drop(&mut self) {
        MACOS_DOWNLOAD_BUSY.store(false, std::sync::atomic::Ordering::Release);
    }
}
pub fn spawn_download(state: &Arc<AppState>, url: String, size: u64) {
    #[cfg(target_os = "macos")]
    if MACOS_DOWNLOAD_BUSY
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::Acquire,
            std::sync::atomic::Ordering::Relaxed,
        )
        .is_err()
    {
        state.log("自身更新正在执行；忽略重复请求");
        return;
    }
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        #[cfg(target_os = "macos")]
        let _download_guard = MacDownloadGuard;
        state.set_upd(UpdState::Downloading {
            done: 0,
            total: size,
        });
        state.emit_state();
        state.log(format!(
            "开始下载更新（{:.1} MB）…",
            size as f64 / 1_048_576.0
        ));
        // emit_state 会重扫进程，进度按 5% 节流而不是每个 64KB 块都推一次。
        let progress_state = Arc::clone(&state);
        let mut last_percent = 0u64;
        let result = download(&state.config(), &url, size, move |done, total| {
            progress_state.set_upd(UpdState::Downloading { done, total });
            let percent = done.saturating_mul(100).checked_div(total).unwrap_or(0);
            if percent >= last_percent + 5 || done == total {
                last_percent = percent;
                progress_state.emit_state();
            }
        });
        match result {
            Ok(path) => {
                state.set_upd(UpdState::Restarting);
                state.emit_state();
                state.log("更新已下载，正在替换并重启…");
                match apply_update(&path, true) {
                    Ok(()) => {
                        #[cfg(windows)]
                        std::process::exit(0);
                        #[cfg(target_os = "macos")]
                        {
                            state.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                            crate::netcut::restore();
                            crate::guard::firewall_release();
                            state.app.exit(0);
                        }
                    }
                    Err(err) => {
                        state.set_upd(UpdState::Failed { msg: err.clone() });
                        state.log(format!("更新失败：{err}"));
                        state.emit_state();
                    }
                }
            }
            Err(err) => {
                state.set_upd(UpdState::Failed { msg: err.clone() });
                state.log(format!("更新下载失败：{err}"));
                state.emit_state();
            }
        }
    });
}

fn missing_asset_message(ver: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        format!("发现新版本 v{ver}；{}", self_update::unavailable_reason())
    }
    #[cfg(windows)]
    {
        format!("发现新版本 v{ver}，但发布页没有可下载的主程序")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upd_notify_roundtrip() {
        let n = UpdNotify {
            ver: "3.5.0".into(),
        };
        let json = serde_json::to_string(&n).unwrap();
        assert_eq!(
            serde_json::from_str::<UpdNotify>(&json).unwrap().ver,
            "3.5.0"
        );
        // 旧/空文件: 缺字段回退空串, 不 panic
        assert_eq!(
            serde_json::from_str::<UpdNotify>("{}").unwrap().ver,
            String::new()
        );
        // 同版本不再提醒; 新版本要提醒
        assert!(!should_notify("3.5.0", "3.5.0"));
        assert!(should_notify("", "3.5.0"));
        assert!(should_notify("3.4.0", "3.5.0"));
    }

    /// 纯逻辑: 已提醒版本与最新版本比较决定是否再次提醒。
    fn should_notify(stored: &str, ver: &str) -> bool {
        stored != ver
    }

    #[test]
    fn version_compare() {
        assert!(is_newer("v1.3.0", "1.2.1"));
        assert!(is_newer("1.2.10", "1.2.9")); // 按数字段比较, 非字典序
        assert!(is_newer("v2.0", "1.9.9")); //   短版本缺省 0
        assert!(!is_newer("v1.2.1", "1.2.1"));
        assert!(!is_newer("v1.2.0", "1.2.1"));
        assert!(!is_newer("v1.2.1-beta", "1.2.1")); // 同号预发布不提示
    }

    /// 行为锁: release 资产匹配规则——名字含 ClaudeGuard 且以 .exe 结尾。
    /// 资产命名偏离此规则时, 所有用户端的检查更新都会失败。
    #[test]
    #[cfg(windows)]
    fn exe_asset_matching() {
        let mk = |names: &[&str]| Release {
            tag_name: "v9.9.9".into(),
            name: None,
            body: None,
            assets: names
                .iter()
                .map(|n| Asset {
                    name: (*n).into(),
                    size: 1,
                    browser_download_url: String::new(),
                })
                .collect(),
        };
        // 规范命名: 命中
        let r = mk(&["ClaudeGuard-v9.9.9.exe"]);
        assert_eq!(r.exe_asset().unwrap().name, "ClaudeGuard-v9.9.9.exe");
        // 小写连写不含 "ClaudeGuard": 不命中
        let r = mk(&["claude-guard.exe"]);
        assert!(r.exe_asset().is_none());
        // zip / 源码包: 不命中
        let r = mk(&["ClaudeGuard-v9.9.9.zip", "source.zip"]);
        assert!(r.exe_asset().is_none());
        // 多资产时仍取第一个命中 exe
        let r = mk(&[
            "checksums.txt",
            "ClaudeGuard-v9.9.9.zip",
            "ClaudeGuard-v9.9.9.exe",
        ]);
        assert_eq!(r.exe_asset().unwrap().name, "ClaudeGuard-v9.9.9.exe");
        // Inno 安装包(-setup.exe)混在资产里: 必须跳过, 只认裸版
        let r = mk(&["ClaudeGuard-v9.9.9-setup.exe", "ClaudeGuard-v9.9.9.exe"]);
        assert_eq!(r.exe_asset().unwrap().name, "ClaudeGuard-v9.9.9.exe");
        // 只有安装包: 宁可不更新也不能拿它替换主程序
        let r = mk(&["ClaudeGuard-v9.9.9-setup.exe"]);
        assert!(r.exe_asset().is_none());
    }
}
