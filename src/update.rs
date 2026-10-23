//! GitHub Releases 更新检查与自替换。
//!
//! 更新源: https://github.com/daha1216/ClaudeGuard (公开仓, 匿名 API)。
//! 网络路径: 优先走用户配置的本地代理(国内直连 GitHub 不稳), 失败回退直连。

use crate::config::Config;
use crate::model::UpdState;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::io::{Read, Write};
use std::path::PathBuf;
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
    /// GitHub 为每个资产提供的 `sha256:<hex>` 摘要；旧版本 API 可能没有。
    #[serde(default)]
    pub digest: Option<String>,
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

/// 更新包硬上限：正常安装包 4–8 MB，留足余量后仍能挡住被塞进来的大文件。
const MAX_ARTIFACT: u64 = 128 * 1024 * 1024;

/// 统一按外发策略取 Agent（R14 / D5）。代理不可用时不回退直连。
fn agent(cfg: &Config) -> Result<ureq::Agent, String> {
    crate::netpol::agent(cfg, T_CHECK)
}

// ------------------------------------------------------------------ 检查更新

/// 查询最新 release。代理不可用即失败，不回退直连。
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
    let agent = agent(cfg)?;
    fetch(&agent).map_err(|e| {
        if crate::netpol::route(cfg) == crate::netpol::Route::Direct {
            e
        } else {
            crate::netpol::proxy_required_error(&e)
        }
    })
}

// ------------------------------------------------------------------ 下载

/// 下载到临时文件, 返回路径。progress(已下载字节, 总字节)。
/// 下载到受控暂存目录，返回**仍打开的句柄**。
///
/// 计划 5.5 要求：管理员专用目录、随机名字、独占创建、句柄贯穿验证与复制。
/// 用临时目录里的固定文件名（旧实现 `%TEMP%\ClaudeGuard-update.exe`）时，任何
/// 同权限进程都能在校验和复制之间把文件换掉。
#[cfg(windows)]
pub struct Staged {
    pub file: std::fs::File,
    pub path: PathBuf,
}

#[cfg(windows)]
impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 暂存目录：只认 ProgramData（管理员创建后普通用户不可写）。
///
/// 旧实现在这里回退到 `%APPDATA%\ClaudeGuard\staging`——那是普通用户可写的位置，
/// 把"受控暂存"变成了"用户可预置文件"，与 R09 的前提相反。拿不到受控目录就
/// 直接失败，让用户看到原因，而不是悄悄降级。
#[cfg(windows)]
fn staging_dir() -> Result<PathBuf, String> {
    let base = std::env::var("ProgramData")
        .map_err(|_| "拿不到 ProgramData 目录，无法使用受控暂存目录".to_string())?;
    let dir = PathBuf::from(base).join("ClaudeGuard").join("staging");
    std::fs::create_dir_all(&dir).map_err(|err| format!("创建受控暂存目录失败：{err}"))?;
    Ok(dir)
}

/// 随机文件名：不依赖 rand crate，用时间+进程+计数器混合，够避免碰撞即可；
/// 真正的防替换靠 `create_new` 独占创建与句柄贯穿。
#[cfg(windows)]
fn staging_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!(
        "{:016x}-{:08x}-{:04x}.exe",
        nanos,
        std::process::id(),
        seq & 0xffff
    )
}

#[cfg(windows)]
fn create_staged() -> Result<Staged, String> {
    use std::io::ErrorKind;
    let dir = staging_dir()?;
    for _ in 0..8 {
        let path = dir.join(staging_name());
        // 必须同时要读权限：后面要用同一个句柄算摘要（sha256_of_file）并复制，
        // 只开 write 会让 ReadFile 直接 ERROR_ACCESS_DENIED。
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok(Staged { file, path }),
            // 名字撞了：换一个；其它错误如实上报（权限问题不该被重试掩盖）
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(format!("创建暂存文件失败：{err}")),
        }
    }
    Err("创建暂存文件失败：连续多次重名".to_string())
}

#[cfg(windows)]
pub fn download(
    cfg: &Config,
    url: &str,
    expected_size: u64,
    mut progress: impl FnMut(u64, u64),
) -> Result<Staged, String> {
    let mut staged = create_staged()?;

    let mut do_download =
        |agent: &ureq::Agent, progress: &mut dyn FnMut(u64, u64)| -> Result<(), String> {
            let resp = agent
                .get(url)
                .set("User-Agent", USER_AGENT)
                .timeout(T_DOWNLOAD)
                .call()
                .map_err(|e| format!("下载失败: {e}"))?;
            // 制品硬上限：超了立刻中止，不先写满磁盘再比大小。
            let limit = if expected_size > 0 {
                expected_size.min(MAX_ARTIFACT)
            } else {
                MAX_ARTIFACT
            };
            let mut reader = resp.into_reader();
            let mut written: u64 = 0;
            let mut chunk = [0u8; 65536];
            loop {
                let n = reader.read(&mut chunk).map_err(|e| format!("读取: {e}"))?;
                if n == 0 {
                    break;
                }
                written += n as u64;
                if written > limit {
                    return Err(format!(
                        "更新包超过允许的大小上限（{} MB），已中止",
                        limit / 1_048_576
                    ));
                }
                // 流式落盘，不把整包读进内存（计划要求下载内存与制品大小解耦）。
                staged
                    .file
                    .write_all(&chunk[..n])
                    .map_err(|e| format!("写暂存文件: {e}"))?;
                progress(written, expected_size);
            }
            if expected_size > 0 && written != expected_size {
                return Err(format!("大小不符: 期望 {expected_size}, 实得 {written}"));
            }
            staged
                .file
                .sync_all()
                .map_err(|e| format!("落盘暂存文件: {e}"))?;
            Ok(())
        };

    let prog = &mut progress;
    let agent = agent(cfg)?;
    do_download(&agent, prog).map_err(|e| {
        if crate::netpol::route(cfg) == crate::netpol::Route::Direct {
            e
        } else {
            crate::netpol::proxy_required_error(&e)
        }
    })?;
    Ok(staged)
}

// ------------------------------------------------------------------ 校验摘要

/// 从 `sha256:<hex>` 取出 64 位十六进制摘要（大小写不敏感）。
/// 形态不对一律返回 None——调用方据此拒绝自动替换，而不是"没摘要就当没问题"。
pub fn parse_digest(raw: &str) -> Option<String> {
    let hex = raw.trim().strip_prefix("sha256:").unwrap_or(raw.trim());
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

#[cfg(test)]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// 从已打开的句柄算摘要：校验与复制用的是同一个句柄，路径在中途被换掉也不影响
/// 我们装的就是刚才校验过的那份字节。
pub fn sha256_of_file(file: &mut std::fs::File) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("定位待校验文件失败：{e}"))?;
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; 65536];
    loop {
        let n = file
            .read(&mut chunk)
            .map_err(|e| format!("读取待校验文件失败：{e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("回卷待校验文件失败：{e}"))?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

// ------------------------------------------------------------------ 自替换

/// 用新 exe 替换当前进程的 exe 并重启。
///
/// 流程: 当前 exe 改名为 .old → 新文件复制到原路径(失败则回滚) → 启动新实例。
/// 安装版以管理员运行, 重命名/复制/启动均无权限问题; 便携版在可写目录同样适用。
/// `spawn_new=false` 供自测使用: 只做替换不启动。
/// 从**已经校验过的句柄**复制到主程序位置并重启。
///
/// 复制走句柄而不是路径：校验和安装之间即使有人替换了暂存文件，装上去的仍是
/// 刚才校验过的那份字节。
#[cfg(windows)]
pub fn apply_update_from(staged: &mut std::fs::File, spawn_new: bool) -> Result<(), String> {
    use std::io::{Seek, SeekFrom};
    let cur = std::env::current_exe().map_err(|e| format!("定位自身: {e}"))?;
    let old = cur.with_extension("exe.old");

    // 清理上次残留
    let _ = std::fs::remove_file(&old);

    std::fs::rename(&cur, &old).map_err(|e| format!("重命名旧版本: {e}"))?;

    let copy_result = (|| -> Result<(), String> {
        staged
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("回卷更新包: {e}"))?;
        let mut out = std::fs::File::create(&cur).map_err(|e| format!("创建新版本文件: {e}"))?;
        std::io::copy(staged, &mut out).map_err(|e| format!("复制新版本: {e}"))?;
        out.sync_all().map_err(|e| format!("落盘新版本: {e}"))?;
        Ok(())
    })();

    if let Err(e) = copy_result {
        // 回滚: 把 .old 改回原名, 让程序继续可用
        let _ = std::fs::rename(&old, &cur);
        return Err(e);
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

/// 启动时的更新收尾：**不**立刻删旧版本备份。
///
/// 备份要留到新实例真正跑起来（完成一轮检查）之后才清理，否则新版本一启动就崩
/// 时用户既没有可用程序、也没有可回滚的文件。
pub fn cleanup_old() {
    #[cfg(target_os = "macos")]
    if let Err(error) = self_update::recover_current() {
        eprintln!("macOS 自更新恢复未完成：{error}");
    }
    #[cfg(windows)]
    if let Some(old) = pending_backup() {
        crate::guard::log_line(&format!(
            "update: 保留上次更新备份 {}，本次启动核验通过后清理",
            old.display()
        ));
    }
}

/// 上次更新留下的旧版本备份（存在即说明需要"启动健康核验"）。
#[cfg(windows)]
pub fn pending_backup() -> Option<PathBuf> {
    let cur = std::env::current_exe().ok()?;
    let old = cur.with_extension("exe.old");
    old.exists().then_some(old)
}

#[cfg(target_os = "macos")]
pub fn pending_backup() -> Option<PathBuf> {
    None
}

/// 新实例已跑通一轮检查 → 更新算成功接管，这时才删备份。
pub fn confirm_healthy() {
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if DONE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    #[cfg(windows)]
    if let Some(old) = pending_backup() {
        match std::fs::remove_file(&old) {
            Ok(()) => crate::guard::log_line("update: 新版本启动核验通过，已清理旧版本备份"),
            Err(err) => crate::guard::log_line(&format!(
                "update: 旧版本备份清理失败（{err}），可手动删除 {}",
                old.display()
            )),
        }
    }
}

// ------------------------------------------------------------------ 后台编排

/// 后台检查 GitHub 最新版本，结果写入 `AppState::upd` 并推给 UI。
pub fn spawn_check(state: &Arc<AppState>) {
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        // 下载/替换进行中：检查结果一律不写，避免把进度覆盖成"有新版本"。
        if state.upd_busy() {
            state.log("更新正在执行，跳过本轮检查");
            return;
        }
        state.set_upd(UpdState::Checking);
        state.emit_state();
        state.log("检查更新…");
        match check_latest(&state.config()) {
            Ok(release) => {
                let ver = release.version().to_string();
                if !is_newer(&ver, current_version()) {
                    if state.set_upd_if_idle(UpdState::UpToDate) {
                        state.log(format!("已是最新版本 v{ver}"));
                    }
                } else if let Some(asset) = release.exe_asset() {
                    let wrote = state.set_upd_if_idle(UpdState::Available {
                        ver: ver.clone(),
                        url: asset.browser_download_url.clone(),
                        size: asset.size,
                    });
                    if wrote {
                        state.log(format!("发现新版本 v{ver}"));
                    }
                } else if state.set_upd_if_idle(UpdState::Failed {
                    msg: missing_asset_message(&ver),
                }) {
                    state.log("发现新版本，但发布页缺少可下载的主程序");
                }
            }
            Err(err) => {
                if state.set_upd_if_idle(UpdState::Failed { msg: err.clone() }) {
                    state.log(format!("检查更新失败：{err}"));
                }
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
    // 走 AppState::notify 这个唯一出口（分类开关 + 脱敏都在那里），
    // 不要直接调 notify::send——那会绕过 R14 的脱敏与统一策略。
    if !state.notify(
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
            if state.upd_busy() {
                continue;
            }
            match check_latest(&state.config()) {
                Ok(release) => {
                    let ver = release.version().to_string();
                    if !is_newer(&ver, current_version()) {
                        if state.set_upd_if_idle(UpdState::UpToDate) {
                            state.log(format!("静默检查：已是最新版本 v{ver}"));
                            state.emit_state();
                        }
                    } else if let Some(asset) = release.exe_asset() {
                        let wrote = state.set_upd_if_idle(UpdState::Available {
                            ver: ver.clone(),
                            url: asset.browser_download_url.clone(),
                            size: asset.size,
                        });
                        if wrote {
                            state.log(format!("发现新版本 v{ver}"));
                            state.emit_state();
                            notify_new_version(&state, &ver);
                        }
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
/// 取某个下载地址对应的官方摘要：以更新检查时的 API 响应为准，
/// 而不是信任 UI 传下来的字符串。
fn digest_for_asset(cfg: &Config, url: &str) -> Result<Option<String>, String> {
    let release = check_latest(cfg)?;
    Ok(release
        .assets
        .iter()
        .find(|a| a.browser_download_url == url)
        .and_then(|a| a.digest.clone()))
}

/// 下载前的准入门槛：URL 必须出现在**当前**官方 release 的资产列表里，
/// 且必须带可用的 sha256 摘要。返回规范化后的摘要。
///
/// 顺序很重要：先确认是官方资产，再决定要不要发请求。旧实现先按 UI 给的
/// url 下载、下完才查摘要，等于对任意地址都先打一次请求。
#[cfg(windows)]
fn official_asset_digest(cfg: &Config, url: &str) -> Result<String, String> {
    let digest = digest_for_asset(cfg, url)
        .map_err(|err| format!("无法获取官方校验摘要：{err}"))?
        .ok_or_else(|| "该版本未提供校验摘要，已取消自动更新；请手动下载安装包".to_string())?;
    parse_digest(&digest).ok_or_else(|| format!("官方摘要格式无效：{digest}"))
}

/// 保护进行中是否允许应用自身更新（计划 5.5 的近期阻断策略）。
///
/// 隔离/断网/lockdown 生效时替换主程序，会让"谁还在维持保护"变得不可确认；
/// 装新版本也绝不能顺手解除保护，所以这里直接拒绝，等用户先恢复。
pub fn update_blocked_reason(tripped: bool, lockdown: bool, disarmed: bool) -> Option<String> {
    if tripped {
        return Some("当前处于熔断隔离状态，请先解除隔离再更新".to_string());
    }
    if lockdown {
        return Some("当前处于出站封锁状态，请先解除封锁再更新".to_string());
    }
    if disarmed {
        return Some("当前已停止保护，请先重新布防再更新".to_string());
    }
    None
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
        if let Some(reason) =
            update_blocked_reason(state.is_tripped(), state.lockdown_on(), state.is_disarmed())
        {
            state.set_upd(UpdState::Failed {
                msg: reason.clone(),
            });
            state.emit_state();
            state.log(format!("更新已拒绝：{reason}"));
            return;
        }
        // R09/D6：先确认这是官方资产并拿到摘要，再发第一个字节。
        // 旧顺序是先按 UI 传来的 url 下载、下完才查摘要——等于对任意 URL 先发请求。
        #[cfg(windows)]
        let expected = match official_asset_digest(&state.config(), &url) {
            Ok(hex) => hex,
            Err(reason) => {
                state.set_upd(UpdState::Failed {
                    msg: reason.clone(),
                });
                state.emit_state();
                state.log(format!("更新已取消：{reason}"));
                return;
            }
        };
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
            Ok(mut staged) => {
                // R09/D6：下载完立刻用同一句柄核验，再谈替换。
                #[cfg(windows)]
                {
                    let actual = match sha256_of_file(&mut staged.file) {
                        Ok(v) => v,
                        Err(err) => {
                            state.set_upd(UpdState::Failed { msg: err.clone() });
                            state.emit_state();
                            state.log(format!("更新已取消：{err}"));
                            return;
                        }
                    };
                    if actual != expected {
                        let msg = format!("更新包校验不通过（期望 {expected}，实得 {actual}）");
                        state.set_upd(UpdState::Failed { msg: msg.clone() });
                        state.emit_state();
                        state.log(format!("更新已取消：{msg}"));
                        return;
                    }
                    state.log("更新包校验通过");
                }

                // 保护状态可能在下载期间变化（例如刚好熔断）：替换前再确认一次。
                if let Some(reason) = update_blocked_reason(
                    state.is_tripped(),
                    state.lockdown_on(),
                    state.is_disarmed(),
                ) {
                    state.set_upd(UpdState::Failed {
                        msg: reason.clone(),
                    });
                    state.emit_state();
                    state.log(format!("更新已中止：{reason}"));
                    return;
                }

                state.set_upd(UpdState::Restarting);
                state.emit_state();
                state.log("更新已下载，正在替换并重启…");
                let applied = {
                    #[cfg(windows)]
                    {
                        apply_update_from(&mut staged.file, true)
                    }
                    #[cfg(target_os = "macos")]
                    {
                        // macOS 走带签名清单的 self_update，校验在下载阶段已完成。
                        apply_update(&staged, true)
                    }
                };
                match applied {
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
                    digest: None,
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

    /// 摘要只认 `sha256:` + 64 位十六进制；其它形态一律视为"没有摘要"。
    #[test]
    fn digest_parsing_is_strict() {
        let hex = "a".repeat(64);
        assert_eq!(parse_digest(&format!("sha256:{hex}")), Some(hex.clone()));
        assert_eq!(
            parse_digest(&format!("sha256:{}", hex.to_uppercase())),
            Some(hex.clone())
        );
        // 缺前缀也接受（GitHub 偶尔只给裸值），但长度/字符必须对
        assert_eq!(parse_digest(&hex), Some(hex.clone()));
        assert_eq!(parse_digest(&format!("sha512:{hex}")), None);
        assert_eq!(parse_digest("sha256:abc"), None);
        assert_eq!(parse_digest(&format!("sha256:{}", "z".repeat(64))), None);
        assert_eq!(parse_digest(""), None);
    }

    /// 句柄摘要与内存摘要必须一致（校验和复制共用同一份字节的前提）。
    #[test]
    fn handle_digest_matches_in_memory_digest() {
        let dir = std::env::temp_dir().join("cg-update-handle-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("pkg.exe");
        std::fs::write(&file_path, b"hello").unwrap();

        let mut file = std::fs::File::open(&file_path).unwrap();
        let from_handle = sha256_of_file(&mut file).unwrap();
        assert_eq!(from_handle, sha256_hex(b"hello"));
        // 读完后句柄要回卷到开头，调用方才能继续复制
        assert_eq!(std::io::read_to_string(&mut file).unwrap(), "hello");

        std::fs::write(&file_path, b"hell0").unwrap();
        let mut file = std::fs::File::open(&file_path).unwrap();
        assert_ne!(sha256_of_file(&mut file).unwrap(), from_handle);
    }

    /// 受控暂存：目录在 ProgramData 下、名字随机、独占创建、Drop 时自删。
    ///
    /// 同时钉住句柄权限：暂存文件必须**可读**，否则后面的摘要校验与复制会
    /// 在 ReadFile 上失败（这是只开 write 权限时踩过的回归）。
    #[test]
    #[cfg(windows)]
    fn staging_uses_controlled_dir_and_cleans_up() {
        let mut staged = create_staged().unwrap();
        let path = staged.path.clone();
        std::io::Write::write_all(&mut staged.file, b"payload").unwrap();
        assert_eq!(
            sha256_of_file(&mut staged.file).unwrap(),
            sha256_hex(b"payload"),
            "暂存句柄必须可读，才能校验并复制同一份字节"
        );
        assert!(path.exists(), "暂存文件应已创建");
        let text = path.to_string_lossy().to_lowercase();
        assert!(
            text.contains("programdata") || text.contains("claudeguard"),
            "暂存目录应在受控位置，实际：{text}"
        );
        assert!(
            path.file_name()
                .map(|n| n.to_string_lossy().len() > 12)
                .unwrap_or(false),
            "文件名应是随机长名，实际：{text}"
        );
        drop(staged);
        assert!(!path.exists(), "Staged 离开作用域后应删除暂存文件");
    }

    /// 生产路径走一遍：暂存句柄写 → 算摘要 → 复制到目标文件，三步同一句柄。
    ///
    /// 这条链路就是 `apply_update_from` 做的事；只开 write 权限时它会在
    /// `sha256_of_file` 或 `std::io::copy` 上失败。
    #[test]
    #[cfg(windows)]
    fn staged_handle_supports_digest_then_copy() {
        let mut staged = create_staged().unwrap();
        std::io::Write::write_all(&mut staged.file, b"binary-payload").unwrap();
        let digest = sha256_of_file(&mut staged.file).unwrap();
        assert_eq!(digest, sha256_hex(b"binary-payload"));

        let dir = std::env::temp_dir().join("cg-update-copy-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out_path = dir.join("copied.exe");
        {
            let mut out = std::fs::File::create(&out_path).unwrap();
            std::io::copy(&mut staged.file, &mut out).unwrap();
            out.sync_all().unwrap();
        }
        assert_eq!(std::fs::read(&out_path).unwrap(), b"binary-payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 独占创建：同名文件已存在时不会复用（防预置文件替换）。
    #[test]
    #[cfg(windows)]
    fn staging_names_do_not_collide() {
        let a = create_staged().unwrap();
        let b = create_staged().unwrap();
        assert_ne!(a.path, b.path);
    }

    /// D6：拿不到可用摘要时不允许自动替换（不能"没校验就当没问题"）。
    #[test]
    fn missing_digest_blocks_auto_update() {
        let gate = |d: Option<&str>| d.and_then(parse_digest);
        assert!(gate(None).is_none());
        assert!(gate(Some("sha256:abc")).is_none());
        assert!(gate(Some("sha512:deadbeef")).is_none());
        let hex = sha256_hex(b"hello");
        assert_eq!(gate(Some(&format!("sha256:{hex}"))), Some(hex));
    }

    /// 计划 5.5：保护生效期间不应用自身更新，且拒绝时必须说明原因。
    #[test]
    fn update_is_blocked_while_protection_is_active() {
        assert!(update_blocked_reason(false, false, false).is_none());
        assert!(update_blocked_reason(true, false, false)
            .unwrap()
            .contains("熔断"));
        assert!(update_blocked_reason(false, true, false)
            .unwrap()
            .contains("封锁"));
        assert!(update_blocked_reason(false, false, true)
            .unwrap()
            .contains("停止保护"));
        // 多重状态同时成立时，按"最需要用户先处理"的顺序报
        assert!(update_blocked_reason(true, true, true)
            .unwrap()
            .contains("熔断"));
    }
}
