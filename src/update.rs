//! GitHub Releases 更新检查与自替换。
//!
//! 更新源: https://github.com/daha1216/ClaudeGuard (公开仓, 匿名 API)。
//! 网络路径: 优先走用户配置的本地代理(国内直连 GitHub 不稳), 失败回退直连。

use crate::config::Config;
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const GITHUB_REPO: &str = "daha1216/ClaudeGuard";
const USER_AGENT: &str = "ClaudeGuard-Updater";

/// 检查超时
const T_CHECK: Duration = Duration::from_secs(10);
/// 下载超时(整体)
const T_DOWNLOAD: Duration = Duration::from_secs(300);

// ------------------------------------------------------------------ 数据结构

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
}

impl Release {
    /// 语义化版本号(去掉 v 前缀)
    pub fn version(&self) -> &str {
        self.tag_name.trim_start_matches('v')
    }

    /// 找主程序资产: 名字含 ClaudeGuard 且以 .exe 结尾
    pub fn exe_asset(&self) -> Option<&Asset> {
        self.assets
            .iter()
            .find(|a| a.name.ends_with(".exe") && a.name.contains("ClaudeGuard"))
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

/// 代理感知 Agent: 与 checks.rs 相同的构建方式。
fn agent_with_proxy(cfg: &Config) -> Option<ureq::Agent> {
    ureq::Proxy::new(format!("http://{}:{}", cfg.proxy_host, cfg.proxy_port))
        .ok()
        .map(|p| {
            ureq::AgentBuilder::new()
                .timeout_connect(T_CHECK)
                .proxy(p)
                .build()
        })
}

fn agent_direct() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout_connect(T_CHECK).build()
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

    if let Some(agent) = agent_with_proxy(cfg) {
        match fetch(&agent) {
            Ok(r) => return Ok(r),
            Err(e1) => match fetch(&agent_direct()) {
                Ok(r) => return Ok(r),
                Err(e2) => {
                    return Err(format!("代理失败: {e1}; 直连失败: {e2}"));
                }
            },
        }
    }
    fetch(&agent_direct())
}

// ------------------------------------------------------------------ 下载

/// 下载到临时文件, 返回路径。progress(已下载字节, 总字节)。
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
    if let Some(agent) = agent_with_proxy(cfg) {
        if let Err(e1) = do_download(&agent, prog) {
            let p2 = &mut progress;
            do_download(&agent_direct(), p2)
                .map_err(|e2| format!("代理失败: {e1}; 直连失败: {e2}"))?;
            return Ok(tmp);
        }
        return Ok(tmp);
    }
    do_download(&agent_direct(), prog)?;
    Ok(tmp)
}

// ------------------------------------------------------------------ 自替换

/// 用新 exe 替换当前进程的 exe 并重启。
///
/// 流程: 当前 exe 改名为 .old → 新文件复制到原路径(失败则回滚) → 启动新实例。
/// 安装版以管理员运行, 重命名/复制/启动均无权限问题; 便携版在可写目录同样适用。
/// `spawn_new=false` 供自测使用: 只做替换不启动。
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

/// 启动时清理上次更新残留的 .old 文件。
pub fn cleanup_old() {
    if let Ok(cur) = std::env::current_exe() {
        let old = cur.with_extension("exe.old");
        let _ = std::fs::remove_file(&old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
