//! GitHub Release update checker for ClaudeGuard (`daha1216/ClaudeGuard`) and
//! `yuaotian/antigravity-proxy`, strictly honoring `ProbeRoute` / no-direct-fallback policy.

use std::io::Read;
use std::time::Duration;

use cg_protocol::{AntigravityProxyStatus, ComponentUpdateStatus, UpdateCheckPhase, UpdateSummary};
use serde::{Deserialize, Serialize};

use crate::probe_http::{
    proxy_required_error, ProbeRoute, MAX_PROBE_BODY_BYTES, MAX_PROBE_REDIRECTS, PROBE_USER_AGENT,
};
use crate::traits::{PlatformError, PlatformResult};

/// Official ClaudeGuard repository for self-update checks.
pub const CLAUDEGUARD_REPO: &str = "daha1216/ClaudeGuard";
/// Upstream `antigravity-proxy` injector repository.
pub const ANTIGRAVITY_PROXY_REPO: &str = "yuaotian/antigravity-proxy";
/// Upstream `antigravity-desktop-cn` Chinese localization repository.
pub const ANTIGRAVITY_CN_REPO: &str = "Silas-02/antigravity-desktop-cn";
/// Upstream `antigravity-usage-monitor` plugin repository.
pub const AG_USAGE_MONITOR_REPO: &str = "yuhuan-dev/antigravity-usage-monitor";
/// Upstream `agy-capsule` plugin repository.
pub const AG_CAPSULE_REPO: &str = "Lumidarin/agy-capsule";
/// Exact user-facing description for `antigravity-proxy`.
pub const ANTIGRAVITY_PROXY_DESC: &str =
    "专为 Antigravity 打造的免 TUN 强制代理工具，支持 DLL 注入与进程流量劫持。";
/// Official npm package for Claude Code CLI.
pub const CLAUDE_CODE_NPM_PKG: &str = "@anthropic-ai/claude-code";
/// Official npm package for Codex CLI.
pub const CODEX_CLI_NPM_PKG: &str = "@openai/codex";
/// Official GitHub fallback repo for Codex CLI.
pub const CODEX_CLI_REPO: &str = "openai/codex";
/// Official Antigravity Desktop generic updater manifest base URL.
pub const ANTIGRAVITY_DEFAULT_MANIFEST_BASE: &str =
    "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest";
/// Default HTTP timeout for update API checks.
pub const DEFAULT_UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Local detected client versions passed from `cg-platform::process_win` into update comparison.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalClientVersions {
    pub claude_desktop: Option<String>,
    pub claude_code: Option<String>,
    pub codex_desktop: Option<String>,
    pub codex_cli: Option<String>,
    pub antigravity_ide: Option<String>,
    pub antigravity_manifest_base: Option<String>,
    pub antigravity_cn: Option<String>,
    pub ag_usage_monitor: Option<String>,
    pub ag_capsule: Option<String>,
}

/// Remote version discovery result for desktop MSIX, npm CLI, and Antigravity clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteClientVersion {
    pub version: String,
    pub release_url: Option<String>,
    pub asset_url: Option<String>,
}

/// Parsed GitHub latest release metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubReleaseInfo {
    pub tag_name: String,
    pub version: String,
    pub html_url: String,
    pub asset_url: Option<String>,
    pub published_at: Option<String>,
}

/// Windows architecture string (`x64` or `arm64`) used by Claude / Codex / Antigravity feeds.
pub fn current_windows_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    }
}

/// Strip prefixes like `rust-v`, `v`, `V` cleanly before SemVer comparison.
pub fn normalize_version(raw: &str) -> String {
    let mut s = raw.trim();
    for prefix in ["rust-v", "rust-V", "v", "V"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    s.trim().to_string()
}

fn parse_semver_parts(raw: &str) -> Option<(Vec<u64>, Option<String>)> {
    let cleaned = normalize_version(raw);
    if cleaned.is_empty() {
        return None;
    }
    let (without_build, _) = cleaned.split_once('+').unwrap_or((&cleaned, ""));
    let (core_str, pre_str) = match without_build.split_once('-') {
        Some((core, pre)) => (core, Some(pre.trim().to_string()).filter(|s| !s.is_empty())),
        None => (without_build, None),
    };
    if core_str.is_empty() {
        return None;
    }
    let mut nums = Vec::new();
    for seg in core_str.split('.') {
        let parsed = seg.trim().parse::<u64>().ok()?;
        nums.push(parsed);
    }
    Some((nums, pre_str))
}

fn compare_prerelease(remote: &str, current: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut r_parts = remote.split('.');
    let mut c_parts = current.split('.');
    loop {
        match (r_parts.next(), c_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(r), Some(c)) => {
                let ord = match (r.parse::<u64>(), c.parse::<u64>()) {
                    (Ok(rn), Ok(cn)) => rn.cmp(&cn),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => r.to_ascii_lowercase().cmp(&c.to_ascii_lowercase()),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Pure SemVer comparison: returns `true` iff `remote` is strictly newer than `current`.
///
/// - Trims leading `'v'` / `'V'` and build metadata (`+...`).
/// - Compares dot-separated numeric core before `'-'` numerically (`2.7.0 > 2.6.3`).
/// - When numeric cores match, stable (no `'-'`) is newer than pre-release (has `'-'`).
pub fn is_version_newer(remote: &str, current: &str) -> bool {
    use std::cmp::Ordering;

    let Some((r_core, r_pre)) = parse_semver_parts(remote) else {
        return false;
    };
    let Some((c_core, c_pre)) = parse_semver_parts(current) else {
        return current.trim().is_empty();
    };

    let len = r_core.len().max(c_core.len());
    for i in 0..len {
        let r_num = r_core.get(i).copied().unwrap_or(0);
        let c_num = c_core.get(i).copied().unwrap_or(0);
        if r_num != c_num {
            return r_num > c_num;
        }
    }

    match (r_pre, c_pre) {
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (None, None) => false,
        (Some(rp), Some(cp)) => compare_prerelease(&rp, &cp) == Ordering::Greater,
    }
}

fn is_source_or_meta_asset(name_l: &str) -> bool {
    name_l.starts_with("source")
        || name_l.starts_with("src.")
        || name_l.starts_with("src-")
        || name_l.contains("source-code")
        || name_l.contains("source_code")
        || name_l.ends_with(".sha256")
        || name_l.ends_with(".sha512")
        || name_l.ends_with(".sha1")
        || name_l.ends_with(".md5")
        || name_l.ends_with(".sig")
        || name_l.ends_with(".asc")
        || name_l.ends_with(".txt")
        || name_l.ends_with(".yml")
        || name_l.ends_with(".yaml")
        || name_l.ends_with(".blockmap")
}

fn pick_preferred_asset(assets: &[(String, String)], preferred_exts: &[&str]) -> Option<String> {
    let setup_requested = preferred_exts
        .iter()
        .any(|ext| ext.to_ascii_lowercase().contains("setup"));

    let candidates: Vec<(&str, String, &str)> = assets
        .iter()
        .filter_map(|(name, url)| {
            let name_l = name.trim().to_ascii_lowercase();
            let url_t = url.trim();
            if name_l.is_empty() || url_t.is_empty() || is_source_or_meta_asset(&name_l) {
                return None;
            }
            Some((name.as_str(), name_l, url_t))
        })
        .collect();

    for ext in preferred_exts {
        let ext_l = ext.trim().to_ascii_lowercase();
        if ext_l.is_empty() {
            continue;
        }
        let allow_setup_for_ext = ext_l.contains("setup");
        if let Some((_, _, url)) = candidates.iter().find(|(_, name_l, _)| {
            name_l.ends_with(&ext_l) && (allow_setup_for_ext || !name_l.ends_with("-setup.exe"))
        }) {
            return Some((*url).to_string());
        }
    }

    candidates
        .iter()
        .find(|(_, name_l, _)| setup_requested || !name_l.ends_with("-setup.exe"))
        .map(|(_, _, url)| (*url).to_string())
}

/// Pure GitHub `/releases/latest` JSON payload parser.
pub fn parse_github_latest_release(
    json_body: &str,
    preferred_exts: &[&str],
) -> PlatformResult<GithubReleaseInfo> {
    let val: serde_json::Value = serde_json::from_str(json_body)
        .map_err(|e| PlatformError::Network(format!("GitHub Release JSON 解析失败：{e}")))?;

    let tag_name = val
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PlatformError::Network("GitHub Release 响应缺少 tag_name".to_string()))?
        .to_string();

    let version = normalize_version(&tag_name);
    if version.is_empty() {
        return Err(PlatformError::Network(
            "GitHub Release tag_name 无效".to_string(),
        ));
    }

    let html_url = val
        .get("html_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string();

    let published_at = val
        .get("published_at")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let mut assets = Vec::new();
    if let Some(arr) = val.get("assets").and_then(|v| v.as_array()) {
        for item in arr {
            let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(url) = item.get("browser_download_url").and_then(|v| v.as_str()) else {
                continue;
            };
            if !name.trim().is_empty() && !url.trim().is_empty() {
                assets.push((name.trim().to_string(), url.trim().to_string()));
            }
        }
    }

    let asset_url = pick_preferred_asset(&assets, preferred_exts);

    Ok(GithubReleaseInfo {
        tag_name,
        version,
        html_url,
        asset_url,
        published_at,
    })
}

fn build_update_agent(
    route: &ProbeRoute,
    timeout: Duration,
    redirects: u32,
) -> PlatformResult<ureq::Agent> {
    match route {
        ProbeRoute::Skip(reason) => Err(PlatformError::Network(reason.clone())),
        ProbeRoute::Proxy(proxy_url) => {
            let proxy = ureq::Proxy::new(proxy_url).map_err(|e| {
                PlatformError::Network(proxy_required_error(&format!("代理地址无效：{e}")))
            })?;
            Ok(ureq::AgentBuilder::new()
                .timeout_connect(timeout)
                .timeout(timeout)
                .redirects(redirects)
                .try_proxy_from_env(false)
                .user_agent(PROBE_USER_AGENT)
                .proxy(proxy)
                .build())
        }
        ProbeRoute::Direct => Ok(ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout(timeout)
            .redirects(redirects)
            .try_proxy_from_env(false)
            .user_agent(PROBE_USER_AGENT)
            .build()),
    }
}

fn map_transport_err(route: &ProbeRoute, err: ureq::Error) -> PlatformError {
    let detail = err.to_string();
    PlatformError::Network(match route {
        ProbeRoute::Proxy(_) => proxy_required_error(&detail),
        _ => detail,
    })
}

/// Fetch and parse a GitHub Release JSON endpoint honoring `ProbeRoute`.
///
/// - Immediately refuses `ProbeRoute::Skip` without opening any socket.
/// - Disables ambient env proxy (`try_proxy_from_env(false)`).
/// - Never falls back silently from `ProbeRoute::Proxy` to `ProbeRoute::Direct`.
pub fn fetch_github_latest_from_url(
    route: &ProbeRoute,
    api_url: &str,
    preferred_exts: &[&str],
    timeout: Duration,
) -> PlatformResult<GithubReleaseInfo> {
    let agent = build_update_agent(route, timeout, MAX_PROBE_REDIRECTS)?;

    let call = agent
        .get(api_url)
        .timeout(timeout)
        .set("User-Agent", PROBE_USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call();

    match call {
        Ok(resp) => {
            let mut buf = Vec::new();
            let _ = resp
                .into_reader()
                .take(MAX_PROBE_BODY_BYTES as u64)
                .read_to_end(&mut buf);
            let body = String::from_utf8_lossy(&buf);
            parse_github_latest_release(&body, preferred_exts)
        }
        Err(ureq::Error::Status(status, resp)) => {
            let remaining_zero = resp
                .header("x-ratelimit-remaining")
                .is_some_and(|v| v.trim() == "0");
            let mut buf = Vec::new();
            let _ = resp
                .into_reader()
                .take(MAX_PROBE_BODY_BYTES as u64)
                .read_to_end(&mut buf);
            let json_msg = serde_json::from_slice::<serde_json::Value>(&buf)
                .ok()
                .and_then(|v| {
                    v.get("message")
                        .and_then(|m| m.as_str())
                        .map(|s| s.trim().to_string())
                })
                .filter(|s| !s.is_empty());

            let rate_limited = status == 429
                || (status == 403
                    && (remaining_zero
                        || json_msg
                            .as_deref()
                            .is_none_or(|m| m.to_ascii_lowercase().contains("rate limit"))));
            if rate_limited {
                return Err(PlatformError::Network(
                    "GitHub API 限流，稍后自动重试".to_string(),
                ));
            }
            if let Some(msg) = json_msg {
                return Err(PlatformError::Network(format!(
                    "GitHub API 请求失败（HTTP {status}）：{msg}"
                )));
            }
            Err(PlatformError::Network(format!(
                "GitHub API 请求失败（HTTP {status}）"
            )))
        }
        Err(err) => Err(map_transport_err(route, err)),
    }
}

/// Fetch the latest GitHub Release for `owner/repo` honoring `ProbeRoute`.
pub fn fetch_github_latest_release(
    route: &ProbeRoute,
    repo: &str,
    preferred_exts: &[&str],
    timeout: Duration,
) -> PlatformResult<GithubReleaseInfo> {
    let trimmed = repo.trim().trim_matches('/');
    let api_url = format!("https://api.github.com/repos/{trimmed}/releases/latest");
    fetch_github_latest_from_url(route, &api_url, preferred_exts, timeout)
}

/// Pure parser for GitHub `/commits?per_page=1` JSON payload, extracting commit date `YYYY.MM.DD`.
pub fn parse_github_latest_commit(json_body: &str, repo: &str) -> PlatformResult<GithubReleaseInfo> {
    let arr: serde_json::Value = serde_json::from_str(json_body)
        .map_err(|e| PlatformError::Network(format!("GitHub Commits JSON 解析失败：{e}")))?;
    let first = arr
        .as_array()
        .and_then(|items| items.first())
        .ok_or_else(|| PlatformError::Network("GitHub 仓库提交记录为空".to_string()))?;
    let date_raw = first
        .pointer("/commit/committer/date")
        .or_else(|| first.pointer("/commit/author/date"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| s.len() >= 10)
        .ok_or_else(|| PlatformError::Network("GitHub 提交记录缺少有效日期".to_string()))?;
    let ymd = date_raw[..10].replace('-', ".");
    let sha = first
        .get("sha")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(7).collect::<String>())
        .unwrap_or_default();
    let html_url = first
        .get("html_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("https://github.com/{}", repo.trim().trim_matches('/')));
    Ok(GithubReleaseInfo {
        tag_name: if sha.is_empty() {
            ymd.clone()
        } else {
            format!("{ymd} ({sha})")
        },
        version: ymd,
        html_url,
        asset_url: None,
        published_at: Some(date_raw.to_string()),
    })
}

/// Fetch GitHub latest Release, falling back to latest default-branch commit date when the repo
/// ships via source commits without formal GitHub Releases (e.g. `Silas-02/antigravity-desktop-cn`).
pub fn fetch_github_latest_release_or_commit(
    route: &ProbeRoute,
    repo: &str,
    preferred_exts: &[&str],
    timeout: Duration,
) -> PlatformResult<RemoteClientVersion> {
    match fetch_github_latest_release(route, repo, preferred_exts, timeout) {
        Ok(rel) => Ok(RemoteClientVersion {
            version: rel.version,
            release_url: (!rel.html_url.is_empty())
                .then_some(rel.html_url)
                .or_else(|| Some(format!("https://github.com/{}", repo.trim().trim_matches('/')))),
            asset_url: rel.asset_url,
        }),
        Err(rel_err) => {
            // Only fall back to commits when Releases endpoint returned HTTP 404 (no formal release).
            if !rel_err.to_string().contains("404") {
                return Err(rel_err);
            }
            let trimmed = repo.trim().trim_matches('/');
            let commits_url = format!("https://api.github.com/repos/{trimmed}/commits?per_page=1");
            let agent = build_update_agent(route, timeout, MAX_PROBE_REDIRECTS)?;
            let resp = match agent
                .get(&commits_url)
                .timeout(timeout)
                .set("User-Agent", PROBE_USER_AGENT)
                .set("Accept", "application/vnd.github+json")
                .call()
            {
                Ok(r) => r,
                Err(ureq::Error::Status(code, _)) => {
                    return Err(PlatformError::Network(format!(
                        "GitHub 仓库提交查询失败（HTTP {code}）"
                    )));
                }
                Err(err) => return Err(map_transport_err(route, err)),
            };
            let mut buf = Vec::new();
            let _ = resp
                .into_reader()
                .take(MAX_PROBE_BODY_BYTES as u64)
                .read_to_end(&mut buf);
            let body = String::from_utf8_lossy(&buf);
            let info = parse_github_latest_commit(&body, trimmed)?;
            Ok(RemoteClientVersion {
                version: info.version,
                release_url: Some(info.html_url),
                asset_url: None,
            })
        }
    }
}

/// Parse official Claude Desktop MSIX redirect `Location` URL into semantic version.
pub fn parse_claude_desktop_redirect(location: &str, arch: &str) -> PlatformResult<String> {
    if !matches!(arch, "x64" | "arm64") {
        return Err(PlatformError::InvalidInput("不支持的 Windows 架构".into()));
    }
    let prefix = format!("https://downloads.claude.ai/releases/win32/{arch}/");
    let tail = location
        .trim()
        .strip_prefix(&prefix)
        .ok_or_else(|| PlatformError::Network("Claude Desktop 更新重定向地址非官方来源".into()))?;
    let (ver, file) = tail
        .split_once('/')
        .ok_or_else(|| PlatformError::Network("Claude Desktop 更新地址格式无效".into()))?;
    if parse_semver_parts(ver).is_none() {
        return Err(PlatformError::Network("Claude Desktop 返回版本号无效".into()));
    }
    let hash = file
        .strip_prefix("Claude-")
        .and_then(|f| f.strip_suffix(".msix"))
        .ok_or_else(|| PlatformError::Network("Claude Desktop 更新文件名格式无效".into()))?;
    if hash.len() != 40 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(PlatformError::Network("Claude Desktop MSIX 校验摘要路径无效".into()));
    }
    Ok(normalize_version(ver))
}

/// Check latest Claude Desktop MSIX version via `claude.ai/api/desktop/win32/{arch}/msix/latest/redirect`.
pub fn fetch_claude_desktop_latest(
    route: &ProbeRoute,
    arch: &str,
    timeout: Duration,
) -> PlatformResult<RemoteClientVersion> {
    if !matches!(arch, "x64" | "arm64") {
        return Err(PlatformError::InvalidInput("不支持的 Windows 架构".into()));
    }
    let agent = build_update_agent(route, timeout, 0)?;
    let url = format!("https://claude.ai/api/desktop/win32/{arch}/msix/latest/redirect");
    let resp = match agent.get(&url).timeout(timeout).call() {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r,
        Err(err) => return Err(map_transport_err(route, err)),
    };
    if !matches!(resp.status(), 301 | 302 | 303 | 307 | 308) {
        return Err(PlatformError::Network(format!(
            "Claude 官方更新接口未返回重定向（HTTP {}）",
            resp.status()
        )));
    }
    let location = resp
        .header("Location")
        .ok_or_else(|| PlatformError::Network("Claude 官方更新接口缺少 Location".into()))?
        .to_string();
    let version = parse_claude_desktop_redirect(&location, arch)?;
    Ok(RemoteClientVersion {
        version,
        release_url: Some("https://claude.ai/download".into()),
        asset_url: Some(location),
    })
}

/// Check latest ChatGPT / Codex Desktop MSIX version via `persistent.oaistatic.com` HEAD metadata.
pub fn fetch_codex_desktop_latest_from_url(
    route: &ProbeRoute,
    url: &str,
    arch: &str,
    timeout: Duration,
) -> PlatformResult<RemoteClientVersion> {
    if !matches!(arch, "x64" | "arm64") {
        return Err(PlatformError::InvalidInput("不支持的 Windows 架构".into()));
    }
    let agent = build_update_agent(route, timeout, 0)?;
    let resp = match agent.head(url).timeout(timeout).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            return Err(PlatformError::Network(format!(
                "OpenAI 桌面更新接口返回 HTTP {code}"
            )));
        }
        Err(err) => return Err(map_transport_err(route, err)),
    };
    if resp.header("x-ms-meta-package_identity") != Some("OpenAI.Codex")
        || resp.header("x-ms-meta-architecture") != Some(arch)
    {
        return Err(PlatformError::Network(
            "OpenAI 桌面安装包元数据不匹配".into(),
        ));
    }
    let ver = resp
        .header("x-ms-meta-package_version")
        .map(normalize_version)
        .filter(|s| !s.is_empty() && parse_semver_parts(s).is_some())
        .ok_or_else(|| PlatformError::Network("OpenAI 桌面更新接口缺少有效版本号".into()))?;
    Ok(RemoteClientVersion {
        version: ver,
        release_url: Some("https://chatgpt.com/download".into()),
        asset_url: Some(url.to_string()),
    })
}

pub fn fetch_codex_desktop_latest(
    route: &ProbeRoute,
    arch: &str,
    timeout: Duration,
) -> PlatformResult<RemoteClientVersion> {
    let url = format!("https://persistent.oaistatic.com/codex-app-prod/ChatGPT-{arch}.msix");
    fetch_codex_desktop_latest_from_url(route, &url, arch, timeout)
}

/// Parse `https://registry.npmjs.org/<pkg>/latest` JSON payload for `"version"`.
pub fn parse_npm_latest_version(json_body: &str, pkg_name: &str) -> PlatformResult<RemoteClientVersion> {
    let val: serde_json::Value = serde_json::from_str(json_body)
        .map_err(|e| PlatformError::Network(format!("npm 清单解析失败：{e}")))?;
    let ver = val
        .get("version")
        .and_then(|v| v.as_str())
        .map(normalize_version)
        .filter(|s| !s.is_empty() && parse_semver_parts(s).is_some())
        .ok_or_else(|| PlatformError::Network(format!("{pkg_name} 响应缺少有效版本号")))?;
    let tarball = val
        .pointer("/dist/tarball")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    Ok(RemoteClientVersion {
        version: ver,
        release_url: Some(format!("https://www.npmjs.com/package/{pkg_name}")),
        asset_url: tarball,
    })
}

/// Shared npm registry `/latest` checker honoring `ProbeRoute`.
pub fn fetch_npm_latest_from_url(
    route: &ProbeRoute,
    url: &str,
    pkg_name: &str,
    timeout: Duration,
) -> PlatformResult<RemoteClientVersion> {
    let agent = build_update_agent(route, timeout, MAX_PROBE_REDIRECTS)?;
    let resp = match agent.get(url).timeout(timeout).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            return Err(PlatformError::Network(format!(
                "npm 官方仓库请求失败（HTTP {code}）"
            )));
        }
        Err(err) => return Err(map_transport_err(route, err)),
    };
    let mut buf = Vec::new();
    let _ = resp
        .into_reader()
        .take(MAX_PROBE_BODY_BYTES as u64)
        .read_to_end(&mut buf);
    let body = String::from_utf8_lossy(&buf);
    parse_npm_latest_version(&body, pkg_name)
}

pub fn fetch_npm_latest(
    route: &ProbeRoute,
    pkg_name: &str,
    timeout: Duration,
) -> PlatformResult<RemoteClientVersion> {
    let url = format!("https://registry.npmjs.org/{pkg_name}/latest");
    fetch_npm_latest_from_url(route, &url, pkg_name, timeout)
}

/// Parse Antigravity electron-updater `latest-x64-win.yml` YAML body for `version:` and `path:`.
pub fn parse_antigravity_yaml_latest(
    yaml_body: &str,
    manifest_base: &str,
) -> PlatformResult<RemoteClientVersion> {
    let mut ver: Option<String> = None;
    let mut path_rel: Option<String> = None;
    for line in yaml_body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("version:") {
            let v = normalize_version(rest.trim().trim_matches(['"', '\'']));
            if !v.is_empty() && parse_semver_parts(&v).is_some() {
                ver = Some(v);
            }
        } else if let Some(rest) = trimmed.strip_prefix("path:") {
            let p = rest.trim().trim_matches(['"', '\'']).to_string();
            if !p.is_empty() {
                path_rel = Some(p);
            }
        }
    }
    let version = ver.ok_or_else(|| {
        PlatformError::Network("Antigravity 更新清单缺少有效 version 字段".into())
    })?;
    let asset_url = path_rel.map(|rel| {
        if rel.starts_with("https://") || rel.starts_with("http://") {
            rel
        } else {
            format!(
                "{}/{}",
                manifest_base.trim_end_matches('/'),
                rel.trim_start_matches('/')
            )
        }
    });
    Ok(RemoteClientVersion {
        version,
        release_url: Some("https://antigravity.google".into()),
        asset_url,
    })
}

pub fn fetch_antigravity_ide_latest(
    route: &ProbeRoute,
    manifest_base_opt: Option<&str>,
    arch: &str,
    timeout: Duration,
) -> PlatformResult<RemoteClientVersion> {
    let base = manifest_base_opt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(ANTIGRAVITY_DEFAULT_MANIFEST_BASE)
        .trim_end_matches('/');
    let arch_seg = if arch == "arm64" { "arm64" } else { "x64" };
    let url = format!("{base}/latest-{arch_seg}-win.yml");
    let agent = build_update_agent(route, timeout, MAX_PROBE_REDIRECTS)?;
    let resp = match agent.get(&url).timeout(timeout).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            return Err(PlatformError::Network(format!(
                "Antigravity 官方更新源请求失败（HTTP {code}）"
            )));
        }
        Err(err) => return Err(map_transport_err(route, err)),
    };
    let mut buf = Vec::new();
    let _ = resp
        .into_reader()
        .take(MAX_PROBE_BODY_BYTES as u64)
        .read_to_end(&mut buf);
    let body = String::from_utf8_lossy(&buf);
    parse_antigravity_yaml_latest(&body, base)
}

fn ensure_slot(slot: &mut ComponentUpdateStatus, id: &str, name: &str, repo: &str) {
    if slot.id.is_empty() {
        slot.id = id.to_string();
    }
    if slot.name.is_empty() {
        slot.name = name.to_string();
    }
    if slot.repo.is_empty() {
        slot.repo = repo.to_string();
    }
}

/// Synchronize locally detected versions onto `UpdateSummary` without touching network.
pub fn hydrate_summary_locals(
    summary: &mut UpdateSummary,
    cg_version: &str,
    ag_proxy: &AntigravityProxyStatus,
    local: &LocalClientVersions,
) {
    ensure_slot(&mut summary.claudeguard, "claudeguard", "ClaudeGuard 主程序", CLAUDEGUARD_REPO);
    summary.claudeguard.installed_version = Some(normalize_version(cg_version));

    ensure_slot(
        &mut summary.antigravity_proxy,
        "antigravity_proxy",
        "antigravity-proxy 注入器",
        ANTIGRAVITY_PROXY_REPO,
    );
    summary.antigravity_proxy.installed_version = ag_proxy
        .injector_version
        .as_deref()
        .map(normalize_version)
        .filter(|s| !s.is_empty());

    ensure_slot(
        &mut summary.claude_desktop,
        "claude_desktop",
        "Claude 桌面端",
        "Anthropic MSIX 官方渠道",
    );
    summary.claude_desktop.installed_version = local.claude_desktop.as_deref().map(normalize_version);
    summary.claude_msix_version = summary.claude_desktop.installed_version.clone();

    ensure_slot(
        &mut summary.claude_code,
        "claude_code",
        "Claude Code CLI",
        CLAUDE_CODE_NPM_PKG,
    );
    summary.claude_code.installed_version = local.claude_code.as_deref().map(normalize_version);

    ensure_slot(
        &mut summary.codex_desktop,
        "codex_desktop",
        "ChatGPT / Codex 桌面端",
        "OpenAI MSIX 官方渠道",
    );
    summary.codex_desktop.installed_version = local.codex_desktop.as_deref().map(normalize_version);
    summary.codex_msix_version = summary.codex_desktop.installed_version.clone();

    ensure_slot(&mut summary.codex_cli, "codex_cli", "Codex CLI", CODEX_CLI_NPM_PKG);
    summary.codex_cli.installed_version = local.codex_cli.as_deref().map(normalize_version);

    ensure_slot(
        &mut summary.antigravity_ide,
        "antigravity_ide",
        "Antigravity 客户端",
        "Google 官方更新源",
    );
    summary.antigravity_ide.installed_version = local
        .antigravity_ide
        .as_deref()
        .map(normalize_version)
        .or_else(|| {
            ag_proxy
                .antigravity_version
                .as_deref()
                .map(normalize_version)
                .filter(|s| !s.is_empty())
        });

    ensure_slot(
        &mut summary.antigravity_cn,
        "antigravity_cn",
        "Antigravity 中文汉化引擎",
        ANTIGRAVITY_CN_REPO,
    );
    if summary.antigravity_cn.release_url.is_none() {
        summary.antigravity_cn.release_url =
            Some(format!("https://github.com/{ANTIGRAVITY_CN_REPO}"));
    }
    summary.antigravity_cn.installed_version =
        local.antigravity_cn.as_deref().map(normalize_version);

    ensure_slot(
        &mut summary.ag_usage_monitor,
        "ag_usage_monitor",
        "antigravity-usage-monitor",
        AG_USAGE_MONITOR_REPO,
    );
    if summary.ag_usage_monitor.release_url.is_none() {
        summary.ag_usage_monitor.release_url =
            Some(format!("https://github.com/{AG_USAGE_MONITOR_REPO}"));
    }
    summary.ag_usage_monitor.installed_version =
        local.ag_usage_monitor.as_deref().map(normalize_version);

    ensure_slot(
        &mut summary.ag_capsule,
        "ag_capsule",
        "agy-capsule",
        AG_CAPSULE_REPO,
    );
    if summary.ag_capsule.release_url.is_none() {
        summary.ag_capsule.release_url = Some(format!("https://github.com/{AG_CAPSULE_REPO}"));
    }
    summary.ag_capsule.installed_version = local.ag_capsule.as_deref().map(normalize_version);
}

fn ensure_component_defaults(summary: &mut UpdateSummary, cg_version: &str) {
    ensure_slot(&mut summary.claudeguard, "claudeguard", "ClaudeGuard 主程序", CLAUDEGUARD_REPO);
    summary.claudeguard.installed_version = Some(normalize_version(cg_version));
    ensure_slot(
        &mut summary.antigravity_proxy,
        "antigravity_proxy",
        "antigravity-proxy 注入器",
        ANTIGRAVITY_PROXY_REPO,
    );
}

fn apply_client_update_check<F>(
    prev: &ComponentUpdateStatus,
    id: &str,
    name: &str,
    repo: &str,
    installed_ver: Option<&str>,
    now_secs: u64,
    mut fetcher: F,
) -> ComponentUpdateStatus
where
    F: FnMut() -> PlatformResult<RemoteClientVersion>,
{
    let installed_clean = installed_ver
        .map(normalize_version)
        .filter(|s| !s.is_empty());
    let mut next = prev.clone();
    next.id = id.to_string();
    next.name = name.to_string();
    next.repo = repo.to_string();
    next.installed_version = installed_clean.clone();
    next.checked_at = Some(now_secs);

    match fetcher() {
        Ok(remote) => {
            next.latest_version = Some(remote.version.clone());
            if remote.release_url.is_some() {
                next.release_url = remote.release_url;
            }
            if remote.asset_url.is_some() {
                next.asset_url = remote.asset_url;
            }
            match installed_clean.as_deref() {
                None => {
                    next.phase = UpdateCheckPhase::NotInstalled;
                    next.note = format!("本机未检测到 {name}（官方最新 v{}）", remote.version);
                }
                Some(ins) if is_version_newer(&remote.version, ins) => {
                    next.phase = UpdateCheckPhase::UpdateAvailable;
                    next.note = format!("发现新版本：当前 v{ins} -> 最新 v{}", remote.version);
                }
                Some(ins) => {
                    next.phase = UpdateCheckPhase::UpToDate;
                    next.note = format!("当前 v{ins} 已是最新官方版本");
                }
            }
        }
        Err(err) => {
            next.phase = UpdateCheckPhase::Failed;
            next.note = format!("检查 {name} 更新失败：{err}");
        }
    }
    next
}

fn apply_claudeguard_check<F>(
    prev: &ComponentUpdateStatus,
    cg_version: &str,
    now_secs: u64,
    fetcher: &mut F,
) -> ComponentUpdateStatus
where
    F: FnMut(&str, &[&str]) -> PlatformResult<GithubReleaseInfo>,
{
    let cur = normalize_version(cg_version);
    let mut next = prev.clone();
    next.id = "claudeguard".to_string();
    next.name = "ClaudeGuard 主程序".to_string();
    next.repo = CLAUDEGUARD_REPO.to_string();
    next.installed_version = Some(cur.clone());
    next.checked_at = Some(now_secs);

    match fetcher(CLAUDEGUARD_REPO, &["-setup.exe", ".exe"]) {
        Ok(rel) => {
            next.latest_version = Some(rel.version.clone());
            next.release_url = (!rel.html_url.is_empty()).then_some(rel.html_url);
            next.asset_url = rel.asset_url;
            if is_version_newer(&rel.version, &cur) {
                next.phase = UpdateCheckPhase::UpdateAvailable;
                next.note = format!("发现新版 ClaudeGuard：当前 v{cur} -> 最新 v{}", rel.version);
            } else {
                next.phase = UpdateCheckPhase::UpToDate;
                next.note = format!("当前 v{cur} 已是 ClaudeGuard 最新版");
            }
        }
        Err(err) => {
            next.phase = UpdateCheckPhase::Failed;
            next.note = format!("检查 ClaudeGuard 更新失败：{err}");
        }
    }
    next
}

fn apply_antigravity_proxy_check<F>(
    prev: &ComponentUpdateStatus,
    ag_proxy: &AntigravityProxyStatus,
    now_secs: u64,
    fetcher: &mut F,
) -> ComponentUpdateStatus
where
    F: FnMut(&str, &[&str]) -> PlatformResult<GithubReleaseInfo>,
{
    let installed_ver = ag_proxy
        .injector_version
        .as_deref()
        .map(normalize_version)
        .filter(|s| !s.is_empty());

    let mut next = prev.clone();
    next.id = "antigravity_proxy".to_string();
    next.name = "antigravity-proxy 注入器".to_string();
    next.repo = ANTIGRAVITY_PROXY_REPO.to_string();
    next.installed_version = installed_ver.clone();
    next.checked_at = Some(now_secs);

    if !ag_proxy.installed {
        next.phase = UpdateCheckPhase::NotInstalled;
        next.note = "本机未检测到反重力客户端".to_string();
        return next;
    }

    match fetcher(ANTIGRAVITY_PROXY_REPO, &[".zip", ".dll"]) {
        Ok(rel) => {
            next.latest_version = Some(rel.version.clone());
            next.release_url = (!rel.html_url.is_empty()).then_some(rel.html_url);
            next.asset_url = rel.asset_url;

            if !ag_proxy.dll_valid || installed_ver.is_none() {
                next.phase = UpdateCheckPhase::UpdateAvailable;
                next.note = format!(
                    "当前未注入或 version.dll 已被覆盖，仓库最新版为 v{}",
                    rel.version
                );
            } else if let Some(ins) = installed_ver.as_deref() {
                if is_version_newer(&rel.version, ins) {
                    next.phase = UpdateCheckPhase::UpdateAvailable;
                    next.note = format!(
                        "发现新版 yuaotian/antigravity-proxy：当前 v{ins} -> 最新 v{}",
                        rel.version
                    );
                } else {
                    next.phase = UpdateCheckPhase::UpToDate;
                    next.note = format!("当前 v{ins} 已是 yuaotian/antigravity-proxy 最新版");
                }
            }
        }
        Err(err) => {
            next.phase = UpdateCheckPhase::Failed;
            next.note = format!("检查 antigravity-proxy 更新失败：{err}");
        }
    }
    next
}

/// Testable orchestrator running update checks via an injected GitHub Release fetcher.
#[allow(clippy::too_many_arguments)]
pub fn check_all_updates_with_fetcher<F>(
    cg_version: &str,
    ag_proxy: &AntigravityProxyStatus,
    claude_msix_ver: Option<String>,
    codex_msix_ver: Option<String>,
    component_filter: Option<&str>,
    prev: &UpdateSummary,
    now_secs: u64,
    mut fetcher: F,
) -> UpdateSummary
where
    F: FnMut(&str, &[&str]) -> PlatformResult<GithubReleaseInfo>,
{
    let mut out = prev.clone();
    ensure_component_defaults(&mut out, cg_version);
    out.claude_msix_version = claude_msix_ver;
    out.codex_msix_version = codex_msix_ver;

    let filter = component_filter
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let check_cg = filter.as_deref().is_none_or(|f| f == "claudeguard");
    let check_ag = filter
        .as_deref()
        .is_none_or(|f| f == "antigravity_proxy" || f == "antigravity-proxy");

    if check_cg {
        out.claudeguard =
            apply_claudeguard_check(&out.claudeguard, cg_version, now_secs, &mut fetcher);
    }
    if check_ag {
        out.antigravity_proxy =
            apply_antigravity_proxy_check(&out.antigravity_proxy, ag_proxy, now_secs, &mut fetcher);
    }

    out
}

/// Full multi-client orchestrator checking ClaudeGuard, `antigravity-proxy`,
/// Claude Desktop, Claude Code CLI, ChatGPT/Codex Desktop, Codex CLI, and Antigravity IDE.
#[allow(clippy::too_many_arguments)]
pub fn check_all_updates_full_with_fetchers<FGh, FClient>(
    cg_version: &str,
    ag_proxy: &AntigravityProxyStatus,
    local: &LocalClientVersions,
    component_filter: Option<&str>,
    prev: &UpdateSummary,
    now_secs: u64,
    mut gh_fetcher: FGh,
    mut client_fetcher: FClient,
) -> UpdateSummary
where
    FGh: FnMut(&str, &[&str]) -> PlatformResult<GithubReleaseInfo>,
    FClient: FnMut(&str) -> PlatformResult<RemoteClientVersion>,
{
    let mut out = prev.clone();
    hydrate_summary_locals(&mut out, cg_version, ag_proxy, local);

    let filter = component_filter
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let matches = |keys: &[&str]| -> bool {
        filter
            .as_deref()
            .is_none_or(|f| keys.contains(&f))
    };

    if matches(&["claudeguard"]) {
        out.claudeguard =
            apply_claudeguard_check(&out.claudeguard, cg_version, now_secs, &mut gh_fetcher);
    }
    if matches(&["antigravity_proxy", "antigravity-proxy", "plugins", "antigravity_plugins"]) {
        out.antigravity_proxy = apply_antigravity_proxy_check(
            &out.antigravity_proxy,
            ag_proxy,
            now_secs,
            &mut gh_fetcher,
        );
    }
    if matches(&["claude_desktop", "claude-desktop", "claude"]) {
        out.claude_desktop = apply_client_update_check(
            &out.claude_desktop,
            "claude_desktop",
            "Claude 桌面端",
            "Anthropic MSIX 官方渠道",
            out.claude_desktop.installed_version.as_deref(),
            now_secs,
            || client_fetcher("claude_desktop"),
        );
    }
    if matches(&["claude_code", "claude-code"]) {
        out.claude_code = apply_client_update_check(
            &out.claude_code,
            "claude_code",
            "Claude Code CLI",
            CLAUDE_CODE_NPM_PKG,
            out.claude_code.installed_version.as_deref(),
            now_secs,
            || client_fetcher("claude_code"),
        );
    }
    if matches(&["codex_desktop", "codex-desktop", "chatgpt"]) {
        out.codex_desktop = apply_client_update_check(
            &out.codex_desktop,
            "codex_desktop",
            "ChatGPT / Codex 桌面端",
            "OpenAI MSIX 官方渠道",
            out.codex_desktop.installed_version.as_deref(),
            now_secs,
            || client_fetcher("codex_desktop"),
        );
    }
    if matches(&["codex_cli", "codex-cli", "codex"]) {
        out.codex_cli = apply_client_update_check(
            &out.codex_cli,
            "codex_cli",
            "Codex CLI",
            CODEX_CLI_NPM_PKG,
            out.codex_cli.installed_version.as_deref(),
            now_secs,
            || client_fetcher("codex_cli"),
        );
    }
    if matches(&["antigravity_ide", "antigravity-ide", "antigravity"]) {
        out.antigravity_ide = apply_client_update_check(
            &out.antigravity_ide,
            "antigravity_ide",
            "Antigravity 客户端",
            "Google 官方更新源",
            out.antigravity_ide.installed_version.as_deref(),
            now_secs,
            || client_fetcher("antigravity_ide"),
        );
    }
    if matches(&[
        "antigravity_cn",
        "antigravity-cn",
        "antigravity-desktop-cn",
        "plugins",
        "antigravity_plugins",
    ]) {
        out.antigravity_cn = apply_client_update_check(
            &out.antigravity_cn,
            "antigravity_cn",
            "Antigravity 中文汉化引擎",
            ANTIGRAVITY_CN_REPO,
            out.antigravity_cn.installed_version.as_deref(),
            now_secs,
            || client_fetcher("antigravity_cn"),
        );
    }
    if matches(&[
        "ag_usage_monitor",
        "antigravity-usage-monitor",
        "usage-monitor",
        "plugins",
        "antigravity_plugins",
    ]) {
        out.ag_usage_monitor = apply_client_update_check(
            &out.ag_usage_monitor,
            "ag_usage_monitor",
            "antigravity-usage-monitor",
            AG_USAGE_MONITOR_REPO,
            out.ag_usage_monitor.installed_version.as_deref(),
            now_secs,
            || client_fetcher("ag_usage_monitor"),
        );
    }
    if matches(&[
        "ag_capsule",
        "agy-capsule",
        "plugins",
        "antigravity_plugins",
    ]) {
        out.ag_capsule = apply_client_update_check(
            &out.ag_capsule,
            "ag_capsule",
            "agy-capsule",
            AG_CAPSULE_REPO,
            out.ag_capsule.installed_version.as_deref(),
            now_secs,
            || client_fetcher("ag_capsule"),
        );
    }

    out
}

/// Live network check across all 7 tracked components strictly honoring `ProbeRoute`.
#[allow(clippy::too_many_arguments)]
pub fn check_all_updates_full(
    route: &ProbeRoute,
    cg_version: &str,
    ag_proxy: &AntigravityProxyStatus,
    local: &LocalClientVersions,
    component_filter: Option<&str>,
    prev: &UpdateSummary,
    now_secs: u64,
) -> UpdateSummary {
    let arch = current_windows_arch();
    let ag_manifest_base = local.antigravity_manifest_base.as_deref();
    check_all_updates_full_with_fetchers(
        cg_version,
        ag_proxy,
        local,
        component_filter,
        prev,
        now_secs,
        |repo, preferred_exts| {
            fetch_github_latest_release(route, repo, preferred_exts, DEFAULT_UPDATE_CHECK_TIMEOUT)
        },
        |component_id| match component_id {
            "claude_desktop" => {
                fetch_claude_desktop_latest(route, arch, DEFAULT_UPDATE_CHECK_TIMEOUT)
            }
            "claude_code" => {
                fetch_npm_latest(route, CLAUDE_CODE_NPM_PKG, DEFAULT_UPDATE_CHECK_TIMEOUT)
            }
            "codex_desktop" => {
                fetch_codex_desktop_latest(route, arch, DEFAULT_UPDATE_CHECK_TIMEOUT)
            }
            "codex_cli" => fetch_npm_latest(route, CODEX_CLI_NPM_PKG, DEFAULT_UPDATE_CHECK_TIMEOUT)
                .or_else(|npm_err| {
                    fetch_github_latest_release(
                        route,
                        CODEX_CLI_REPO,
                        &[".exe", ".zip"],
                        DEFAULT_UPDATE_CHECK_TIMEOUT,
                    )
                    .map(|rel| RemoteClientVersion {
                        version: rel.version,
                        release_url: (!rel.html_url.is_empty()).then_some(rel.html_url),
                        asset_url: rel.asset_url,
                    })
                    .map_err(|_| npm_err)
                }),
            "antigravity_ide" => fetch_antigravity_ide_latest(
                route,
                ag_manifest_base,
                arch,
                DEFAULT_UPDATE_CHECK_TIMEOUT,
            ),
            "antigravity_cn" => fetch_github_latest_release_or_commit(
                route,
                ANTIGRAVITY_CN_REPO,
                &[".zip"],
                DEFAULT_UPDATE_CHECK_TIMEOUT,
            ),
            "ag_usage_monitor" => fetch_github_latest_release_or_commit(
                route,
                AG_USAGE_MONITOR_REPO,
                &[".zip", ".vsix"],
                DEFAULT_UPDATE_CHECK_TIMEOUT,
            ),
            "ag_capsule" => fetch_github_latest_release_or_commit(
                route,
                AG_CAPSULE_REPO,
                &[".zip", ".vsix"],
                DEFAULT_UPDATE_CHECK_TIMEOUT,
            ),
            other => Err(PlatformError::InvalidInput(other.to_string())),
        },
    )
}

/// Check updates across ClaudeGuard and `yuaotian/antigravity-proxy`, plus MSIX versions.
#[allow(clippy::too_many_arguments)]
pub fn check_all_updates(
    route: &ProbeRoute,
    cg_version: &str,
    ag_proxy: &AntigravityProxyStatus,
    claude_msix_ver: Option<String>,
    codex_msix_ver: Option<String>,
    component_filter: Option<&str>,
    prev: &UpdateSummary,
    now_secs: u64,
) -> UpdateSummary {
    let local = LocalClientVersions {
        claude_desktop: claude_msix_ver,
        codex_desktop: codex_msix_ver,
        ..LocalClientVersions::default()
    };
    check_all_updates_full(
        route,
        cg_version,
        ag_proxy,
        &local,
        component_filter,
        prev,
        now_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve_once_capturing_req(
        response: String,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut captured = String::new();
            if let Ok((mut sock, _)) = listener.accept() {
                let mut req = [0u8; 4096];
                if let Ok(n) = sock.read(&mut req) {
                    captured = String::from_utf8_lossy(&req[..n]).into_owned();
                }
                let _ = sock.write_all(response.as_bytes());
            }
            captured
        });
        (addr, handle)
    }

    fn dead_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn semver_comparison_handles_prefixes_segment_lengths_and_prereleases() {
        assert!(is_version_newer("v2.7.0", "2.6.3"));
        assert!(is_version_newer("V2.10.0", "v2.9.9"));
        assert!(!is_version_newer("v2.6.3", "2.6.3"));
        assert!(!is_version_newer("2.6.2", "v2.6.3"));

        // Stable release is newer than pre-release of the same numeric core.
        assert!(is_version_newer("2.7.0", "2.7.0-rc.1"));
        assert!(!is_version_newer("2.7.0-rc.1", "2.7.0"));
        assert!(is_version_newer("2.7.0-rc.2", "2.7.0-rc.1"));
        assert!(is_version_newer("2.7.0-beta.10", "2.7.0-beta.2"));

        // Different numeric segment counts.
        assert!(is_version_newer("4.0.0.1", "4.0.0"));
        assert!(!is_version_newer("4.0", "4.0.0"));
    }

    #[test]
    fn parse_github_latest_release_selects_preferred_non_source_assets() {
        let ag_json = r#"{
            "tag_name": "v2.7.0",
            "html_url": "https://github.com/yuaotian/antigravity-proxy/releases/tag/v2.7.0",
            "published_at": "2026-11-10T12:00:00Z",
            "assets": [
                {
                    "name": "source-code.zip",
                    "browser_download_url": "https://example.invalid/source-code.zip"
                },
                {
                    "name": "antigravity-proxy.sha256",
                    "browser_download_url": "https://example.invalid/antigravity-proxy.sha256"
                },
                {
                    "name": "version.dll",
                    "browser_download_url": "https://example.invalid/version.dll"
                },
                {
                    "name": "antigravity-proxy-windows-x64.zip",
                    "browser_download_url": "https://example.invalid/antigravity-proxy-windows-x64.zip"
                }
            ]
        }"#;
        let parsed_ag = parse_github_latest_release(ag_json, &[".zip", ".dll"]).unwrap();
        assert_eq!(parsed_ag.tag_name, "v2.7.0");
        assert_eq!(parsed_ag.version, "2.7.0");
        assert_eq!(
            parsed_ag.asset_url.as_deref(),
            Some("https://example.invalid/antigravity-proxy-windows-x64.zip")
        );
        assert_eq!(
            parsed_ag.published_at.as_deref(),
            Some("2026-11-10T12:00:00Z")
        );

        let cg_json = r#"{
            "tag_name": "v4.1.0",
            "html_url": "https://github.com/daha1216/ClaudeGuard/releases/tag/v4.1.0",
            "assets": [
                {
                    "name": "ClaudeGuard-v4.1.0-setup.exe",
                    "browser_download_url": "https://example.invalid/ClaudeGuard-v4.1.0-setup.exe"
                },
                {
                    "name": "ClaudeGuard-portable.exe",
                    "browser_download_url": "https://example.invalid/ClaudeGuard-portable.exe"
                }
            ]
        }"#;
        // Requesting -setup.exe prefers installer.
        let setup = parse_github_latest_release(cg_json, &["-setup.exe", ".exe"]).unwrap();
        assert_eq!(
            setup.asset_url.as_deref(),
            Some("https://example.invalid/ClaudeGuard-v4.1.0-setup.exe")
        );
        // Requesting only .exe skips -setup.exe unless requested!
        let portable = parse_github_latest_release(cg_json, &[".exe"]).unwrap();
        assert_eq!(
            portable.asset_url.as_deref(),
            Some("https://example.invalid/ClaudeGuard-portable.exe")
        );
    }

    #[test]
    fn fetch_github_release_enforces_skip_no_direct_fallback_headers_and_rate_limit() {
        // 1. ProbeRoute::Skip never touches sockets.
        let skip_err = fetch_github_latest_from_url(
            &ProbeRoute::Skip("uncovered; direct refused".into()),
            "http://127.0.0.1:1/never",
            &[".zip"],
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(skip_err.to_string().contains("uncovered"));

        // 2. Proxy failure NEVER falls back to direct even when local server is listening.
        let (target_addr, _h_unused) = serve_once_capturing_req(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into(),
        );
        let dead_proxy = ProbeRoute::Proxy(format!("http://127.0.0.1:{}", dead_port()));
        let proxy_err = fetch_github_latest_from_url(
            &dead_proxy,
            &format!("http://{target_addr}/repos/x/y/releases/latest"),
            &[".zip"],
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(
            proxy_err.to_string().contains("放弃直连"),
            "err={proxy_err}"
        );

        // 3. Direct request sends ClaudeGuard/4.0 User-Agent & Accept: application/vnd.github+json.
        let ok_body = r#"{"tag_name":"v2.7.0","html_url":"https://github.com/yuaotian/antigravity-proxy/releases/tag/v2.7.0","assets":[{"name":"version.dll","browser_download_url":"https://example.invalid/version.dll"}]}"#;
        let (ok_addr, ok_h) = serve_once_capturing_req(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ok_body}",
            ok_body.len()
        ));
        let rel = fetch_github_latest_from_url(
            &ProbeRoute::Direct,
            &format!("http://{ok_addr}/latest"),
            &[".dll"],
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(rel.version, "2.7.0");
        assert_eq!(
            rel.asset_url.as_deref(),
            Some("https://example.invalid/version.dll")
        );
        let raw_req = ok_h.join().unwrap();
        let req_l = raw_req.to_ascii_lowercase();
        assert!(req_l.contains("user-agent: claudeguard/4.0"));
        assert!(req_l.contains("accept: application/vnd.github+json"));

        // 4. HTTP 403 / 429 rate-limit mapping and JSON error message extraction.
        let rl_body = r#"{"message":"API rate limit exceeded"}"#;
        let (rl_addr, rl_h) = serve_once_capturing_req(format!(
            "HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rl_body}",
            rl_body.len()
        ));
        let rl_err = fetch_github_latest_from_url(
            &ProbeRoute::Direct,
            &format!("http://{rl_addr}/latest"),
            &[".zip"],
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(rl_err.to_string().contains("GitHub API 限流"));
        rl_h.join().unwrap();

        let err_404 = r#"{"message":"Not Found"}"#;
        let (nf_addr, nf_h) = serve_once_capturing_req(format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{err_404}",
            err_404.len()
        ));
        let nf_err = fetch_github_latest_from_url(
            &ProbeRoute::Direct,
            &format!("http://{nf_addr}/latest"),
            &[".zip"],
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(nf_err.to_string().contains("Not Found"));
        nf_h.join().unwrap();
    }

    #[test]
    fn check_all_updates_orchestrates_all_phases_and_component_filter() {
        let prev = UpdateSummary::default();
        let ag_healthy = AntigravityProxyStatus {
            installed: true,
            dll_present: true,
            dll_valid: true,
            injector_version: Some("2.6.3".into()),
            ..AntigravityProxyStatus::default()
        };

        // 1. Update available for antigravity_proxy, up-to-date for claudeguard.
        let s1 = check_all_updates_with_fetcher(
            "4.0.0",
            &ag_healthy,
            Some("5.1231.2.0".into()),
            Some("26.1111.2228.0".into()),
            None,
            &prev,
            1000,
            |repo, _| match repo {
                CLAUDEGUARD_REPO => Ok(GithubReleaseInfo {
                    tag_name: "v4.0.0".into(),
                    version: "4.0.0".into(),
                    html_url: "https://github.com/daha1216/ClaudeGuard/releases/tag/v4.0.0".into(),
                    asset_url: None,
                    published_at: None,
                }),
                ANTIGRAVITY_PROXY_REPO => Ok(GithubReleaseInfo {
                    tag_name: "v2.7.0".into(),
                    version: "2.7.0".into(),
                    html_url: "https://github.com/yuaotian/antigravity-proxy/releases/tag/v2.7.0"
                        .into(),
                    asset_url: Some("https://example.invalid/ag.zip".into()),
                    published_at: None,
                }),
                other => Err(PlatformError::InvalidInput(other.into())),
            },
        );
        assert_eq!(s1.claude_msix_version.as_deref(), Some("5.1231.2.0"));
        assert_eq!(s1.codex_msix_version.as_deref(), Some("26.1111.2228.0"));
        assert_eq!(s1.claudeguard.phase, UpdateCheckPhase::UpToDate);
        assert_eq!(
            s1.antigravity_proxy.phase,
            UpdateCheckPhase::UpdateAvailable
        );
        assert!(s1.antigravity_proxy.note.contains("v2.6.3 -> 最新 v2.7.0"));

        // 2. Uninjected / invalid version.dll prompts reinstall/update even when version missing.
        let ag_unhooked = AntigravityProxyStatus {
            installed: true,
            dll_present: false,
            dll_valid: false,
            injector_version: None,
            ..AntigravityProxyStatus::default()
        };
        let s2 = check_all_updates_with_fetcher(
            "4.0.0",
            &ag_unhooked,
            None,
            None,
            Some("antigravity_proxy"),
            &s1,
            2000,
            |repo, _| {
                assert_eq!(repo, ANTIGRAVITY_PROXY_REPO);
                Ok(GithubReleaseInfo {
                    tag_name: "v2.7.0".into(),
                    version: "2.7.0".into(),
                    html_url: "https://github.com/yuaotian/antigravity-proxy/releases/tag/v2.7.0"
                        .into(),
                    asset_url: None,
                    published_at: None,
                })
            },
        );
        assert_eq!(s2.claudeguard.checked_at, Some(1000)); // filtered out, preserved!
        assert_eq!(
            s2.antigravity_proxy.phase,
            UpdateCheckPhase::UpdateAvailable
        );
        assert!(s2
            .antigravity_proxy
            .note
            .contains("当前未注入或 version.dll 已被覆盖"));

        // 3. NotInstalled antigravity returns NotInstalled without hitting network.
        let ag_absent = AntigravityProxyStatus::default();
        let s3 = check_all_updates_with_fetcher(
            "4.0.0",
            &ag_absent,
            None,
            None,
            Some("antigravity_proxy"),
            &s2,
            3000,
            |_, _| panic!("should not query network when Antigravity is not installed"),
        );
        assert_eq!(s3.antigravity_proxy.phase, UpdateCheckPhase::NotInstalled);
        assert_eq!(s3.antigravity_proxy.note, "本机未检测到反重力客户端");

        // 4. Fetch failure preserves installed_version and sets Failed phase.
        let s4 = check_all_updates_with_fetcher(
            "4.0.0",
            &ag_healthy,
            None,
            None,
            Some("antigravity_proxy"),
            &s1,
            4000,
            |_, _| {
                Err(PlatformError::Network(
                    "GitHub API 限流，稍后自动重试".into(),
                ))
            },
        );
        assert_eq!(s4.antigravity_proxy.phase, UpdateCheckPhase::Failed);
        assert_eq!(
            s4.antigravity_proxy.installed_version.as_deref(),
            Some("2.6.3")
        );
        assert!(s4.antigravity_proxy.note.contains("GitHub API 限流"));
    }

    #[test]
    fn parses_all_client_feeds_and_orchestrates_full_matrix() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        let loc = format!("https://downloads.claude.ai/releases/win32/x64/1.0.214/Claude-{hash}.msix");
        assert_eq!(
            parse_claude_desktop_redirect(&loc, "x64").unwrap(),
            "1.0.214"
        );
        assert!(parse_claude_desktop_redirect("https://evil.invalid/Claude.msix", "x64").is_err());

        let npm_res = parse_npm_latest_version(
            r#"{"name":"@anthropic-ai/claude-code","version":"2.1.320","dist":{"tarball":"https://registry.npmjs.org/t.tgz"}}"#,
            "@anthropic-ai/claude-code",
        )
        .unwrap();
        assert_eq!(npm_res.version, "2.1.320");
        assert_eq!(
            npm_res.asset_url.as_deref(),
            Some("https://registry.npmjs.org/t.tgz")
        );

        let ag_yaml = "version: 2.34.0\npath: Antigravity-x64.exe\nsha512: abc\n";
        let ag_res = parse_antigravity_yaml_latest(ag_yaml, "https://example.invalid/manifest").unwrap();
        assert_eq!(ag_res.version, "2.34.0");
        assert_eq!(
            ag_res.asset_url.as_deref(),
            Some("https://example.invalid/manifest/Antigravity-x64.exe")
        );

        assert_eq!(normalize_version("rust-v0.160.0"), "0.160.0");

        // Codex Desktop HEAD server test
        let (addr, h) = serve_once_capturing_req(
            "HTTP/1.1 200 OK\r\nx-ms-meta-package_identity: OpenAI.Codex\r\nx-ms-meta-architecture: x64\r\nx-ms-meta-package_version: 26.1200.5.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        );
        let codex_head = fetch_codex_desktop_latest_from_url(
            &ProbeRoute::Direct,
            &format!("http://{addr}/ChatGPT-x64.msix"),
            "x64",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(codex_head.version, "26.1200.5.0");
        h.join().unwrap();

        let local = LocalClientVersions {
            claude_desktop: Some("1.0.100".into()),
            claude_code: Some("2.1.308".into()),
            codex_desktop: Some("26.1111.2228.0".into()),
            codex_cli: None,
            antigravity_ide: Some("2.33.0".into()),
            antigravity_manifest_base: None,
            antigravity_cn: Some("2026.03.15".into()),
            ag_usage_monitor: Some("1.5.3".into()),
            ag_capsule: Some("1.1.2".into()),
        };
        let ag_healthy = AntigravityProxyStatus {
            installed: true,
            dll_present: true,
            dll_valid: true,
            injector_version: Some("2.6.3".into()),
            ..AntigravityProxyStatus::default()
        };
        let summary = check_all_updates_full_with_fetchers(
            "4.0.0",
            &ag_healthy,
            &local,
            None,
            &UpdateSummary::default(),
            5000,
            |repo, _| Ok(GithubReleaseInfo {
                tag_name: match repo {
                    CLAUDEGUARD_REPO => "v4.0.0".into(),
                    _ => "v2.6.3".into(),
                },
                version: match repo {
                    CLAUDEGUARD_REPO => "4.0.0".into(),
                    _ => "2.6.3".into(),
                },
                html_url: String::new(),
                asset_url: None,
                published_at: None,
            }),
            |cid| match cid {
                "claude_desktop" => Ok(RemoteClientVersion { version: "1.0.214".into(), release_url: None, asset_url: None }),
                "claude_code" => Ok(RemoteClientVersion { version: "2.1.320".into(), release_url: None, asset_url: None }),
                "codex_desktop" => Ok(RemoteClientVersion { version: "26.1111.2228.0".into(), release_url: None, asset_url: None }),
                "codex_cli" => Ok(RemoteClientVersion { version: "0.160.0".into(), release_url: None, asset_url: None }),
                "antigravity_ide" => Ok(RemoteClientVersion { version: "2.34.0".into(), release_url: None, asset_url: None }),
                "antigravity_cn" => Ok(RemoteClientVersion { version: "2026.03.19".into(), release_url: None, asset_url: None }),
                "ag_usage_monitor" => Ok(RemoteClientVersion { version: "1.6.0".into(), release_url: None, asset_url: None }),
                "ag_capsule" => Ok(RemoteClientVersion { version: "1.1.2".into(), release_url: None, asset_url: None }),
                other => Err(PlatformError::InvalidInput(other.into())),
            },
        );
        assert_eq!(summary.claude_desktop.phase, UpdateCheckPhase::UpdateAvailable);
        assert_eq!(summary.claude_code.phase, UpdateCheckPhase::UpdateAvailable);
        assert_eq!(summary.codex_desktop.phase, UpdateCheckPhase::UpToDate);
        assert_eq!(summary.codex_cli.phase, UpdateCheckPhase::NotInstalled);
        assert_eq!(summary.antigravity_ide.phase, UpdateCheckPhase::UpdateAvailable);
        assert_eq!(summary.antigravity_cn.phase, UpdateCheckPhase::UpdateAvailable);
        assert_eq!(summary.ag_usage_monitor.phase, UpdateCheckPhase::UpdateAvailable);
        assert_eq!(summary.ag_capsule.phase, UpdateCheckPhase::UpToDate);
        assert!(ANTIGRAVITY_PROXY_DESC.contains("免 TUN 强制代理工具"));

        let commit = parse_github_latest_commit(
            r#"[{"sha":"abcdef123456","html_url":"https://github.com/Silas-02/antigravity-desktop-cn/commit/abcdef1","commit":{"committer":{"date":"2026-03-19T08:30:00Z"}}}]"#,
            ANTIGRAVITY_CN_REPO,
        )
        .unwrap();
        assert_eq!(commit.version, "2026.03.19");
        assert!(is_version_newer(&commit.version, "2026.03.15"));
    }
}
