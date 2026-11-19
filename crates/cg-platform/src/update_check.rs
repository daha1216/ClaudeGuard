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
/// Default HTTP timeout for GitHub Release API checks.
pub const DEFAULT_UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Trim whitespace and leading `'v'` / `'V'` prefix from a version string.
pub fn normalize_version(raw: &str) -> String {
    raw.trim().trim_start_matches(['v', 'V']).trim().to_string()
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
    let agent = match route {
        ProbeRoute::Skip(reason) => return Err(PlatformError::Network(reason.clone())),
        ProbeRoute::Proxy(proxy_url) => {
            let proxy = ureq::Proxy::new(proxy_url).map_err(|e| {
                PlatformError::Network(proxy_required_error(&format!("代理地址无效：{e}")))
            })?;
            ureq::AgentBuilder::new()
                .timeout_connect(timeout)
                .timeout(timeout)
                .redirects(MAX_PROBE_REDIRECTS)
                .try_proxy_from_env(false)
                .user_agent(PROBE_USER_AGENT)
                .proxy(proxy)
                .build()
        }
        ProbeRoute::Direct => ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout(timeout)
            .redirects(MAX_PROBE_REDIRECTS)
            .try_proxy_from_env(false)
            .user_agent(PROBE_USER_AGENT)
            .build(),
    };

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
        Err(err) => {
            let detail = err.to_string();
            Err(PlatformError::Network(match route {
                ProbeRoute::Proxy(_) => proxy_required_error(&detail),
                _ => detail,
            }))
        }
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

fn ensure_component_defaults(summary: &mut UpdateSummary, cg_version: &str) {
    if summary.claudeguard.id.is_empty() {
        summary.claudeguard.id = "claudeguard".to_string();
    }
    if summary.claudeguard.name.is_empty() {
        summary.claudeguard.name = "ClaudeGuard 主程序".to_string();
    }
    if summary.claudeguard.repo.is_empty() {
        summary.claudeguard.repo = CLAUDEGUARD_REPO.to_string();
    }
    summary.claudeguard.installed_version = Some(normalize_version(cg_version));

    if summary.antigravity_proxy.id.is_empty() {
        summary.antigravity_proxy.id = "antigravity_proxy".to_string();
    }
    if summary.antigravity_proxy.name.is_empty() {
        summary.antigravity_proxy.name = "antigravity-proxy 注入器".to_string();
    }
    if summary.antigravity_proxy.repo.is_empty() {
        summary.antigravity_proxy.repo = ANTIGRAVITY_PROXY_REPO.to_string();
    }
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
    check_all_updates_with_fetcher(
        cg_version,
        ag_proxy,
        claude_msix_ver,
        codex_msix_ver,
        component_filter,
        prev,
        now_secs,
        |repo, preferred_exts| {
            fetch_github_latest_release(route, repo, preferred_exts, DEFAULT_UPDATE_CHECK_TIMEOUT)
        },
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
}
