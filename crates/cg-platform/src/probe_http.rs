//! Unified `NetworkPolicy` HTTP probe & GitHub Release 302 allowlisted downloader.
//!
//! Security & privacy invariants (R14 / D5 / v3.12.2):
//! - Always sets `.try_proxy_from_env(false)` so routing is 100% deterministic.
//! - When a proxy is configured, NEVER silently falls back to direct connections.
//! - NEVER probes directly when `AccessPath` is `Uncovered` or `Unknown`.
//! - Release artifact downloads run with `redirects(0)` and manually validate every
//!   3xx `Location` hop against `DOWNLOAD_REDIRECT_HOSTS` (`https://` only).

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::access_win::AccessPath;
use crate::traits::{PlatformError, PlatformResult};

/// Default maximum HTTP probe body size (3 MiB).
pub const MAX_PROBE_BODY_BYTES: usize = 3 * 1024 * 1024;
/// Maximum HTTP redirects allowed during anchor probes.
pub const MAX_PROBE_REDIRECTS: u32 = 5;
/// Maximum manual 302 hops during artifact download.
pub const MAX_DOWNLOAD_REDIRECTS: usize = 5;
/// Hard safety limit on downloaded release artifacts (128 MiB).
pub const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
/// Probe HTTP User-Agent.
pub const PROBE_USER_AGENT: &str = "ClaudeGuard/4.0";

/// Strict host allowlist for GitHub Release artifact 302 redirects.
pub const DOWNLOAD_REDIRECT_HOSTS: [&str; 3] = [
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

/// Network routing decision derived from `NetworkPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Proxy(String),
    Direct,
}

/// Outbound traffic intent determining proxy usage and redirect rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressIntent {
    Probe,
    UpdateCheck,
    UpdateDownload,
    ClientCheck,
    /// Notification webhook credentials always connect directly without reading monitored proxy.
    Notify,
}

/// Unified outbound HTTP policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub proxy_host: String,
    pub proxy_port: u16,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 7890,
        }
    }
}

/// Strip any leading proxy scheme (`http://`, `https://`, `socks5://`, `socks5h://`) and trailing
/// path/slash so callers never produce `http://http://...` double-scheme URLs.
fn strip_proxy_scheme_and_path(raw: &str) -> &str {
    let mut s = raw.trim();
    loop {
        let matched = ["socks5h://", "socks5://", "https://", "http://"]
            .into_iter()
            .find(|scheme| {
                s.get(..scheme.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
            });
        if let Some(scheme) = matched {
            s = s[scheme.len()..].trim_start();
        } else {
            break;
        }
    }
    s.split('/').next().unwrap_or("").trim()
}

/// Strip leading scheme, trailing `/`, and any `:port` suffix from a `proxy_host` value.
fn sanitize_proxy_host(raw: &str) -> &str {
    let s = strip_proxy_scheme_and_path(raw);
    if s.starts_with('[') {
        if let Some((bracketed, port_part)) = s.rsplit_once(':') {
            if bracketed.ends_with(']') && port_part.bytes().all(|b| b.is_ascii_digit()) {
                return bracketed.trim();
            }
        }
        return s;
    }
    if let Some((host_part, port_part)) = s.rsplit_once(':') {
        if !host_part.contains(':') && port_part.bytes().all(|b| b.is_ascii_digit()) {
            return host_part.trim();
        }
    }
    s
}

impl NetworkPolicy {
    pub fn direct() -> Self {
        Self {
            proxy_host: String::new(),
            proxy_port: 0,
        }
    }

    pub fn with_proxy(host: impl Into<String>, port: u16) -> Self {
        Self {
            proxy_host: host.into(),
            proxy_port: port,
        }
    }

    /// Resolve the deterministic route from policy settings.
    pub fn route(&self) -> Route {
        let host = sanitize_proxy_host(&self.proxy_host);
        if host.is_empty() || self.proxy_port == 0 {
            Route::Direct
        } else {
            Route::Proxy(format!("http://{host}:{port}", port = self.proxy_port))
        }
    }
}

/// Probe routing decision tied to observed OS `AccessPath`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeRoute {
    Proxy(String),
    Direct,
    /// Uncovered / Unknown access path -> refuse outbound probe so home IP is never leaked.
    Skip(String),
}

/// Determine probe route purely from `AccessPath` (never probes directly on `Uncovered`/`Unknown`).
pub fn plan_probe_route(access: &AccessPath) -> ProbeRoute {
    match access {
        AccessPath::SystemProxy { addr } => {
            let cleaned = strip_proxy_scheme_and_path(addr);
            ProbeRoute::Proxy(format!("http://{cleaned}"))
        }
        AccessPath::Tun { .. } => ProbeRoute::Direct,
        AccessPath::Uncovered => {
            ProbeRoute::Skip("未开启系统代理且未检测到 TUN 网卡，已拒绝直连".to_string())
        }
        AccessPath::Unknown { reason } => ProbeRoute::Skip(format!("接入路径未确认：{reason}")),
    }
}

/// Uniform error message stating no silent direct fallback occurred.
pub fn proxy_required_error(detail: &str) -> String {
    format!("代理不可用（{detail}）；已按外发策略放弃直连，避免暴露真实出口")
}

/// Strictly validate a 302 download redirect URL: HTTPS only and host in `DOWNLOAD_REDIRECT_HOSTS`.
pub fn redirect_allowed(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    DOWNLOAD_REDIRECT_HOSTS.contains(&host)
}

/// Build a `ureq::Agent` enforcing `NetworkPolicy` and `EgressIntent`.
pub fn build_client(
    policy: &NetworkPolicy,
    intent: EgressIntent,
    timeout: Duration,
) -> PlatformResult<ureq::Agent> {
    let mut builder = ureq::AgentBuilder::new()
        .max_idle_connections(0)
        .timeout_connect(timeout)
        .try_proxy_from_env(false)
        .user_agent(PROBE_USER_AGENT);

    match intent {
        EgressIntent::Notify => {
            return Ok(builder
                .redirects(0)
                .timeout_read(timeout)
                .timeout(timeout)
                .build());
        }
        EgressIntent::Probe => {
            builder = builder
                .redirects(MAX_PROBE_REDIRECTS)
                .timeout_read(timeout)
                .timeout(timeout);
        }
        EgressIntent::UpdateCheck => {
            builder = builder.redirects(0).timeout_read(timeout).timeout(timeout);
        }
        EgressIntent::UpdateDownload => {
            builder = builder
                .redirects(0)
                .timeout_connect(Duration::from_secs(15))
                .timeout_read(timeout)
                .timeout(Duration::from_secs(600));
        }
        EgressIntent::ClientCheck => {
            builder = builder
                .redirects(0)
                .max_idle_connections(0)
                .timeout_read(Duration::from_secs(45))
                .timeout(Duration::from_secs(600));
        }
    }

    match policy.route() {
        Route::Proxy(proxy_url) => match ureq::Proxy::new(&proxy_url) {
            Ok(proxy) => Ok(builder.proxy(proxy).build()),
            Err(err) => Err(PlatformError::Network(proxy_required_error(&format!(
                "代理地址无效：{err}"
            )))),
        },
        Route::Direct => Ok(builder.build()),
    }
}

/// Raw HTTP probe response (HTTP 2xx/4xx/5xx all count as reachable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProbeResponse {
    pub status: u16,
    pub body: String,
    pub latency_ms: u64,
}

/// Execute an HTTP GET probe honoring `ProbeRoute`.
///
/// Immediately refuses `ProbeRoute::Skip` without issuing any socket calls.
pub fn probe_url(
    route: &ProbeRoute,
    url: &str,
    timeout: Duration,
    max_body_bytes: usize,
) -> PlatformResult<HttpProbeResponse> {
    let connect_timeout = timeout.min(Duration::from_secs(5));
    let agent = match route {
        ProbeRoute::Skip(reason) => return Err(PlatformError::Network(reason.clone())),
        ProbeRoute::Proxy(proxy_url) => {
            let proxy = ureq::Proxy::new(proxy_url).map_err(|e| {
                PlatformError::Network(proxy_required_error(&format!("代理地址无效：{e}")))
            })?;
            ureq::AgentBuilder::new()
                .max_idle_connections(0)
                .timeout_connect(connect_timeout)
                .timeout_read(timeout)
                .timeout(timeout)
                .redirects(MAX_PROBE_REDIRECTS)
                .try_proxy_from_env(false)
                .user_agent(PROBE_USER_AGENT)
                .proxy(proxy)
                .build()
        }
        ProbeRoute::Direct => ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout_connect(connect_timeout)
            .timeout_read(timeout)
            .timeout(timeout)
            .redirects(MAX_PROBE_REDIRECTS)
            .try_proxy_from_env(false)
            .user_agent(PROBE_USER_AGENT)
            .build(),
    };

    let started = Instant::now();
    let resp = match agent.get(url).timeout(timeout).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(err) => {
            let detail = err.to_string();
            return Err(PlatformError::Network(match route {
                ProbeRoute::Proxy(_) => proxy_required_error(&detail),
                _ => detail,
            }));
        }
    };

    let status = resp.status();
    let mut buf = Vec::new();
    if let Err(io_err) = resp
        .into_reader()
        .take(max_body_bytes as u64)
        .read_to_end(&mut buf)
    {
        if buf.is_empty() {
            let detail = format!("读取响应体失败：{io_err}");
            return Err(PlatformError::Network(match route {
                ProbeRoute::Proxy(_) => proxy_required_error(&detail),
                _ => detail,
            }));
        }
    }
    let body = String::from_utf8_lossy(&buf).into_owned();
    Ok(HttpProbeResponse {
        status,
        body,
        latency_ms: started.elapsed().as_millis() as u64,
    })
}

/// Summary returned after streaming and SHA-256 hashing a release artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadSummary {
    pub final_url: String,
    pub bytes_written: u64,
    pub sha256_hex: String,
    pub hops: usize,
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Download a GitHub Release artifact through `NetworkPolicy`, manually following 302 redirects
/// ONLY to `DOWNLOAD_REDIRECT_HOSTS` (`https://`). Never falls back to direct when a proxy is set.
pub fn download_release_asset(
    policy: &NetworkPolicy,
    url: &str,
    expected_size: Option<u64>,
    max_bytes: u64,
    timeout: Duration,
    writer: &mut dyn Write,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> PlatformResult<DownloadSummary> {
    download_with_redirect_policy(
        policy,
        url,
        expected_size,
        max_bytes,
        timeout,
        redirect_allowed,
        writer,
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn download_with_redirect_policy<FAllow>(
    policy: &NetworkPolicy,
    url: &str,
    expected_size: Option<u64>,
    max_bytes: u64,
    timeout: Duration,
    allow_redirect: FAllow,
    writer: &mut dyn Write,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> PlatformResult<DownloadSummary>
where
    FAllow: Fn(&str) -> bool,
{
    let agent = build_client(policy, EgressIntent::UpdateDownload, timeout)?;
    let hard_limit = max_bytes.min(MAX_ARTIFACT_BYTES);
    let effective_limit = match expected_size {
        Some(exp) if exp > 0 => exp.min(hard_limit),
        _ => hard_limit,
    };

    let mut current = url.to_string();
    let mut hops = 0usize;
    let resp = loop {
        let resp = match agent.get(&current).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) if (300..400).contains(&code) => r,
            Err(err) => {
                let msg = err.to_string();
                return Err(PlatformError::Network(match policy.route() {
                    Route::Proxy(_) => proxy_required_error(&msg),
                    Route::Direct => msg,
                }));
            }
        };
        let code = resp.status();
        if (300..400).contains(&code) {
            if hops >= MAX_DOWNLOAD_REDIRECTS {
                return Err(PlatformError::Network(
                    "下载失败：重定向次数过多".to_string(),
                ));
            }
            let location = resp.header("location").unwrap_or("").trim().to_string();
            if location.is_empty() {
                return Err(PlatformError::Network(format!(
                    "下载失败：HTTP {code} 重定向缺少 Location"
                )));
            }
            if !allow_redirect(&location) {
                return Err(PlatformError::Network(format!(
                    "下载失败：重定向到未授权主机（{}），已拒绝",
                    location.split('?').next().unwrap_or(&location)
                )));
            }
            current = location;
            hops += 1;
            continue;
        }
        if !(200..300).contains(&code) {
            return Err(PlatformError::Network(format!("下载失败：HTTP {code}")));
        }
        break resp;
    };

    let mut reader = resp.into_reader();
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut chunk = [0u8; 65_536];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| PlatformError::Io(format!("读取下载流失败：{e}")))?;
        if n == 0 {
            break;
        }
        written = written.saturating_add(n as u64);
        if written > effective_limit {
            return Err(PlatformError::Network(format!(
                "更新包超过大小限制（{effective_limit} 字节），已中止"
            )));
        }
        hasher.update(&chunk[..n]);
        writer
            .write_all(&chunk[..n])
            .map_err(|e| PlatformError::Io(format!("写入下载目标失败：{e}")))?;
        progress(written, expected_size);
    }

    if let Some(exp) = expected_size.filter(|&e| e > 0) {
        if written != exp {
            return Err(PlatformError::Network(format!(
                "大小不符：期望 {exp}，实得 {written}"
            )));
        }
    }

    Ok(DownloadSummary {
        final_url: current,
        bytes_written: written,
        sha256_hex: hex_lower(&hasher.finalize()),
        hops,
    })
}

/// Send a JSON webhook notification (e.g., Feishu / Lark) through `NetworkPolicy` using
/// `EgressIntent::Notify` (direct domestic egress by default, zero unexpected proxy dependency).
pub fn post_json_notify(
    policy: &NetworkPolicy,
    url: &str,
    payload: &serde_json::Value,
    timeout: Duration,
) -> PlatformResult<(u16, String)> {
    let agent = build_client(policy, EgressIntent::Notify, timeout)?;
    let body_str = serde_json::to_string(payload)
        .map_err(|e| PlatformError::InvalidInput(format!("序列化通知 JSON 失败：{e}")))?;
    match agent
        .post(url)
        .set("Content-Type", "application/json; charset=utf-8")
        .set("User-Agent", "ClaudeGuard/4.0")
        .timeout(timeout)
        .send_string(&body_str)
    {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.into_string().unwrap_or_default();
            Ok((status, text))
        }
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            Ok((code, text))
        }
        Err(err) => Err(PlatformError::Network(format!("通知请求发送失败：{err}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn dead_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn serve_once(response: String) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut req = [0u8; 4096];
                let _ = sock.read(&mut req);
                let _ = sock.write_all(response.as_bytes());
            }
        });
        (addr, handle)
    }

    #[test]
    fn uncovered_and_unknown_access_refuse_direct_probe() {
        let uncovered_route = plan_probe_route(&AccessPath::Uncovered);
        assert_eq!(
            uncovered_route,
            ProbeRoute::Skip("未开启系统代理且未检测到 TUN 网卡，已拒绝直连".into())
        );
        let unknown_route = plan_probe_route(&AccessPath::Unknown {
            reason: "PAC".into(),
        });
        assert_eq!(
            unknown_route,
            ProbeRoute::Skip("接入路径未确认：PAC".into())
        );
        assert_eq!(
            plan_probe_route(&AccessPath::Tun {
                adapter: "Mihomo".into()
            }),
            ProbeRoute::Direct
        );
        assert_eq!(
            plan_probe_route(&AccessPath::SystemProxy {
                addr: "127.0.0.1:7890".into()
            }),
            ProbeRoute::Proxy("http://127.0.0.1:7890".into())
        );
        assert_eq!(
            plan_probe_route(&AccessPath::SystemProxy {
                addr: "http://198.51.100.10:7890/".into()
            }),
            ProbeRoute::Proxy("http://198.51.100.10:7890".into())
        );

        let err = probe_url(
            &uncovered_route,
            "http://127.0.0.1:1/never",
            Duration::from_secs(1),
            1024,
        )
        .unwrap_err();
        assert!(err.to_string().contains("未开启系统代理"));
        assert!(err.to_string().contains("已拒绝直连"));
    }

    #[test]
    fn network_policy_route_strips_double_schemes_ports_and_slashes() {
        assert_eq!(NetworkPolicy::direct().route(), Route::Direct);
        assert_eq!(
            NetworkPolicy::with_proxy("http://", 7890).route(),
            Route::Direct
        );
        assert_eq!(
            NetworkPolicy::with_proxy("198.51.100.10", 0).route(),
            Route::Direct
        );
        for raw_host in [
            "198.51.100.10",
            "http://198.51.100.10",
            "HTTP://http://198.51.100.10/",
            "https://198.51.100.10:8080/",
            "socks5://198.51.100.10:10808",
            "socks5h://198.51.100.10:10809/",
            "  http://198.51.100.10:7890/  ",
        ] {
            assert_eq!(
                NetworkPolicy::with_proxy(raw_host, 7890).route(),
                Route::Proxy("http://198.51.100.10:7890".into()),
                "failed for input: {raw_host}"
            );
        }
        assert_eq!(
            NetworkPolicy::with_proxy("http://[::1]:1080/", 7890).route(),
            Route::Proxy("http://[::1]:7890".into())
        );
    }

    #[test]
    fn configured_proxy_never_falls_back_to_direct_on_failure() {
        // Real local target is listening, but configured proxy port is dead -> MUST fail!
        let (target_addr, _h) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into());
        let policy = NetworkPolicy::with_proxy("127.0.0.1", dead_port());
        let err = download_release_asset(
            &policy,
            &format!("http://{target_addr}/asset.exe"),
            None,
            1024 * 1024,
            Duration::from_secs(2),
            &mut Vec::new(),
            &mut |_, _| {},
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("代理不可用"), "msg={msg}");
        assert!(msg.contains("放弃直连"), "msg={msg}");
    }

    #[test]
    fn notify_intent_ignores_proxy_and_connects_directly() {
        let (addr, handle) = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into(),
        );
        let policy = NetworkPolicy::with_proxy("127.0.0.1", dead_port());
        let client = build_client(&policy, EgressIntent::Notify, Duration::from_secs(3)).unwrap();
        let resp = client.get(&format!("http://{addr}/hook")).call().unwrap();
        assert_eq!(resp.status(), 200);
        handle.join().unwrap();
    }

    #[test]
    fn redirect_allowlist_permits_only_https_github_asset_hosts() {
        assert!(redirect_allowed(
            "https://release-assets.githubusercontent.com/a/b?sig=1"
        ));
        assert!(redirect_allowed("https://objects.githubusercontent.com/x"));
        assert!(redirect_allowed(
            "https://GITHUB-RELEASES.githubusercontent.com/y"
        ));

        // Reject plaintext http, evil subdomains, non-asset GitHub hosts, and relative paths.
        assert!(!redirect_allowed(
            "http://release-assets.githubusercontent.com/a/b"
        ));
        assert!(!redirect_allowed("https://evil.example/a"));
        assert!(!redirect_allowed(
            "https://release-assets.githubusercontent.com.evil.example/a"
        ));
        assert!(!redirect_allowed("https://raw.githubusercontent.com/a"));
        assert!(!redirect_allowed("/relative/path"));
    }

    #[test]
    fn download_follows_allowed_302_and_rejects_disallowed_302() {
        // 1. Disallowed 302 under production `redirect_allowed`: must fail!
        let (redirect_addr, h1) = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: https://evil.example/payload.exe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        );
        let mut sink = Vec::new();
        let err = download_release_asset(
            &NetworkPolicy::direct(),
            &format!("http://{redirect_addr}/release.exe"),
            None,
            1024,
            Duration::from_secs(3),
            &mut sink,
            &mut |_, _| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("未授权主机"), "err={err}");
        assert!(sink.is_empty());
        h1.join().unwrap();

        // 2. Allowed 302 hop (simulated allowlist matching local destination) streams bytes + SHA-256!
        let (asset_addr, h_asset) = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello-v4-ok".into(),
        );
        let asset_url = format!("http://{asset_addr}/asset.bin");
        let (redir_addr, h_redir) = serve_once(format!(
            "HTTP/1.1 302 Found\r\nLocation: {asset_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ));

        let mut downloaded = Vec::new();
        let mut last_progress = 0u64;
        let expected_url = asset_url.clone();
        let summary = download_with_redirect_policy(
            &NetworkPolicy::direct(),
            &format!("http://{redir_addr}/latest"),
            Some(11),
            1024,
            Duration::from_secs(3),
            move |loc| loc == expected_url,
            &mut downloaded,
            &mut |n, _| last_progress = n,
        )
        .unwrap();

        assert_eq!(downloaded, b"hello-v4-ok");
        assert_eq!(summary.bytes_written, 11);
        assert_eq!(summary.hops, 1);
        assert_eq!(summary.final_url, asset_url);
        assert_eq!(last_progress, 11);
        assert_eq!(summary.sha256_hex.len(), 64);

        h_redir.join().unwrap();
        h_asset.join().unwrap();
    }

    #[test]
    fn probe_url_treats_http_403_as_reachable_via_proxy() {
        let (proxy_addr, h) = serve_once(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\nConnection: close\r\n\r\nedge-denied"
                .into(),
        );
        let route = ProbeRoute::Proxy(format!("http://127.0.0.1:{}", proxy_addr.port()));
        let resp = probe_url(
            &route,
            "http://example.invalid/ping",
            Duration::from_secs(3),
            1024,
        )
        .unwrap();
        assert_eq!(resp.status, 403);
        assert_eq!(resp.body, "edge-denied");
        h.join().unwrap();
    }
}
