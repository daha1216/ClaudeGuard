//! R14 / D5：统一的出网策略。
//!
//! 规则只有一条，但它必须被所有模块共享：**有代理配置时一律走代理；代理不可用
//! 就失败并如实报告，绝不静默直连回退**。守护器自身的流量一旦直连，就会带着
//! 家宽 IP 出现在 GitHub / 飞书 / 更新源上，这正是要防的泄漏。
//!
//! 探测（anchors）是"允许直连"的场景之一：它本来就是按 TUN/直连模式去测真实
//! 出口的，且由调用方显式传 `None` 表达这个意图，不属于"回退"；飞书凭据
//! （[`EgressIntent::Notify`]）同理，直连是刻意的，由意图显式表达。
//!
//! 出网 Agent 一律经 [`client`] 按 [`EgressIntent`] 构造（AGENTS.md 模块地图
//! 禁止清单）：新建出网 Agent 只允许在本文件。

use crate::config::Config;

/// 出网方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// 经用户配置的代理（默认）。
    Proxy(String),
    /// 直连。只有探测在 TUN 接管时显式要求，以及用户配置里没有代理时才会出现。
    Direct,
}

/// 依据配置决定出网方式。
///
/// 没有配置代理地址时返回 `Direct`——这不是"回退"，而是用户从未配置代理，
/// 此时守护器不掌握任何代理信息，不能凭空造一个。
pub fn route(cfg: &Config) -> Route {
    let host = cfg.proxy_host.trim();
    let port = cfg.proxy_port;
    if host.is_empty() || port == 0 {
        return Route::Direct;
    }
    Route::Proxy(format!("http://{host}:{port}"))
}

/// 出网意图：调用点必须显式说明"这条流量是谁发的、允许怎么走"。
///
/// 统一入口 [`client`] 按意图决定直连/代理与重定向策略，让"走不走监控代理"
/// 这种关键语义在调用点可见，而不是散落在各模块里靠注释维护。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressIntent {
    /// 检查 ClaudeGuard 自身更新（GitHub API）：走代理，`redirects(0)`。
    UpdateCheck,
    /// 下载 ClaudeGuard 更新制品：走代理，`redirects(0)`，
    /// 302 由调用方按 [`DOWNLOAD_REDIRECT_HOSTS`] 白名单手动逐跳。
    UpdateDownload,
    /// Claude/Codex 桌面客户端更新：走代理，`redirects(0)`，保留其既有超时与不复用连接的语义。
    ClientCheck,
    /// 对外通知（飞书 Webhook 等）：**凭据不走监控代理，恒直连**，不读任何代理配置。
    Notify,
}

/// 统一出网入口：全仓出网 Agent 只允许从这里构造（见 AGENTS.md 模块地图禁止清单）。
///
/// 共同语义（与原 [`agent`] / [`download_agent`] 完全一致）：
/// - 有代理配置走代理；没配置就是 `Direct`——用户从未配置代理，不是"回退"；
/// - 显式 `try_proxy_from_env(false)`：实际走了哪条路必须是确定的；
/// - `redirects(0)`：重定向一律不跟，除非该意图的调用方自己按白名单逐跳。
///
/// `timeout` 的语义随意图：`Notify` 是整体超时（凭据请求必须有硬上限），
/// 其余是连接超时（`ClientCheck` 另带自身的读/整体超时默认值）。
pub fn client(
    cfg: &Config,
    intent: EgressIntent,
    timeout: std::time::Duration,
) -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        // 不让 ureq 自己从环境变量猜代理：实际走了哪条路必须是确定的。
        .try_proxy_from_env(false)
        // 外发请求只认官方地址，重定向一律不跟（防止被引到别的主机）。
        .redirects(0);
    match intent {
        // 凭据不走监控代理：连 cfg 的代理字段都不读，恒直连。
        EgressIntent::Notify => return Ok(builder.timeout(timeout).build()),
        // 客户端更新沿用既有语义：不复用连接，读 45s / 整体 600s（单请求超时在其上覆盖）。
        EgressIntent::ClientCheck => {
            builder = builder
                .max_idle_connections(0)
                .timeout_read(std::time::Duration::from_secs(45))
                .timeout(std::time::Duration::from_secs(600));
        }
        EgressIntent::UpdateCheck | EgressIntent::UpdateDownload => {}
    }
    match route(cfg) {
        Route::Proxy(url) => match ureq::Proxy::new(&url) {
            Ok(proxy) => Ok(builder.proxy(proxy).build()),
            // 代理地址非法时也不直连：宁可失败，也不偷偷换路。
            Err(err) => Err(proxy_required_error(&format!("代理地址无效：{err}"))),
        },
        Route::Direct => Ok(builder.build()),
    }
}

/// 构造 Agent：走代理时绑定代理，并显式禁用"从环境变量猜代理"。
///
/// 等价于 [`client`] 的 [`EgressIntent::UpdateCheck`]（检查更新只认官方地址，不跟跳转）。
pub fn agent(cfg: &Config, timeout: std::time::Duration) -> Result<ureq::Agent, String> {
    client(cfg, EgressIntent::UpdateCheck, timeout)
}

/// 下载制品时允许跟随的重定向目标（主机名白名单）。
///
/// GitHub Release 资产的下载地址必然 302 到这些域名：`github.com` →
/// `release-assets.githubusercontent.com`（旧版本是 `objects.githubusercontent.com`）。
/// 检查更新用的 Agent 是 `redirects(0)`——那是刻意的，防止 API 响应把请求引到别处；
/// 但下载制品必须跟这一跳，否则拿到的永远是 302 的空响应体（v3.12.2 修的就是这个：
/// 用户点检查更新报"大小不符：期望 4581888，实得 0"）。
///
/// 只放行资产域名，不放行任意主机：即使响应头被篡改，也只能跳到 GitHub 自己的存储。
pub const DOWNLOAD_REDIRECT_HOSTS: [&str; 3] = [
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

/// 主机名是否在下载重定向白名单里。
pub fn redirect_allowed(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    let Some(rest) = lower.split("://").nth(1) else {
        return false;
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    DOWNLOAD_REDIRECT_HOSTS.contains(&host)
}

/// 下载专用 Agent：允许有限重定向（由 [`redirect_allowed`] 逐跳校验）。
///
/// 等价于 [`client`] 的 [`EgressIntent::UpdateDownload`]。
pub fn download_agent(cfg: &Config, timeout: std::time::Duration) -> Result<ureq::Agent, String> {
    client(cfg, EgressIntent::UpdateDownload, timeout)
}

/// 代理不可用时的统一错误文案（含"没有偷偷直连"这一事实）。
pub fn proxy_required_error(detail: &str) -> String {
    format!("代理不可用（{detail}）；已按外发策略放弃直连，避免暴露真实出口")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(host: &str, port: u16) -> Config {
        Config {
            proxy_host: host.to_string(),
            proxy_port: port,
            ..Config::default()
        }
    }

    #[test]
    fn configured_proxy_is_used() {
        let cfg = cfg_with("127.0.0.1", 7890);
        assert_eq!(
            route(&cfg),
            Route::Proxy("http://127.0.0.1:7890".to_string())
        );
    }

    #[test]
    fn empty_proxy_config_means_direct_not_a_fallback() {
        assert_eq!(route(&cfg_with("", 7890)), Route::Direct);
        assert_eq!(route(&cfg_with("127.0.0.1", 0)), Route::Direct);
        assert_eq!(route(&cfg_with("   ", 7890)), Route::Direct);
    }

    #[test]
    fn proxy_error_message_states_no_silent_direct_connection() {
        let msg = proxy_required_error("连接被拒绝");
        assert!(msg.contains("代理不可用"));
        assert!(msg.contains("放弃直连"), "必须明确告知没有偷偷直连");
    }

    #[test]
    fn download_redirect_only_allows_github_asset_hosts() {
        // GitHub Release 资产的真实落点
        assert!(redirect_allowed(
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r&sig=x"
        ));
        assert!(redirect_allowed(
            "https://objects.githubusercontent.com/foo"
        ));
        assert!(redirect_allowed(
            "https://GITHUB-RELEASES.githubusercontent.com/x"
        ));
        // 其它主机一律拒绝：重定向被篡改时不能跟着跑
        assert!(!redirect_allowed("https://evil.example.com/x"));
        assert!(!redirect_allowed("https://github.com.evil.example.com/x"));
        assert!(!redirect_allowed("https://raw.githubusercontent.com/x"));
        assert!(!redirect_allowed("http://127.0.0.1:8080/x"));
        assert!(!redirect_allowed("not a url"));
        assert!(!redirect_allowed(""));
    }

    /// 起一个只回固定响应的本地 HTTP 服务（回完即关），返回监听地址与句柄。
    fn serve_fixed(
        status_line: &'static str,
        body: &'static str,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf);
                let response = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes());
            }
        });
        (addr, handle)
    }

    /// 一个确定没人监听的端口（绑定后立刻放手）。
    fn dead_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn notify_intent_bypasses_configured_proxy_and_stays_direct() {
        let (addr, worker) = serve_fixed("HTTP/1.1 200 OK", "ok");
        // 配了一个必然连不上的代理：Notify 不读代理配置，请求必须直连本地服务。
        let cfg = cfg_with("127.0.0.1", dead_port());
        let agent = client(
            &cfg,
            EgressIntent::Notify,
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let response = agent
            .get(&format!("http://{addr}/webhook"))
            .timeout(std::time::Duration::from_secs(5))
            .call()
            .expect("Notify 必须恒直连，不得读代理配置");
        assert_eq!(response.status(), 200);
        worker.join().unwrap();
    }

    #[test]
    fn update_check_honors_configured_proxy() {
        // 本地假代理：请求到了它就证明走了代理；目标主机用 .invalid，
        // 不走代理时 DNS 必然失败。
        let (proxy_addr, worker) = serve_fixed("HTTP/1.1 200 OK", "{\"via\":\"proxy\"}");
        let cfg = cfg_with("127.0.0.1", proxy_addr.port());
        let agent = client(
            &cfg,
            EgressIntent::UpdateCheck,
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let response = agent
            .get("http://does-not-resolve.invalid/latest")
            .timeout(std::time::Duration::from_secs(5))
            .call()
            .expect("配置了代理就必须走代理，否则连不上 .invalid 主机");
        assert_eq!(response.status(), 200);
        worker.join().unwrap();
    }

    #[test]
    fn no_proxy_config_is_direct_not_a_client_check_error() {
        // 客户端更新原先在没配代理时直接报"代理地址无效"；统一入口后与其它外发一致：
        // 没配置就是 Direct（用户从未配置，不是回退），必须能建出可用的 Agent。
        let (addr, worker) = serve_fixed("HTTP/1.1 200 OK", "meta");
        let cfg = cfg_with("", 0);
        let agent = client(
            &cfg,
            EgressIntent::ClientCheck,
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let response = agent
            .get(&format!("http://{addr}/latest"))
            .timeout(std::time::Duration::from_secs(5))
            .call()
            .expect("没配置代理时 ClientCheck 直连成功");
        assert_eq!(response.status(), 200);
        worker.join().unwrap();
    }

    #[test]
    fn client_reports_invalid_proxy_without_silent_direct() {
        // route() 恒加 http:// 前缀，ureq 只在凭据段不合法时判 InvalidProxyUrl：
        // `user@host:port` 里凭据没有冒号 → Proxy::new 失败。
        // 必须报统一错误文案并放弃直连，绝不静默降级成直连。
        let err = client(
            &cfg_with("user@127.0.0.1", 7890),
            EgressIntent::UpdateCheck,
            std::time::Duration::from_secs(1),
        )
        .expect_err("非法代理地址必须失败");
        assert!(err.contains("代理不可用"), "{err}");
        assert!(err.contains("放弃直连"), "{err}");
    }
}
