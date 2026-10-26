//! R14 / D5：统一的出网策略。
//!
//! 规则只有一条，但它必须被所有模块共享：**有代理配置时一律走代理；代理不可用
//! 就失败并如实报告，绝不静默直连回退**。守护器自身的流量一旦直连，就会带着
//! 家宽 IP 出现在 GitHub / 飞书 / 更新源上，这正是要防的泄漏。
//!
//! 探测（anchors）是唯一"允许直连"的场景：它本来就是按 TUN/直连模式去测真实
//! 出口的，且由调用方显式传 `None` 表达这个意图，不属于"回退"。

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

/// 构造 Agent：走代理时绑定代理，并显式禁用"从环境变量猜代理"。
///
/// 禁用 `try_proxy_from_env` 是刻意的：环境变量可能指向另一个代理或直接为空，
/// 让 ureq 自己猜会让"实际走了哪条路"变得不可预测。
pub fn agent(cfg: &Config, timeout: std::time::Duration) -> Result<ureq::Agent, String> {
    let base = || {
        ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            // 不让 ureq 自己从环境变量猜代理：实际走了哪条路必须是确定的。
            .try_proxy_from_env(false)
            // 外发请求只认官方地址，重定向一律不跟（防止被引到别的主机）。
            .redirects(0)
    };
    match route(cfg) {
        Route::Proxy(url) => match ureq::Proxy::new(&url) {
            Ok(proxy) => Ok(base().proxy(proxy).build()),
            // 代理地址非法时也不直连：宁可失败，也不偷偷换路。
            Err(err) => Err(proxy_required_error(&format!("代理地址无效：{err}"))),
        },
        Route::Direct => Ok(base().build()),
    }
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
pub fn download_agent(cfg: &Config, timeout: std::time::Duration) -> Result<ureq::Agent, String> {
    let base = || {
        ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .try_proxy_from_env(false)
            // 手动逐跳校验，所以这里放开 ureq 的自动跟随
            .redirects(0)
    };
    match route(cfg) {
        Route::Proxy(url) => match ureq::Proxy::new(&url) {
            Ok(proxy) => Ok(base().proxy(proxy).build()),
            Err(err) => Err(proxy_required_error(&format!("代理地址无效：{err}"))),
        },
        Route::Direct => Ok(base().build()),
    }
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
}
