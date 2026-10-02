use crate::config::Config;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub state: StepState,
    pub text: String,
}

impl StepResult {
    fn pass(text: impl Into<String>) -> Self {
        Self {
            state: StepState::Pass,
            text: text.into(),
        }
    }
    fn fail(text: impl Into<String>) -> Self {
        Self {
            state: StepState::Fail,
            text: text.into(),
        }
    }
    fn skip() -> Self {
        Self {
            state: StepState::Skip,
            text: "未检测".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckOutcome {
    pub proxy: StepResult,
    pub port: StepResult,
    pub egress: StepResult,
    pub passed: bool,
    pub reason: String,
    /// egress ip observed (if any) for display
    pub egress_ip: Option<String>,
    pub egress_desc: Option<String>,
    /// egress country code from ipinfo (e.g. "US"), when geo is known
    pub egress_country: Option<String>,
}

/// 出口判定（v2.6 多 IP + 地区规则，run_checks 与 monitor 熔断共用）。
/// 返回 (pass, mismatch)：
/// - pass:    命中任一约定 IP，或命中约定地区
/// - mismatch: 拿到了出口信息且两条规则都不满足——只有这种情况才允许熔断
///   （网络失败/地区模式下拿不到地区 → mismatch=false，沿用 v1 的防误杀语义）
pub fn match_egress(cfg: &Config, ip: Option<&str>, country: Option<&str>) -> (bool, bool) {
    let ip_hit = ip
        .map(|ip| cfg.allowed_ips.iter().any(|a| a == ip))
        .unwrap_or(false);
    let region = cfg.egress_region.trim();
    let region_hit = !region.is_empty() && country == Some(region);
    let pass = ip_hit || region_hit;
    // 防误杀：完全拿不到出口信息（网络失败），或地区模式下本次没拿到地区（ipinfo 挂了只有 ipify）
    // ——两种情况都不算 mismatch，宁可放过不可错杀
    let no_info = ip.is_none() && country.is_none();
    let region_blind = !region.is_empty() && country.is_none();
    let mismatch = !pass && !no_info && !region_blind;
    (pass, mismatch)
}

/// 步骤 1：系统代理必须启用并指向 host:port
pub fn check_system_proxy(host: &str, port: u16) -> StepResult {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key =
        match hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings") {
            Ok(k) => k,
            Err(e) => return StepResult::fail(format!("读取系统代理设置失败: {e}")),
        };
    let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let server: String = key.get_value("ProxyServer").unwrap_or_default();
    let expected = format!("{host}:{port}");
    if enabled != 1 {
        return StepResult::fail("系统代理未开启");
    }
    if server == expected || server.split(';').any(|p| p.contains(&expected)) {
        StepResult::pass(format!("已开启: {server}"))
    } else {
        StepResult::fail(format!("指向 {server}，应为 {expected}"))
    }
}

/// 步骤 2：TCP 连接 + HTTP CONNECT 握手（验证端口是可用 HTTP 代理）。
/// 成功时返回保持打开的隧道连接，供步骤 3 的 TCP 观察回退使用。
pub fn check_port_connect(host: &str, port: u16, target: &str) -> (StepResult, Option<TcpStream>) {
    let t0 = Instant::now();
    use std::net::ToSocketAddrs;
    let addr = format!("{host}:{port}");
    let sockaddr = match (host, port).to_socket_addrs().map(|mut it| it.next()) {
        Ok(Some(a)) => a,
        _ => return (StepResult::fail(format!("代理地址无效: {addr}")), None),
    };
    let mut stream = match TcpStream::connect_timeout(&sockaddr, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(e) => {
            return (
                StepResult::fail(format!("无法连接 {addr}，端口没有监听（{e}）")),
                None,
            )
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));
    let target = target.trim().replace(['\r', '\n'], "");
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    if let Err(e) = stream.write_all(req.as_bytes()) {
        return (StepResult::fail(format!("发送握手失败: {e}")), None);
    }
    let mut buf = [0u8; 2048];
    let mut acc = String::new();
    for _ in 0..3 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                if acc.contains('\r') {
                    break;
                }
            }
            Err(e) => return (StepResult::fail(format!("握手无响应: {e}")), None),
        }
    }
    let line = acc.lines().next().unwrap_or("");
    if line.starts_with("HTTP/") && line.contains(" 2") {
        let ms = t0.elapsed().as_millis();
        (
            StepResult::pass(format!("CONNECT 握手成功（{ms} ms）")),
            Some(stream),
        )
    } else {
        (
            StepResult::fail(format!("不是 HTTP 代理（响应: {line}）")),
            None,
        )
    }
}

/// 步骤 3 共用的代理 Agent（连接池复用，避免每周期重新握手）
fn proxy_agent(cfg: &Config) -> Result<ureq::Agent, String> {
    let proxy = ureq::Proxy::new(format!("http://{}:{}", cfg.proxy_host, cfg.proxy_port))
        .map_err(|e| e.to_string())?;
    Ok(ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout(Duration::from_secs(12))
        .build())
}

/// 步骤 3 主判据：走代理查询出口公网 IP（附带国家代码，供地区匹配）
fn fetch_ipinfo(agent: &ureq::Agent) -> Result<(String, String, String), String> {
    let resp = agent
        .get("https://ipinfo.io/json")
        .call()
        .map_err(|e| format!("ipinfo: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("ipinfo read: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("ipinfo json: {e}"))?;
    let ip = v
        .get("ip")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let city = v.get("city").and_then(|x| x.as_str()).unwrap_or("");
    let country = v.get("country").and_then(|x| x.as_str()).unwrap_or("");
    let org = v.get("org").and_then(|x| x.as_str()).unwrap_or("");
    let desc = format!("{city} {country} {org}").trim().to_string();
    if ip.is_empty() {
        return Err("ipinfo: no ip field".into());
    }
    Ok((ip, desc, country.to_string()))
}

fn fetch_ipify(agent: &ureq::Agent) -> Result<(String, String, String), String> {
    let resp = agent
        .get("https://api.ipify.org?format=json")
        .call()
        .map_err(|e| format!("ipify: {e}"))?;
    let text = resp.into_string().map_err(|e| format!("ipify read: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("ipify json: {e}"))?;
    let ip = v
        .get("ip")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if ip.is_empty() {
        return Err("ipify: no ip field".into());
    }
    Ok((ip, "(via ipify)".into(), String::new()))
}

/// 完整三步校验。log 回调用于写日志。
pub fn run_checks(cfg: &Config, mut log: impl FnMut(String)) -> CheckOutcome {
    let mut out = CheckOutcome {
        proxy: StepResult::skip(),
        port: StepResult::skip(),
        egress: StepResult::skip(),
        passed: false,
        reason: String::new(),
        egress_ip: None,
        egress_desc: None,
        egress_country: None,
    };

    // 1. 系统代理
    out.proxy = check_system_proxy(&cfg.proxy_host, cfg.proxy_port);
    if out.proxy.state != StepState::Pass {
        out.reason = format!("系统代理未指向 {}:{}", cfg.proxy_host, cfg.proxy_port);
        log(format!("BLOCKED: {}", out.reason));
        return out;
    }

    // 2. 端口 CONNECT 握手（隧道保持打开）
    let (port_res, tunnel) =
        check_port_connect(&cfg.proxy_host, cfg.proxy_port, &cfg.connect_target);
    out.port = port_res;
    if out.port.state != StepState::Pass {
        out.reason = "端口不是可用代理".into();
        log(format!("BLOCKED: {}", out.reason));
        return out;
    }

    // 3a. 网页出口（共享一个代理 Agent，失败再换 ipify）
    let web = proxy_agent(cfg)
        .map_err(|e| format!("agent: {e}"))
        .and_then(|agent| {
            fetch_ipinfo(&agent)
                .or_else(|e1| fetch_ipify(&agent).map_err(|e2| format!("{e1} | {e2}")))
        });
    match web {
        Ok((ip, desc, country)) => {
            log(format!("egress(web): {ip} {desc}"));
            out.egress_ip = Some(ip.clone());
            out.egress_desc = Some(desc.clone());
            out.egress_country = if country.is_empty() {
                None
            } else {
                Some(country.clone())
            };
            let (hit, _) = match_egress(cfg, Some(&ip), out.egress_country.as_deref());
            let region = cfg.egress_region.trim();
            if hit {
                let how = if cfg.allowed_ips.iter().any(|a| a == &ip) {
                    "命中约定 IP".to_string()
                } else {
                    format!("命中约定地区 {country}")
                };
                let region_note = if !region.is_empty() && cfg.allowed_ips.is_empty() {
                    // 纯地区模式：把约定地区带上，用户看得见为什么放行
                    format!("（约定地区 {region}）")
                } else {
                    String::new()
                };
                out.egress = StepResult::pass(format!("{ip}  {desc} · {how}{region_note}"));
                out.passed = true;
                return out;
            }
            out.egress = StepResult::fail(format!("当前出口 {ip}（{desc}）"));
            out.reason = if !region.is_empty() && !cfg.allowed_ips.is_empty() {
                format!("出口 {ip}（{country}）既不在约定 IP 列表，也不是约定地区 {region}")
            } else if !region.is_empty() {
                format!("出口地区 {country} 不是约定的 {region}")
            } else {
                format!("出口 IP 是 {ip}，不在约定列表")
            };
            log(format!("BLOCKED: {}", out.reason));
            out
        }
        Err(err) => {
            // 3b. 网页查询失败 -> TCP 观察回退（tunnel 仍打开，迫使代理保持节点连接）
            log(format!("web check failed, tcp fallback: {err}"));
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut hit_ip = String::new();
            while Instant::now() < deadline {
                let conns = crate::tcp_table::established_connections();
                if let Some(c) = conns
                    .iter()
                    .find(|c| cfg.allowed_ips.iter().any(|w| w == &c.remote_addr))
                {
                    hit_ip = c.remote_addr.clone();
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            drop(tunnel);
            if !hit_ip.is_empty() {
                out.egress = StepResult::pass(format!("TCP 观察: 已连接 {hit_ip}"));
                out.passed = true;
                return out;
            }
            let egress: Vec<String> = {
                let pid = crate::tcp_table::listener_pid(cfg.proxy_port);
                crate::tcp_table::established_connections()
                    .into_iter()
                    .filter(|c| c.pid == pid && !is_private_ip(&c.remote_addr))
                    .map(|c| c.remote_addr)
                    .collect::<Vec<_>>()
            };
            let shown: Vec<String> = egress.iter().take(5).cloned().collect();
            let want = if cfg.allowed_ips.is_empty() {
                "约定地区".to_string()
            } else {
                cfg.allowed_ips.join("/")
            };
            out.egress = StepResult::fail(format!("未连接 {want}，当前出口: {}", shown.join(", ")));
            out.reason = "代理未连接指定节点".into();
            log(format!(
                "BLOCKED: {} (egress: {})",
                out.reason,
                egress
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out
        }
    }
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || ip.starts_with("0.0.0.0")
        || ip == "::1"
        || ip.starts_with("::")
        || ip.starts_with("fe80:")
        || {
            if let Some(rest) = ip.strip_prefix("172.") {
                if let Some(second) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
                    (16..=31).contains(&second)
                } else {
                    false
                }
            } else {
                false
            }
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(ips: &[&str], region: &str) -> Config {
        let mut c = Config::default();
        c.allowed_ips = ips.iter().map(|s| s.to_string()).collect();
        c.egress_region = region.to_string();
        c
    }

    /// 行为锁: 多 IP 列表命中任一即通过。
    #[test]
    fn multi_ip_list_matches() {
        let c = cfg(&["1.1.1.1", "2.2.2.2"], "");
        assert_eq!(match_egress(&c, Some("2.2.2.2"), Some("AU")), (true, false));
        let (pass, mis) = match_egress(&c, Some("3.3.3.3"), Some("AU"));
        assert!(!pass && mis);
    }

    /// 行为锁: 地区模式——国家命中即通过；拿不到国家时防误杀（不熔断）。
    #[test]
    fn region_mode() {
        let c = cfg(&[], "US");
        assert_eq!(match_egress(&c, Some("9.9.9.9"), Some("US")), (true, false));
        let (pass, mis) = match_egress(&c, Some("9.9.9.9"), Some("JP"));
        assert!(!pass && mis);
        // ipify 兜底只拿到 IP、没拿到地区：不通过，但绝不熔断
        let (pass, mis) = match_egress(&c, Some("9.9.9.9"), None);
        assert!(!pass && !mis);
    }

    /// 行为锁: 双规则并存时任一命中即通过；全部落空才熔断。
    #[test]
    fn ip_or_region_union() {
        let c = cfg(&["1.1.1.1"], "US");
        assert_eq!(match_egress(&c, Some("9.9.9.9"), Some("US")), (true, false));
        assert_eq!(match_egress(&c, Some("1.1.1.1"), Some("JP")), (true, false));
        let (pass, mis) = match_egress(&c, Some("9.9.9.9"), Some("JP"));
        assert!(!pass && mis);
    }

    /// 行为锁: 完全拿不到出口信息 → 不通过也不熔断（v1 防误杀语义）。
    #[test]
    fn no_info_no_trip() {
        let c = cfg(&["1.1.1.1"], "");
        assert_eq!(match_egress(&c, None, None), (false, false));
        let c2 = cfg(&["1.1.1.1"], "US");
        assert_eq!(match_egress(&c2, None, None), (false, false));
    }
}
