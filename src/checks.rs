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
    Running,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub state: StepState,
    pub text: String,
}

impl StepResult {
    fn pass(text: impl Into<String>) -> Self {
        Self { state: StepState::Pass, text: text.into() }
    }
    fn fail(text: impl Into<String>) -> Self {
        Self { state: StepState::Fail, text: text.into() }
    }
    fn skip() -> Self {
        Self { state: StepState::Skip, text: "未检测".into() }
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
}

/// 步骤 1：系统代理必须启用并指向 host:port
pub fn check_system_proxy(host: &str, port: u16) -> StepResult {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = match hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings") {
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
    let addr = format!("{host}:{port}");
    let mut stream = match TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| format!("{host}:{port}").parse().unwrap()),
        Duration::from_secs(4),
    ) {
        Ok(s) => s,
        Err(e) => {
            return (StepResult::fail(format!("无法连接 {addr}，端口没有监听（{e}）")), None)
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));
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
        (StepResult::pass(format!("CONNECT 握手成功（{ms} ms）")), Some(stream))
    } else {
        (StepResult::fail(format!("不是 HTTP 代理（响应: {line}）")), None)
    }
}

/// 步骤 3 主判据：走代理查询出口公网 IP
fn fetch_ipinfo(cfg: &Config) -> Result<(String, String), String> {
    let proxy = ureq::Proxy::new(format!("http://{}:{}", cfg.proxy_host, cfg.proxy_port))
        .map_err(|e| e.to_string())?;
    let agent = ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout(Duration::from_secs(12))
        .build();
    let resp = agent
        .get("https://ipinfo.io/json")
        .call()
        .map_err(|e| format!("ipinfo: {e}"))?;
    let text = resp.into_string().map_err(|e| format!("ipinfo read: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("ipinfo json: {e}"))?;
    let ip = v.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let city = v.get("city").and_then(|x| x.as_str()).unwrap_or("");
    let country = v.get("country").and_then(|x| x.as_str()).unwrap_or("");
    let org = v.get("org").and_then(|x| x.as_str()).unwrap_or("");
    let desc = format!("{city} {country} {org}").trim().to_string();
    if ip.is_empty() {
        return Err("ipinfo: no ip field".into());
    }
    Ok((ip, desc))
}

fn fetch_ipify(cfg: &Config) -> Result<(String, String), String> {
    let proxy = ureq::Proxy::new(format!("http://{}:{}", cfg.proxy_host, cfg.proxy_port))
        .map_err(|e| e.to_string())?;
    let agent = ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout(Duration::from_secs(12))
        .build();
    let resp = agent
        .get("https://api.ipify.org?format=json")
        .call()
        .map_err(|e| format!("ipify: {e}"))?;
    let text = resp.into_string().map_err(|e| format!("ipify read: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("ipify json: {e}"))?;
    let ip = v.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if ip.is_empty() {
        return Err("ipify: no ip field".into());
    }
    Ok((ip, "(via ipify)".into()))
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
    };

    // 1. 系统代理
    out.proxy = check_system_proxy(&cfg.proxy_host, cfg.proxy_port);
    if out.proxy.state != StepState::Pass {
        out.reason = format!("系统代理未指向 {}:{}", cfg.proxy_host, cfg.proxy_port);
        log(format!("BLOCKED: {}", out.reason));
        return out;
    }

    // 2. 端口 CONNECT 握手（隧道保持打开）
    let (port_res, tunnel) = check_port_connect(&cfg.proxy_host, cfg.proxy_port, &cfg.connect_target);
    out.port = port_res;
    if out.port.state != StepState::Pass {
        out.reason = "端口不是可用代理".into();
        log(format!("BLOCKED: {}", out.reason));
        return out;
    }

    // 3a. 网页出口
    let web = fetch_ipinfo(cfg).or_else(|e1| fetch_ipify(cfg).map_err(|e2| format!("{e1} | {e2}")));
    match web {
        Ok((ip, desc)) => {
            log(format!("egress(web): {ip} {desc}"));
            out.egress_ip = Some(ip.clone());
            out.egress_desc = Some(desc.clone());
            if ip == cfg.required_ip {
                out.egress = StepResult::pass(format!("{ip}  {desc}"));
                out.passed = true;
                return out;
            }
            out.egress = StepResult::fail(format!("当前出口 {ip}（{desc}）"));
            out.reason = format!("出口 IP 是 {ip}，应为 {}", cfg.required_ip);
            log(format!("BLOCKED: {}", out.reason));
            return out;
        }
        Err(err) => {
            // 3b. 网页查询失败 -> TCP 观察回退（tunnel 仍打开，迫使代理保持节点连接）
            log(format!("web check failed, tcp fallback: {err}"));
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut hit = false;
            while Instant::now() < deadline {
                let conns = crate::tcp_table::established_connections();
                if conns.iter().any(|c| c.remote_addr == cfg.required_ip) {
                    hit = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            drop(tunnel);
            if hit {
                out.egress = StepResult::pass(format!("TCP 观察: 已连接 {}", cfg.required_ip));
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
            out.egress = StepResult::fail(format!("未连接 {}，当前出口: {}", cfg.required_ip, shown.join(", ")));
            out.reason = "代理未连接指定节点".into();
            log(format!("BLOCKED: {} (egress: {})", out.reason, egress.iter().take(8).cloned().collect::<Vec<_>>().join(", ")));
            return out;
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
