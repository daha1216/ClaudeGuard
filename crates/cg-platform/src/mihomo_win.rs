//! Local Mihomo / Clash Meta External Controller discovery, status polling, and node switching.
//!
//! Security boundary: strictly restricted to loopback endpoints (`127.0.0.1` / `localhost` / `[::1]`)
//! so controller queries and secrets NEVER leave the host machine.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cg_protocol::{MihomoNodeInfo, MihomoStatus};

const DEFAULT_LOOPBACK_PORTS: [u16; 3] = [9090, 9097, 9091];
const PREFERRED_GROUPS: [&str; 9] = [
    "claude",
    "ai",
    "openai",
    "proxy",
    "节点选择",
    "代理选择",
    "手动切换",
    "select",
    "global",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerEndpoint {
    pub base_url: String,
    pub secret: Option<String>,
}

/// Validates and normalizes an `external-controller` value into a loopback HTTP base URL.
pub fn normalize_loopback_controller(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let normalized = if let Some(port) = trimmed.strip_prefix(':') {
        format!("127.0.0.1:{port}")
    } else if let Some(rest) = trimmed.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{rest}")
    } else if trimmed.starts_with("127.0.0.1:")
        || trimmed.starts_with("localhost:")
        || trimmed.starts_with("[::1]:")
    {
        trimmed.to_string()
    } else {
        return None;
    };
    let port_str = normalized.rsplit_once(':')?.1;
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(format!("http://{normalized}"))
}

fn parse_yaml_scalar(raw: &str) -> String {
    let s = raw.trim();
    if let Some(after_quote) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = after_quote.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(esc) = chars.next() {
                    out.push(esc);
                }
            } else if ch == '"' {
                return out;
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    if let Some(after_quote) = s.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = after_quote.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    let _ = chars.next();
                    out.push('\'');
                } else {
                    return out;
                }
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    if s.starts_with('#') {
        return String::new();
    }
    let mut end = s.len();
    for (idx, ch) in s.char_indices() {
        if ch == '#' && idx > 0 && s.as_bytes()[idx - 1].is_ascii_whitespace() {
            end = idx;
            break;
        }
    }
    s[..end].trim().to_string()
}

/// Lightweight zero-dependency YAML line parser for `external-controller` and `secret`.
pub fn parse_clash_yaml_controller(content: &str) -> Option<ControllerEndpoint> {
    let mut ctrl: Option<String> = None;
    let mut secret: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Only inspect top-level keys (no leading indent in raw_line)
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("external-controller:") {
            let val = parse_yaml_scalar(rest);
            if let Some(url) = normalize_loopback_controller(&val) {
                ctrl = Some(url);
            }
        } else if let Some(rest) = line.strip_prefix("secret:") {
            let val = parse_yaml_scalar(rest);
            if !val.is_empty() {
                secret = Some(val);
            }
        }
    }

    ctrl.map(|base_url| ControllerEndpoint { base_url, secret })
}

pub(crate) fn candidate_config_paths_for_homes(homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for home in homes {
        let roaming = home.join("AppData").join("Roaming");
        let local = home.join("AppData").join("Local");

        for app_base in [&roaming, &local] {
            paths.push(
                app_base
                    .join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("clash-verge.yaml"),
            );
            paths.push(
                app_base
                    .join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("config.yaml"),
            );
            paths.push(app_base.join("clash-verge").join("clash-verge.yaml"));
            paths.push(app_base.join("clash-verge").join("config.yaml"));
            paths.push(app_base.join("clash-nyanpasu").join("clash-config.yaml"));
            paths.push(app_base.join("clash-nyanpasu").join("config.yaml"));
            paths.push(
                app_base
                    .join("mihomo-party")
                    .join("work")
                    .join("config.yaml"),
            );
            paths.push(app_base.join("mihomo-party").join("config.yaml"));
            paths.push(app_base.join("sparkle").join("work").join("config.yaml"));
            paths.push(app_base.join("sparkle").join("config.yaml"));
            paths.push(
                app_base
                    .join("com.follow")
                    .join("clash")
                    .join("config.yaml"),
            );
            paths.push(app_base.join("flclash").join("config.yaml"));
            paths.push(app_base.join("mihomo").join("config.yaml"));
        }
        paths.push(home.join(".config").join("mihomo").join("config.yaml"));
        paths.push(home.join(".config").join("clash").join("config.yaml"));
    }
    paths
}

fn candidate_config_paths() -> Vec<PathBuf> {
    candidate_config_paths_for_homes(&crate::process_win::user_home_dirs())
}

pub(crate) fn dedup_endpoints(from_configs: Vec<ControllerEndpoint>) -> Vec<ControllerEndpoint> {
    let mut found = Vec::new();
    for ep in from_configs {
        if !found.contains(&ep) {
            found.push(ep);
        }
    }
    for port in DEFAULT_LOOPBACK_PORTS {
        let fallback = ControllerEndpoint {
            base_url: format!("http://127.0.0.1:{port}"),
            secret: None,
        };
        if !found.contains(&fallback) {
            found.push(fallback);
        }
    }
    found
}

fn discover_endpoints() -> Vec<ControllerEndpoint> {
    let mut raw = Vec::new();
    for path in candidate_config_paths() {
        if let Ok(text) = fs::read_to_string(&path) {
            if let Some(ep) = parse_clash_yaml_controller(&text) {
                raw.push(ep);
            }
        }
    }
    dedup_endpoints(raw)
}

fn build_loopback_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(150))
        .timeout_read(Duration::from_millis(1000))
        .timeout_write(Duration::from_millis(1000))
        .max_idle_connections(0)
        .try_proxy_from_env(false)
        .build()
}

fn apply_auth(req: ureq::Request, secret: Option<&str>) -> ureq::Request {
    if let Some(sec) = secret.map(str::trim).filter(|s| !s.is_empty()) {
        req.set("Authorization", &format!("Bearer {sec}"))
    } else {
        req
    }
}

fn contains_ascii_word(haystack_lower: &str, word: &str) -> bool {
    let hb = haystack_lower.as_bytes();
    let wb = word.as_bytes();
    if wb.is_empty() || hb.len() < wb.len() {
        return false;
    }
    for start in 0..=(hb.len() - wb.len()) {
        if &hb[start..start + wb.len()] == wb {
            let prev_alpha = start > 0 && hb[start - 1].is_ascii_alphabetic();
            let end = start + wb.len();
            let next_alpha = end < hb.len() && hb[end].is_ascii_alphabetic();
            if !prev_alpha && !next_alpha {
                return true;
            }
        }
    }
    false
}

fn group_matches_pref(name_lower: &str, pref: &str) -> bool {
    if name_lower == pref {
        return true;
    }
    if pref.is_ascii() && pref.len() <= 3 {
        return contains_ascii_word(name_lower, pref);
    }
    name_lower.contains(pref)
}

/// Parses Clash/Mihomo `GET /proxies` JSON into active Selector group, node, delay, and candidates.
pub fn parse_proxies_json(
    controller_url: &str,
    core_name: &str,
    body: &str,
) -> Option<MihomoStatus> {
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    let proxies = root.get("proxies")?.as_object()?;

    let mut selectors: Vec<(&String, &serde_json::Value)> = proxies
        .iter()
        .filter(|(_, v)| {
            v.get("type")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t.eq_ignore_ascii_case("Selector"))
        })
        .collect();

    if selectors.is_empty() {
        return Some(MihomoStatus {
            available: true,
            controller_url: controller_url.to_string(),
            core_name: core_name.to_string(),
            note: "已连接本地代理内核，但未找到可手动切换的 Selector 策略组".into(),
            ..MihomoStatus::default()
        });
    }

    selectors.sort_by_key(|(name, _)| {
        let low = name.to_ascii_lowercase();
        PREFERRED_GROUPS
            .iter()
            .position(|pref| group_matches_pref(&low, pref))
            .unwrap_or(99)
    });

    let (group_name, group_val) = selectors[0];
    let active_node = group_val
        .get("now")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let node_delay = |node_name: &str| -> Option<u32> {
        let history = proxies.get(node_name)?.get("history")?.as_array()?;
        let last = history.last()?;
        let d = last.get("delay")?.as_u64()?;
        if d > 0 {
            Some(d as u32)
        } else {
            None
        }
    };

    let active_delay_ms = node_delay(&active_node);
    let mut candidates = Vec::new();
    if let Some(all) = group_val.get("all").and_then(|v| v.as_array()) {
        for item in all {
            if let Some(name) = item.as_str() {
                if name.eq_ignore_ascii_case("DIRECT") || name.eq_ignore_ascii_case("REJECT") {
                    continue;
                }
                candidates.push(MihomoNodeInfo {
                    name: name.to_string(),
                    delay_ms: node_delay(name),
                });
                if candidates.len() >= 12 {
                    break;
                }
            }
        }
    }

    let note = if active_node.is_empty() {
        format!("已连接 {core_name}（组：{group_name}）")
    } else if let Some(ms) = active_delay_ms {
        format!("{core_name} · 组 [{group_name}] 当前节点：{active_node}（{ms}ms）")
    } else {
        format!("{core_name} · 组 [{group_name}] 当前节点：{active_node}")
    };

    Some(MihomoStatus {
        available: true,
        controller_url: controller_url.to_string(),
        core_name: core_name.to_string(),
        active_group: group_name.clone(),
        active_node,
        active_delay_ms,
        candidates,
        note,
    })
}

/// Probes discovered loopback Mihomo/Clash controllers and returns live node status.
pub fn inspect_mihomo() -> MihomoStatus {
    let agent = build_loopback_agent();
    for ep in discover_endpoints() {
        let ver_url = format!("{}/version", ep.base_url);
        let Ok(ver_resp) = apply_auth(agent.get(&ver_url), ep.secret.as_deref()).call() else {
            continue;
        };
        if ver_resp.status() != 200 {
            continue;
        }
        let ver_text = ver_resp.into_string().unwrap_or_default();
        let ver_json: serde_json::Value = serde_json::from_str(&ver_text).unwrap_or_default();
        let is_meta = ver_json
            .get("meta")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ver_str = ver_json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let core_name = if is_meta {
            format!("Mihomo {ver_str}").trim().to_string()
        } else if !ver_str.is_empty() {
            format!("Clash {ver_str}")
        } else {
            "Clash / Mihomo".into()
        };

        let prox_url = format!("{}/proxies", ep.base_url);
        if let Ok(prox_resp) = apply_auth(agent.get(&prox_url), ep.secret.as_deref()).call() {
            if let Ok(body) = prox_resp.into_string() {
                if let Some(status) = parse_proxies_json(&ep.base_url, &core_name, &body) {
                    return status;
                }
            }
        }
    }

    MihomoStatus {
        available: false,
        note: "未检测到本机 Mihomo / Clash 外部控制接口（支持 127.0.0.1:9090/9097 自动发现）"
            .into(),
        ..MihomoStatus::default()
    }
}

fn percent_encode_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for b in raw.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Switches the active proxy node in a Selector group and optionally closes active connections
/// (`DELETE /connections`) so leaked sockets terminate immediately.
pub fn switch_mihomo_node(
    group: &str,
    node: &str,
    close_connections: bool,
) -> Result<String, String> {
    let group = group.trim();
    let node = node.trim();
    if group.is_empty() || node.is_empty() {
        return Err("策略组名称与目标节点名称均不能为空".into());
    }
    let agent = build_loopback_agent();
    let mut last_err = "未检测到可用的本机 Mihomo / Clash 外部控制接口".to_string();

    for ep in discover_endpoints() {
        let put_url = format!("{}/proxies/{}", ep.base_url, percent_encode_segment(group));
        let payload = serde_json::json!({ "name": node }).to_string();
        match apply_auth(agent.put(&put_url), ep.secret.as_deref())
            .set("Content-Type", "application/json")
            .send_string(&payload)
        {
            Ok(resp) if (200..300).contains(&resp.status()) => {
                let mut closed_note = String::new();
                if close_connections {
                    let del_url = format!("{}/connections", ep.base_url);
                    if apply_auth(agent.delete(&del_url), ep.secret.as_deref())
                        .call()
                        .is_ok()
                    {
                        closed_note = "并已断开旧连接".to_string();
                    }
                }
                return Ok(format!(
                    "已将策略组 [{group}] 切换至节点「{node}」{closed_note}"
                ));
            }
            Ok(resp) => {
                last_err = format!("切换节点返回 HTTP {}", resp.status());
            }
            Err(ureq::Error::Status(code, _)) => {
                last_err = format!("控制接口拒绝切换（HTTP {code}）");
            }
            Err(_) => continue,
        }
    }

    Err(last_err)
}

/// Inspects a single YAML config file path (primarily for unit tests).
pub fn parse_yaml_file(path: &Path) -> Option<ControllerEndpoint> {
    let raw = fs::read_to_string(path).ok()?;
    parse_clash_yaml_controller(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loopback_controller_yaml_and_rejects_remote_hosts() {
        let yaml = r#"
port: 7890
external-controller: 127.0.0.1:9097
secret: "my-local-secret"
"#;
        let ep = parse_clash_yaml_controller(yaml).expect("parse yaml");
        assert_eq!(ep.base_url, "http://127.0.0.1:9097");
        assert_eq!(ep.secret.as_deref(), Some("my-local-secret"));

        assert_eq!(
            normalize_loopback_controller("0.0.0.0:9090").as_deref(),
            Some("http://127.0.0.1:9090")
        );
        assert_eq!(
            normalize_loopback_controller(":9090").as_deref(),
            Some("http://127.0.0.1:9090")
        );
        assert!(normalize_loopback_controller("192.168.1.5:9090").is_none());
    }

    #[test]
    fn parses_mihomo_proxies_json_and_picks_preferred_selector() {
        let sample = r#"{
            "proxies": {
                "US-LAX-01": { "type": "Shadowsocks", "history": [{"delay": 58}] },
                "SG-02": { "type": "VMess", "history": [{"delay": 42}] },
                "Proxy": { "type": "Selector", "now": "US-LAX-01", "all": ["DIRECT", "US-LAX-01", "SG-02"] }
            }
        }"#;
        let st = parse_proxies_json("http://127.0.0.1:9090", "Mihomo v1.19", sample)
            .expect("parse proxies");
        assert!(st.available);
        assert_eq!(st.active_group, "Proxy");
        assert_eq!(st.active_node, "US-LAX-01");
        assert_eq!(st.active_delay_ms, Some(58));
        assert_eq!(st.candidates.len(), 2);
        assert_eq!(st.candidates[0].name, "US-LAX-01");
        assert_eq!(st.candidates[1].delay_ms, Some(42));
    }

    #[test]
    fn quoted_hash_secret_dedup_by_secret_word_boundary_ai_and_client_paths() {
        // 1. Quoted YAML secret containing `#` + trailing `# comment`
        let yaml_dq =
            "external-controller: \"127.0.0.1:9097\" # inline\nsecret: \"p@ss#word#1\" # comment\n";
        let ep_dq = parse_clash_yaml_controller(yaml_dq).expect("double-quoted secret");
        assert_eq!(ep_dq.base_url, "http://127.0.0.1:9097");
        assert_eq!(ep_dq.secret.as_deref(), Some("p@ss#word#1"));

        let yaml_sq = "external-controller: ':9090'\nsecret: 's3cr#t''key' # comment\n";
        let ep_sq = parse_clash_yaml_controller(yaml_sq).expect("single-quoted secret");
        assert_eq!(ep_sq.base_url, "http://127.0.0.1:9090");
        assert_eq!(ep_sq.secret.as_deref(), Some("s3cr#t'key"));

        // 2. Dedup by `(base_url, secret)` preserves distinct secrets on the same port
        let deduped = dedup_endpoints(vec![
            ControllerEndpoint {
                base_url: "http://127.0.0.1:9090".into(),
                secret: Some("stale-sec".into()),
            },
            ControllerEndpoint {
                base_url: "http://127.0.0.1:9090".into(),
                secret: Some("active-sec".into()),
            },
            ControllerEndpoint {
                base_url: "http://127.0.0.1:9090".into(),
                secret: Some("active-sec".into()),
            },
        ]);
        assert!(deduped.contains(&ControllerEndpoint {
            base_url: "http://127.0.0.1:9090".into(),
            secret: Some("stale-sec".into()),
        }));
        assert!(deduped.contains(&ControllerEndpoint {
            base_url: "http://127.0.0.1:9090".into(),
            secret: Some("active-sec".into()),
        }));
        assert!(deduped.contains(&ControllerEndpoint {
            base_url: "http://127.0.0.1:9090".into(),
            secret: None,
        }));

        // 3. `"Taiwan"` / `"Mainland"` must NOT match `"ai"`, whereas `"🤖 AI 专线"` DOES match `"ai"`
        let taiwan_vs_proxy = r#"{
            "proxies": {
                "TW-01": { "type": "Trojan", "history": [{"delay": 35}] },
                "US-01": { "type": "Trojan", "history": [{"delay": 110}] },
                "🇹🇼 Taiwan": { "type": "Selector", "now": "TW-01", "all": ["TW-01"] },
                "Mainland": { "type": "Selector", "now": "DIRECT", "all": ["DIRECT"] },
                "节点选择": { "type": "Selector", "now": "US-01", "all": ["US-01", "TW-01"] }
            }
        }"#;
        let st = parse_proxies_json("http://127.0.0.1:9090", "Mihomo", taiwan_vs_proxy).unwrap();
        assert_eq!(st.active_group, "节点选择");

        let real_ai_group = r#"{
            "proxies": {
                "US-AI": { "type": "VLESS", "history": [{"delay": 95}] },
                "节点选择": { "type": "Selector", "now": "US-AI", "all": ["US-AI"] },
                "🤖 AI 专线": { "type": "Selector", "now": "US-AI", "all": ["US-AI"] }
            }
        }"#;
        let st_ai = parse_proxies_json("http://127.0.0.1:9090", "Mihomo", real_ai_group).unwrap();
        assert_eq!(st_ai.active_group, "🤖 AI 专线");

        // 4. Candidate config paths cover FlClash, Mihomo Party, Sparkle, Nyanpasu, and Verge Local
        let paths = candidate_config_paths_for_homes(&[PathBuf::from(r"C:\Users\Alice")]);
        let joined: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_ascii_lowercase())
            .collect();
        for expected_suffix in [
            r"roaming\com.follow\clash\config.yaml",
            r"roaming\mihomo-party\work\config.yaml",
            r"roaming\mihomo-party\config.yaml",
            r"roaming\sparkle\work\config.yaml",
            r"roaming\clash-nyanpasu\clash-config.yaml",
            r"local\io.github.clash-verge-rev.clash-verge-rev\config.yaml",
        ] {
            assert!(
                joined.iter().any(|p| p.ends_with(expected_suffix)),
                "missing candidate config path suffix {expected_suffix}"
            );
        }
    }
}
