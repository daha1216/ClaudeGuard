//! Local Mihomo / Clash Meta External Controller discovery, status polling, and node switching.
//!
//! Security boundary: strictly restricted to loopback endpoints (`127.0.0.1` / `localhost` / `[::1]`)
//! so controller queries and secrets NEVER leave the host machine.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cg_protocol::{MihomoNodeInfo, MihomoStatus};

const DEFAULT_LOOPBACK_PORTS: [u16; 3] = [9090, 9097, 9091];
const MAX_CANDIDATE_NODES: usize = 64;
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

fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix_ascii: &str) -> Option<&'a str> {
    if !prefix_ascii.is_ascii() {
        return None;
    }
    let head = s.as_bytes().get(..prefix_ascii.len())?;
    head.eq_ignore_ascii_case(prefix_ascii.as_bytes())
        .then(|| s.get(prefix_ascii.len()..))
        .flatten()
}

/// Validates and normalizes an `external-controller` value into a loopback HTTP base URL.
pub fn normalize_loopback_controller(raw: &str) -> Option<String> {
    let mut trimmed = raw.trim().trim_matches('"').trim_matches('\'').trim();
    if let Some(rest) = strip_ascii_prefix_ci(trimmed, "http://")
        .or_else(|| strip_ascii_prefix_ci(trimmed, "https://"))
    {
        trimmed = rest;
    }
    let trimmed = trimmed.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let normalized = if let Some(port) = trimmed.strip_prefix(":::") {
        format!("[::1]:{port}")
    } else if let Some(port) = trimmed.strip_prefix("[::]:") {
        format!("[::1]:{port}")
    } else if let Some(port) = trimmed.strip_prefix(':') {
        format!("127.0.0.1:{port}")
    } else if let Some(rest) = trimmed.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{rest}")
    } else if strip_ascii_prefix_ci(trimmed, "127.0.0.1:").is_some()
        || strip_ascii_prefix_ci(trimmed, "localhost:").is_some()
        || strip_ascii_prefix_ci(trimmed, "[::1]:").is_some()
    {
        trimmed.to_ascii_lowercase()
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
    s.get(..end).unwrap_or(s).trim().to_string()
}

/// Lightweight zero-dependency YAML line parser for `external-controller` and `secret`.
pub fn parse_clash_yaml_controller(content: &str) -> Option<ControllerEndpoint> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut ctrl: Option<String> = None;
    let mut secret: Option<String> = None;

    for raw_line in content.lines() {
        let raw_line = raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line);
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

/// Detects whether a Clash/Mihomo YAML config defines a non-empty `external-controller-pipe:`
/// (e.g. Clash Verge Rev v2+ Named Pipe mode when TCP `external-controller` is disabled).
pub fn parse_clash_yaml_pipe(content: &str) -> Option<String> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut pipe: Option<String> = None;
    for raw_line in content.lines() {
        let raw_line = raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line);
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("external-controller-pipe:") {
            let val = parse_yaml_scalar(rest);
            if !val.is_empty()
                && !val.eq_ignore_ascii_case("null")
                && !val.eq_ignore_ascii_case("~")
            {
                pipe = Some(val);
            }
        }
    }
    pipe
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

fn discover_endpoints_and_pipe() -> (Vec<ControllerEndpoint>, Option<String>) {
    let mut raw = Vec::new();
    let mut pipe_hint: Option<String> = None;
    for path in candidate_config_paths() {
        if let Ok(text) = fs::read_to_string(&path) {
            if let Some(ep) = parse_clash_yaml_controller(&text) {
                raw.push(ep);
            }
            if pipe_hint.is_none() {
                pipe_hint = parse_clash_yaml_pipe(&text);
            }
        }
    }
    (dedup_endpoints(raw), pipe_hint)
}

fn pipe_only_diagnostic_note(pipe_name: &str) -> String {
    format!(
        "检测到本机代理启用了命名管道控制接口（external-controller-pipe: {pipe_name}），未开启本地 HTTP 外部控制端口（可在代理设置中开启 127.0.0.1:9090/9097）"
    )
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
                if candidates.len() >= MAX_CANDIDATE_NODES {
                    break;
                }
            }
        }
    }
    if !active_node.is_empty()
        && !active_node.eq_ignore_ascii_case("DIRECT")
        && !active_node.eq_ignore_ascii_case("REJECT")
        && !candidates.iter().any(|c| c.name == active_node)
    {
        if candidates.len() >= MAX_CANDIDATE_NODES {
            let _ = candidates.pop();
        }
        candidates.push(MihomoNodeInfo {
            name: active_node.clone(),
            delay_ms: active_delay_ms,
        });
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
    let (endpoints, pipe_hint) = discover_endpoints_and_pipe();
    for ep in endpoints {
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

    let note = match pipe_hint {
        Some(pipe_name) => pipe_only_diagnostic_note(&pipe_name),
        None => {
            "未检测到本机 Mihomo / Clash 外部控制接口（支持 127.0.0.1:9090/9097 自动发现）".into()
        }
    };
    MihomoStatus {
        available: false,
        note,
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

pub(crate) fn switch_mihomo_node_on_endpoints(
    endpoints: &[ControllerEndpoint],
    pipe_hint: Option<&str>,
    group: &str,
    node: &str,
    close_connections: bool,
) -> Result<String, String> {
    if group.trim().is_empty() || node.trim().is_empty() {
        return Err("策略组名称与目标节点名称均不能为空".into());
    }
    let agent = build_loopback_agent();
    let mut last_err = match pipe_hint {
        Some(pipe_name) => pipe_only_diagnostic_note(pipe_name),
        None => "未检测到可用的本机 Mihomo / Clash 外部控制接口".to_string(),
    };

    for ep in endpoints {
        // Verify this loopback endpoint actually speaks Clash/Mihomo `GET /version` == 200
        // before sending `PUT /proxies/{group}` or `DELETE /connections` with `Authorization`.
        let ver_url = format!("{}/version", ep.base_url);
        let ver_resp = match apply_auth(agent.get(&ver_url), ep.secret.as_deref()).call() {
            Ok(r) if r.status() == 200 => r,
            Err(ureq::Error::Status(401 | 403, _)) => {
                last_err = "控制接口鉴权失败（secret 不匹配）".to_string();
                continue;
            }
            _ => continue,
        };
        let ver_body = ver_resp.into_string().unwrap_or_default();
        let valid_version = serde_json::from_str::<serde_json::Value>(&ver_body)
            .ok()
            .and_then(|v| {
                v.get("version")
                    .and_then(|s| s.as_str())
                    .map(|s| !s.is_empty())
            })
            .unwrap_or(false);
        if !valid_version {
            continue;
        }

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

/// Switches the active proxy node in a Selector group and optionally closes active connections
/// (`DELETE /connections`) so leaked sockets terminate immediately.
pub fn switch_mihomo_node(
    group: &str,
    node: &str,
    close_connections: bool,
) -> Result<String, String> {
    if group.trim().is_empty() || node.trim().is_empty() {
        return Err("策略组名称与目标节点名称均不能为空".into());
    }
    let (endpoints, pipe_hint) = discover_endpoints_and_pipe();
    switch_mihomo_node_on_endpoints(
        &endpoints,
        pipe_hint.as_deref(),
        group,
        node,
        close_connections,
    )
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

    #[test]
    fn bom_ipv6_wildcard_pipe_note_64_candidates_and_version_gated_untrimmed_switch() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // 1. UTF-8 BOM on first line + `[::]:port` / `:::port`
        let bom_yaml = "\u{feff}external-controller: \"[::]:9097\"\nsecret: \"bom-sec\"\n";
        let ep_bom = parse_clash_yaml_controller(bom_yaml).expect("parse BOM yaml");
        assert_eq!(ep_bom.base_url, "http://[::1]:9097");
        assert_eq!(ep_bom.secret.as_deref(), Some("bom-sec"));
        assert_eq!(
            normalize_loopback_controller(":::9090").as_deref(),
            Some("http://[::1]:9090")
        );

        // 2. Named pipe diagnostic detection (`external-controller-pipe:`)
        let pipe_yaml = "\u{feff}external-controller-pipe: \\\\.\\pipe\\verge-mihomo\n";
        assert_eq!(
            parse_clash_yaml_pipe(pipe_yaml).as_deref(),
            Some(r"\\.\pipe\verge-mihomo")
        );
        let pipe_err = switch_mihomo_node_on_endpoints(
            &[],
            Some(r"\\.\pipe\verge-mihomo"),
            "Proxy",
            "US-01",
            false,
        )
        .unwrap_err();
        assert!(pipe_err.contains("external-controller-pipe"));

        // 3. Candidate limit 64 + active_node beyond #64 is always included
        let mut all_nodes = vec!["\"DIRECT\"".to_string()];
        for i in 1..=70 {
            all_nodes.push(format!("\"Node-{i:02}\""));
        }
        let big_json = format!(
            r#"{{"proxies":{{"Node-70":{{"type":"VLESS","history":[{{"delay":31}}]}},"Proxy":{{"type":"Selector","now":"Node-70","all":[{}]}}}}}}"#,
            all_nodes.join(",")
        );
        let st = parse_proxies_json("http://127.0.0.1:9090", "Mihomo", &big_json).unwrap();
        assert_eq!(st.candidates.len(), 64);
        assert!(
            st.candidates
                .iter()
                .any(|c| c.name == "Node-70" && c.delay_ms == Some(31)),
            "active_node must always be included even past index 64"
        );

        // 4. `switch_mihomo_node` checks `GET /version` before `PUT` and preserves untrimmed spaces
        let non_mihomo = TcpListener::bind("127.0.0.1:0").unwrap();
        let non_mihomo_addr = non_mihomo.local_addr().unwrap();
        let h_non = std::thread::spawn(move || {
            let mut req_count = 0usize;
            if let Ok((mut sock, _)) = non_mihomo.accept() {
                req_count += 1;
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
            req_count
        });

        let real_mihomo = TcpListener::bind("127.0.0.1:0").unwrap();
        let real_addr = real_mihomo.local_addr().unwrap();
        let h_real = std::thread::spawn(move || {
            let mut put_req = String::new();
            for step in 0..2 {
                if let Ok((mut sock, _)) = real_mihomo.accept() {
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut raw_bytes = Vec::new();
                    let mut buf = [0u8; 2048];
                    loop {
                        match sock.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                raw_bytes.extend_from_slice(&buf[..n]);
                                let cur = String::from_utf8_lossy(&raw_bytes);
                                if step == 0 && cur.contains("\r\n\r\n") {
                                    break;
                                }
                                if step == 1 && cur.contains("\r\n\r\n") && cur.ends_with('}') {
                                    break;
                                }
                            }
                        }
                    }
                    let raw = String::from_utf8_lossy(&raw_bytes).into_owned();
                    if step == 0 {
                        let body = r#"{"meta":true,"version":"v1.19.0"}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes());
                    } else {
                        put_req = raw;
                        let _ = sock.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                }
            }
            put_req
        });

        let msg = switch_mihomo_node_on_endpoints(
            &[
                ControllerEndpoint {
                    base_url: format!("http://{non_mihomo_addr}"),
                    secret: Some("sec-1".into()),
                },
                ControllerEndpoint {
                    base_url: format!("http://{real_addr}"),
                    secret: Some("sec-2".into()),
                },
            ],
            None,
            " 节点选择 ",
            " US 01 ",
            false,
        )
        .expect("switch on verified Mihomo endpoint");
        assert!(msg.contains("[ 节点选择 ]") && msg.contains("「 US 01 」"));
        assert_eq!(
            h_non.join().unwrap(),
            1,
            "non-Mihomo server must never receive PUT"
        );
        let captured_put = h_real.join().unwrap();
        assert!(
            captured_put.contains("PUT /proxies/%20%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9%20 "),
            "group leading/trailing spaces must be preserved: {captured_put}"
        );
        assert!(
            captured_put.contains(r#"{"name":" US 01 "}"#),
            "node leading/trailing spaces must be preserved: {captured_put}"
        );
    }
}
