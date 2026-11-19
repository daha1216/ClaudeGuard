//! Pure HTTP anchor response body parsers (`trace`, `json_ip`, `gemini_region`, `reachability`, `auto`).

use crate::geo;
use cg_protocol::{AnchorKind, ProbeResult, normalize_ip, normalize_region};
use std::io::Read;

/// Maximum response body size read/parsed per anchor probe (3 MiB).
pub const MAX_BODY_BYTES: usize = 3 * 1024 * 1024;

/// User-Agent sent on anchor probe requests.
pub const USER_AGENT: &str = "ClaudeGuard/4.0";

/// Reads at most [`MAX_BODY_BYTES`] from a stream, replacing invalid UTF-8 lossily.
pub fn read_body_limited(reader: impl Read) -> String {
    let mut bytes = Vec::with_capacity(16 * 1024);
    let _ = reader.take(MAX_BODY_BYTES as u64).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Caps raw bytes at [`MAX_BODY_BYTES`] and parses an anchor body according to `kind`.
pub fn parse_body_bytes(
    kind: AnchorKind,
    bytes: &[u8],
    status: Option<u16>,
    latency_ms: u64,
) -> ProbeResult {
    let capped = if bytes.len() > MAX_BODY_BYTES {
        &bytes[..MAX_BODY_BYTES]
    } else {
        bytes
    };
    let text = String::from_utf8_lossy(capped);
    let mut result = parse_anchor_text(kind, &text, status);
    result.reachable = true;
    result.status = status;
    result.latency_ms = latency_ms;
    result
}

/// Parses an already-decoded HTTP body string for the specified [`AnchorKind`].
pub fn parse_anchor_text(kind: AnchorKind, body: &str, status: Option<u16>) -> ProbeResult {
    let body = cap_str(body);
    let parsed = match kind {
        AnchorKind::Auto => return parse_auto(body),
        AnchorKind::Trace => parse_trace(body),
        AnchorKind::JsonIp => parse_json_ip(body),
        AnchorKind::GeminiRegion => parse_gemini_region(body),
        AnchorKind::Reachability => Some(parse_reachability(status)),
    };
    parsed.unwrap_or_else(|| ProbeResult {
        reachable: true,
        status,
        parsed_as: kind_tag(kind).into(),
        detail: format!("{}解析失败，未识别到出口信息", kind.label()),
        ..ProbeResult::default()
    })
}

/// Constructs a reachability-only probe result (any HTTP response status passes).
pub fn parse_reachability(status: Option<u16>) -> ProbeResult {
    let detail = match status {
        Some(code) => format!("有响应（HTTP {code}），按可达性判定"),
        None => "有响应，按可达性判定".into(),
    };
    ProbeResult {
        reachable: true,
        status,
        parsed_as: kind_tag(AnchorKind::Reachability).into(),
        detail,
        ..ProbeResult::default()
    }
}

/// Parses Cloudflare `/cdn-cgi/trace` key=value response (`ip=`, `loc=`, `colo=`).
pub fn parse_trace(text: &str) -> Option<ProbeResult> {
    let text = cap_str(text);
    let mut ip: Option<String> = None;
    let mut loc: Option<String> = None;
    let mut colo: Option<String> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "ip" if ip.is_none() => ip = normalize_ip(value),
            "loc" if loc.is_none() => loc = Some(value.to_string()),
            "colo" if colo.is_none() => colo = Some(value.to_string()),
            _ => {}
        }
    }
    if ip.is_none() && loc.is_none() {
        return None;
    }

    let raw_region = loc;
    let country = raw_region.as_deref().and_then(normalize_region);
    let city = colo
        .as_deref()
        .and_then(geo::by_colo)
        .map(|place| place.city.to_string());
    let detail = format!(
        "trace：ip={}，地区={}，节点={}",
        ip.as_deref().unwrap_or("-"),
        raw_region.as_deref().unwrap_or("-"),
        colo.as_deref().unwrap_or("-")
    );
    Some(ProbeResult {
        reachable: true,
        ip,
        country,
        raw_region,
        colo,
        city,
        latency_ms: 0,
        status: None,
        parsed_as: kind_tag(AnchorKind::Trace).into(),
        detail,
    })
}

/// Parses JSON IP echo payloads (`ip`/`ip_address`/`query`/`origin` and `country`/`country_code`/`loc`/`region`).
pub fn parse_json_ip(text: &str) -> Option<ProbeResult> {
    let text = cap_str(text).trim_start_matches('\u{feff}').trim();
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let top = value.as_object()?;
    let mut objects = vec![top];
    if let Some(data) = top.get("data").and_then(|v| v.as_object()) {
        objects.push(data);
    }
    let pick = |keys: &[&str]| -> Option<String> {
        for object in &objects {
            for key in keys {
                if let Some(val) = object.get(*key).and_then(|v| v.as_str()) {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
        None
    };

    let ip = pick(&["ip", "ip_address", "query", "origin"]).and_then(|raw| normalize_ip(&raw));
    let raw_region = pick(&["country", "country_code", "loc", "region"]);
    let city = pick(&["city"]);
    if ip.is_none() && raw_region.is_none() {
        return None;
    }

    let country = raw_region.as_deref().and_then(normalize_region);
    let detail = format!(
        "JSON：ip={}，地区={}",
        ip.as_deref().unwrap_or("-"),
        raw_region.as_deref().unwrap_or("-")
    );
    Some(ProbeResult {
        reachable: true,
        ip,
        country,
        raw_region,
        colo: None,
        city,
        latency_ms: 0,
        status: None,
        parsed_as: kind_tag(AnchorKind::JsonIp).into(),
        detail,
    })
}

/// Scans Gemini HTML payload for `,2,1,200,"XXX"` alpha-3 country marker.
pub fn parse_gemini_region(text: &str) -> Option<ProbeResult> {
    const MARKER: &str = ",2,1,200,\"";
    let text = cap_str(text);
    for (pos, _) in text.match_indices(MARKER) {
        let rest = &text[pos + MARKER.len()..];
        let bytes = rest.as_bytes();
        if bytes.len() < 4 || bytes[3] != b'"' || !bytes[..3].iter().all(u8::is_ascii_uppercase) {
            continue;
        }
        let raw = rest[..3].to_string();
        let country = normalize_region(&raw);
        let detail = match &country {
            Some(code) => format!("页面地区标记：{raw} → {code}"),
            None => format!("页面地区标记：{raw}（无法归一）"),
        };
        return Some(ProbeResult {
            reachable: true,
            ip: None,
            country,
            raw_region: Some(raw),
            colo: None,
            city: None,
            latency_ms: 0,
            status: None,
            parsed_as: kind_tag(AnchorKind::GeminiRegion).into(),
            detail,
        });
    }
    None
}

/// Auto-detects response format in order: `trace` -> `json_ip` -> `gemini_region` -> `reachability`.
pub fn parse_auto(text: &str) -> ProbeResult {
    let text = cap_str(text);
    if let Some(parsed) = parse_trace(text) {
        return parsed;
    }
    if let Some(parsed) = parse_json_ip(text) {
        return parsed;
    }
    if let Some(parsed) = parse_gemini_region(text) {
        return parsed;
    }
    ProbeResult {
        reachable: true,
        parsed_as: kind_tag(AnchorKind::Reachability).into(),
        detail: "有响应，但未识别到出口信息".into(),
        ..ProbeResult::default()
    }
}

fn cap_str(text: &str) -> &str {
    if text.len() <= MAX_BODY_BYTES {
        return text;
    }
    let mut end = MAX_BODY_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn kind_tag(kind: AnchorKind) -> &'static str {
    match kind {
        AnchorKind::Auto => "auto",
        AnchorKind::Trace => "trace",
        AnchorKind::JsonIp => "json_ip",
        AnchorKind::GeminiRegion => "gemini_region",
        AnchorKind::Reachability => "reachability",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_reads_ip_region_colo_and_enriches_city() {
        let body = "fl=20f123\nip=198.51.100.98\ncolo=LAX\nloc=US\n";
        let probe = parse_trace(body).expect("trace");
        assert_eq!(probe.parsed_as, "trace");
        assert_eq!(probe.ip.as_deref(), Some("198.51.100.98"));
        assert_eq!(probe.country.as_deref(), Some("US"));
        assert_eq!(probe.colo.as_deref(), Some("LAX"));
        assert_eq!(probe.city.as_deref(), Some("洛杉矶"));
    }

    #[test]
    fn json_reads_nested_and_top_level_fields() {
        let top = r#"{"ip":"198.51.100.98","country":"USA","city":"Los Angeles"}"#;
        let p1 = parse_json_ip(top).expect("top");
        assert_eq!(p1.ip.as_deref(), Some("198.51.100.98"));
        assert_eq!(p1.country.as_deref(), Some("US"));
        assert_eq!(p1.city.as_deref(), Some("Los Angeles"));

        let nested = r#"{"data":{"ip_address":"203.0.113.45","country_code":"jp"}}"#;
        let p2 = parse_json_ip(nested).expect("nested");
        assert_eq!(p2.ip.as_deref(), Some("203.0.113.45"));
        assert_eq!(p2.country.as_deref(), Some("JP"));
    }

    #[test]
    fn gemini_region_and_auto_fallback_order() {
        let gemini = r#"abc,2,1,200,"usa",2,1,200,"JPN",null"#;
        let p = parse_auto(gemini);
        assert_eq!(p.parsed_as, "gemini_region");
        assert_eq!(p.country.as_deref(), Some("JP"));

        let html = parse_auto("<html>ok</html>");
        assert_eq!(html.parsed_as, "reachability");
        assert!(html.reachable);
        assert!(html.ip.is_none());
    }

    #[test]
    fn body_cap_limits_to_3mib() {
        let oversized = vec![b'a'; MAX_BODY_BYTES + 1024];
        let text = read_body_limited(std::io::Cursor::new(oversized));
        assert_eq!(text.len(), MAX_BODY_BYTES);

        let mut beyond_cap = "x".repeat(MAX_BODY_BYTES + 64);
        beyond_cap.push_str("\nip=198.51.100.98\nloc=US\n");
        let parsed = parse_body_bytes(AnchorKind::Auto, beyond_cap.as_bytes(), Some(200), 10);
        assert_eq!(parsed.parsed_as, "reachability");
        assert!(parsed.ip.is_none());
    }

    #[test]
    fn trace_requires_ip_or_loc_and_handles_crlf() {
        assert!(parse_trace("").is_none());
        assert!(parse_trace("colo=LAX\nwarp=off\n").is_none());

        let loc_only = parse_trace("# comment\r\nloc=JPN\r\ncolo=NRT\r\n").expect("loc only");
        assert!(loc_only.ip.is_none());
        assert_eq!(loc_only.country.as_deref(), Some("JP"));
        assert_eq!(loc_only.city.as_deref(), Some("东京"));
    }

    #[test]
    fn explicit_kind_failure_and_reachability_preserve_status_and_latency() {
        let p = parse_body_bytes(AnchorKind::JsonIp, b"not json", Some(502), 88);
        assert!(p.reachable);
        assert_eq!(p.status, Some(502));
        assert_eq!(p.latency_ms, 88);
        assert_eq!(p.parsed_as, "json_ip");
        assert!(!p.has_info());

        let r = parse_body_bytes(AnchorKind::Reachability, b"ignored", Some(403), 31);
        assert!(r.reachable);
        assert_eq!(r.status, Some(403));
        assert_eq!(r.latency_ms, 31);
        assert_eq!(r.parsed_as, "reachability");
    }

    #[test]
    fn json_ip_prefers_first_alias_and_rejects_missing_geo_fields() {
        let p = parse_json_ip(r#"{"query":"203.0.113.45","ip":"198.51.100.98"}"#).expect("alias");
        assert_eq!(p.ip.as_deref(), Some("198.51.100.98"));
        assert!(parse_json_ip(r#"{"city":"Los Angeles"}"#).is_none());
        assert!(parse_json_ip(r#"["198.51.100.98"]"#).is_none());
    }
}
