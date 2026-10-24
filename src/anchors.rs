//! 锚点探测：经系统代理抓取目标锚点，并把响应体解析成出口信息。
//!
//! 网络只发生在 [`probe`] 里；[`parse_trace`] / [`parse_json_ip`] /
//! [`parse_gemini_region`] / [`parse_auto`] 都是纯函数，单测不发起网络。
//! 解析函数的 `reachable` 固定为 `true`：它们只在"已经拿到响应体"之后被调用，
//! 状态码与延迟由 [`probe`] 回填。

use std::io::Read;
use std::time::{Duration, Instant};

use crate::model::{normalize_ip, normalize_region, AnchorKind, ProbeResult, Target};

/// 响应体读取上限：Gemini 页面约 800KB，超过 3MB 的部分不再解析。
pub const MAX_BODY_BYTES: u64 = 3 * 1024 * 1024;

/// 探测请求的 UA，代理/网关日志里能一眼认出 ClaudeGuard。
pub const USER_AGENT: &str = "ClaudeGuard/3.0";

/// 跟随重定向的次数（SPEC §2；与 ureq 默认值一致，显式写出便于对照）。
const MAX_REDIRECTS: u32 = 5;

/// 探测 `target`。`proxy_url = Some(...)` 时经该代理，`None` 直连（TUN 接管或真实直连）。
/// 任何 HTTP 响应（含 4xx/5xx）都算可达，网络错误/超时返回 [`ProbeResult::failed`]。
pub fn probe(proxy_url: Option<&str>, target: &Target) -> ProbeResult {
    match build_agent(proxy_url, Duration::from_secs(target.timeout_secs.max(1))) {
        Ok(agent) => probe_with(&agent, target),
        Err(err) => ProbeResult::failed(err),
    }
}

/// 构造可复用的 Agent。
///
/// `AgentBuilder::build()` 会加载系统根证书（实测约 60ms），一轮检查里每个目标
/// 各建一个 Agent 会把这份开销乘以目标数；一轮共用一个即可。
pub fn build_agent(proxy_url: Option<&str>, timeout: Duration) -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(MAX_REDIRECTS)
        .user_agent(USER_AGENT);
    if let Some(url) = proxy_url {
        match ureq::Proxy::new(url) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(err) => return Err(format!("代理地址无效：{err}")),
        }
    }
    Ok(builder.build())
}

/// 用已有 Agent 探测单个目标；每个请求单独设超时，互不影响。
pub fn probe_with(agent: &ureq::Agent, target: &Target) -> ProbeResult {
    let started = Instant::now();
    let timeout = Duration::from_secs(target.timeout_secs.max(1));
    // ureq 把 4xx/5xx 归到 Err(Status)；这里把两种"有响应"的分支合并成同一个 Response。
    let response = match agent.get(&target.anchor_url).timeout(timeout).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(err) => return ProbeResult::failed(transport_detail(&err)),
    };

    let status = response.status();
    let mut result = if target.anchor_kind == AnchorKind::Reachability {
        // 显式 reachability 不看响应体，有响应就够。
        ProbeResult {
            reachable: true,
            parsed_as: kind_tag(AnchorKind::Reachability).into(),
            detail: format!("有响应（HTTP {status}），按可达性判定"),
            ..ProbeResult::default()
        }
    } else {
        parse_anchor(
            target.anchor_kind,
            &read_body_limited(response.into_reader()),
        )
    };
    result.reachable = true;
    result.status = Some(status);
    result.latency_ms = started.elapsed().as_millis() as u64;
    result
}

/// 读取响应体（上限 [`MAX_BODY_BYTES`]）；非法 UTF-8 用替换字符兜底，读失败保留已读部分。
fn read_body_limited(reader: impl Read) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(16 * 1024);
    let _ = reader.take(MAX_BODY_BYTES).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 按目标声明的 kind 解析响应体；显式 kind 解析失败即"有响应但无出口信息"。
fn parse_anchor(kind: AnchorKind, body: &str) -> ProbeResult {
    let parsed = match kind {
        AnchorKind::Auto => return parse_auto(body),
        AnchorKind::Trace => parse_trace(body),
        AnchorKind::JsonIp => parse_json_ip(body),
        AnchorKind::GeminiRegion => parse_gemini_region(body),
        AnchorKind::Reachability => None,
    };
    parsed.unwrap_or_else(|| ProbeResult {
        reachable: true,
        parsed_as: kind_tag(kind).into(),
        detail: format!("{}解析失败，未识别到出口信息", kind.label()),
        ..ProbeResult::default()
    })
}

/// trace 文本解析：按行取 `ip=` / `loc=` / `colo=`，至少要有 ip 或 loc 之一。
pub fn parse_trace(text: &str) -> Option<ProbeResult> {
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
        city: None,
        latency_ms: 0,
        status: None,
        parsed_as: kind_tag(AnchorKind::Trace).into(),
        detail,
    })
}

/// JSON 解析：依次取 `ip/ip_address/query/origin` 与
/// `country/country_code/loc/region`（顶层对象优先，`data.` 子对象兜底）。
pub fn parse_json_ip(text: &str) -> Option<ProbeResult> {
    let text = text.trim_start_matches('\u{feff}').trim();
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let top = value.as_object()?;
    let mut objects: Vec<&serde_json::Map<String, serde_json::Value>> = vec![top];
    if let Some(data) = top.get("data").and_then(|value| value.as_object()) {
        objects.push(data);
    }
    let pick = |keys: &[&str]| -> Option<String> {
        for object in &objects {
            for key in keys {
                if let Some(text) = object.get(*key).and_then(|value| value.as_str()) {
                    let text = text.trim();
                    if !text.is_empty() {
                        return Some(text.to_string());
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

/// Gemini 页面地区标记：等价于正则 `,2,1,200,"([A-Z]{3})"` 的线性扫描
/// （页面近 1MB，手写扫描比编译正则更轻，且不引入额外依赖）。给地区、不给 IP。
pub fn parse_gemini_region(text: &str) -> Option<ProbeResult> {
    const MARKER: &str = ",2,1,200,\"";
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

/// auto 解析顺序（命中即停）：trace → json_ip → gemini_region → 仅可达性。
pub fn parse_auto(text: &str) -> ProbeResult {
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

fn kind_tag(kind: AnchorKind) -> &'static str {
    match kind {
        AnchorKind::Auto => "auto",
        AnchorKind::Trace => "trace",
        AnchorKind::JsonIp => "json_ip",
        AnchorKind::GeminiRegion => "gemini_region",
        AnchorKind::Reachability => "reachability",
    }
}

/// 网络错误的中文描述；不带"网络错误："前缀（policy 会补），便于拼 UI reason。
fn transport_detail(err: &ureq::Error) -> String {
    let label = match err.kind() {
        ureq::ErrorKind::Dns => "DNS 解析失败",
        ureq::ErrorKind::ConnectionFailed => "连接失败",
        ureq::ErrorKind::ProxyConnect => "代理连接失败",
        ureq::ErrorKind::ProxyUnauthorized => "代理认证失败",
        ureq::ErrorKind::InvalidProxyUrl => "代理地址无效",
        ureq::ErrorKind::TooManyRedirects => "重定向次数过多",
        ureq::ErrorKind::BadStatus | ureq::ErrorKind::BadHeader => "响应格式异常",
        ureq::ErrorKind::InvalidUrl => "锚点地址无效",
        ureq::ErrorKind::UnknownScheme => "锚点地址协议不支持",
        ureq::ErrorKind::InsecureRequestHttpsOnly => "请求被安全检查拒绝",
        ureq::ErrorKind::Io => "连接超时或中断",
        ureq::ErrorKind::HTTP => "HTTP 状态错误",
    };
    let message = err.to_string();
    if message.is_empty() {
        label.to_string()
    } else {
        format!("{label}：{message}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_panel() -> &'static str {
        "fl=20f123\nh=cloudflare.com\nip=204.1.100.98\nts=1729470000.123\nvisit_scheme=https\nuag=ClaudeGuard/3.0\ncolo=LAX\nsliver=none\nhttp=http/2\nloc=US\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n"
    }

    #[test]
    fn trace_reads_ip_region_and_colo() {
        let probe = parse_trace(trace_panel()).expect("trace 面板应能解析");
        assert_eq!(probe.parsed_as, "trace");
        assert!(probe.reachable);
        assert_eq!(probe.ip.as_deref(), Some("204.1.100.98"));
        assert_eq!(probe.country.as_deref(), Some("US"));
        assert_eq!(probe.raw_region.as_deref(), Some("US"));
        assert_eq!(probe.colo.as_deref(), Some("LAX"));
        assert!(probe.detail.contains("204.1.100.98"));
    }

    #[test]
    fn trace_requires_ip_or_region() {
        assert!(parse_trace("").is_none());
        assert!(parse_trace("colo=LAX\nwarp=off\nfl=20f123\n").is_none());
        assert!(parse_trace("随便一段没有等号的内容\n").is_none());
        // 只有地区也算命中
        let probe = parse_trace("loc=JP\n").expect("只有 loc 也应命中");
        assert_eq!(probe.country.as_deref(), Some("JP"));
        assert!(probe.ip.is_none());
    }

    #[test]
    fn trace_handles_crlf_and_comments() {
        let probe = parse_trace("# ip=9.9.9.9\r\nip=204.1.100.98\r\nloc=JPN\r\ncolo=NRT\r\n")
            .expect("CRLF 文本应能解析");
        assert_eq!(probe.ip.as_deref(), Some("204.1.100.98"));
        assert_eq!(probe.country.as_deref(), Some("JP"));
        assert_eq!(probe.raw_region.as_deref(), Some("JPN"));
        assert_eq!(probe.colo.as_deref(), Some("NRT"));
    }

    #[test]
    fn trace_keeps_unknown_region_raw() {
        let probe = parse_trace("ip=204.1.100.98\nloc=XYZ\n").expect("未知地区也应解析");
        assert!(probe.country.is_none());
        assert_eq!(probe.raw_region.as_deref(), Some("XYZ"));
    }

    #[test]
    fn json_reads_top_level_fields() {
        let text = r#"{"ip":"204.1.100.98","country":"USA","city":"Los Angeles","org":"AS123"}"#;
        let probe = parse_json_ip(text).expect("JSON 出口应能解析");
        assert_eq!(probe.parsed_as, "json_ip");
        assert_eq!(probe.ip.as_deref(), Some("204.1.100.98"));
        assert_eq!(probe.country.as_deref(), Some("US"));
        assert_eq!(probe.raw_region.as_deref(), Some("USA"));
        assert_eq!(probe.city.as_deref(), Some("Los Angeles"));
    }

    #[test]
    fn json_reads_nested_data_and_aliases() {
        let text = r#"{"data":{"ip_address":"198.51.100.24","country_code":"jp"}}"#;
        let probe = parse_json_ip(text).expect("data 子对象应能解析");
        assert_eq!(probe.ip.as_deref(), Some("198.51.100.24"));
        assert_eq!(probe.country.as_deref(), Some("JP"));
        assert!(probe.city.is_none());
    }

    #[test]
    fn json_prefers_first_alias_in_order() {
        let text = r#"{"query":"1.1.1.1","ip":"204.1.100.98"}"#;
        let probe = parse_json_ip(text).expect("别名应能解析");
        assert_eq!(probe.ip.as_deref(), Some("204.1.100.98"));
    }

    #[test]
    fn json_rejects_bad_or_informationaless_payloads() {
        assert!(parse_json_ip("not json at all").is_none());
        assert!(parse_json_ip(r#"{"foo":"bar","count":3}"#).is_none());
        assert!(parse_json_ip(r#"["ip","1.1.1.1"]"#).is_none());
        // 合法 JSON 但没有 ip/地区字段 → 交给后面的解析器
        assert!(parse_json_ip(r#"{"city":"Tokyo"}"#).is_none());
    }

    #[test]
    fn gemini_reads_region_marker() {
        let page = r#"abc,2,1,200,"USA",null,123,2,1,200,"JPN",null,456"#;
        let probe = parse_gemini_region(page).expect("地区标记应能解析");
        assert_eq!(probe.parsed_as, "gemini_region");
        assert_eq!(probe.raw_region.as_deref(), Some("USA"));
        assert_eq!(probe.country.as_deref(), Some("US"));
        assert!(probe.ip.is_none());
    }

    #[test]
    fn gemini_skips_invalid_candidates() {
        // 大小写不符 / 长度不符的候选要跳过，继续找下一个合法标记。
        assert!(parse_gemini_region(r#",2,1,200,"usa",",2,1,200,"xz",",2,1,200,"JP""#).is_none());
        let probe =
            parse_gemini_region(r#",2,1,200,"us",,2,1,200,"JPN""#).expect("应跳到后面的合法标记");
        assert_eq!(probe.raw_region.as_deref(), Some("JPN"));
        assert_eq!(probe.country.as_deref(), Some("JP"));
    }

    #[test]
    fn gemini_scans_large_page() {
        let mut page = "x".repeat(800 * 1024);
        page.push_str(r#",2,1,200,"HKG","#);
        let probe = parse_gemini_region(&page).expect("800KB 页面也应能解析");
        assert_eq!(probe.country.as_deref(), Some("HK"));
        assert_eq!(probe.raw_region.as_deref(), Some("HKG"));
    }

    #[test]
    fn auto_prefers_trace_over_json_and_gemini() {
        let text = "ip=204.1.100.98\nloc=US\n{\"ip\":\"9.9.9.9\"},2,1,200,\"JPN\"";
        let probe = parse_auto(text);
        assert_eq!(probe.parsed_as, "trace");
        assert_eq!(probe.ip.as_deref(), Some("204.1.100.98"));
        assert_eq!(probe.country.as_deref(), Some("US"));
    }

    #[test]
    fn auto_prefers_json_over_gemini() {
        let text = r#"{"ip":"204.1.100.98","note":",2,1,200,\"JPN\""}"#;
        let probe = parse_auto(text);
        assert_eq!(probe.parsed_as, "json_ip");
        assert_eq!(probe.ip.as_deref(), Some("204.1.100.98"));
    }

    #[test]
    fn auto_falls_back_to_gemini_then_reachability() {
        let gemini = parse_auto(r#"prefix,2,1,200,"SGP",suffix"#);
        assert_eq!(gemini.parsed_as, "gemini_region");
        assert_eq!(gemini.country.as_deref(), Some("SG"));

        let unknown = parse_auto("<html>hello</html>");
        assert_eq!(unknown.parsed_as, "reachability");
        assert!(unknown.reachable);
        assert!(unknown.ip.is_none());
        assert!(unknown.country.is_none());
        assert!(unknown.detail.contains("未识别"));
    }

    #[test]
    fn body_read_is_capped_at_limit() {
        let oversized = std::io::Cursor::new(vec![b'x'; MAX_BODY_BYTES as usize + 512]);
        let text = read_body_limited(oversized);
        assert_eq!(text.len() as u64, MAX_BODY_BYTES);

        let small = read_body_limited(std::io::Cursor::new(b"ip=1.1.1.1\nloc=US\n".to_vec()));
        assert_eq!(small, "ip=1.1.1.1\nloc=US\n");
    }
}
