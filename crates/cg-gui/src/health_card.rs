//! Pure-Rust zero-external-dep Desensitized Pre-Flight Health Card generator (M7).
//!
//! Produces:
//! 1. Allowlisted, strictly redacted [`SanitizedHealthCard`] metadata + Markdown table snippet.
//! 2. Lossless `1200 x 680` Frost Ceramic / Obsidian PNG poster rendered in pure Rust
//!    with ZERO `tEXt`/`iTXt`/`zTXt` metadata chunks so raw IPs and Windows usernames
//!    can NEVER leak into either Markdown or PNG output.

use crate::protocol::{
    AsnClassification, GuardSnapshot, SafetyGrade, SanitizedHealthCard, TargetState,
};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const CARD_WIDTH: u32 = 1200;
pub const CARD_HEIGHT: u32 = 680;

/// Returns true if `text` contains any raw IPv4 literal or IPv6 literal.
pub fn contains_any_ip_literal(text: &str) -> bool {
    // 1. Scan for IPv4 literals (`a.b.c.d` where all 4 octets are valid u8).
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let token = text[start..i].trim_matches('.');
            if token.matches('.').count() == 3 && token.parse::<Ipv4Addr>().is_ok() {
                return true;
            }
        } else {
            i += 1;
        }
    }

    // 2. Scan for IPv6 literals (tokens with `::` or >=2 colons containing hex groups).
    for raw_tok in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ',' | ';' | '(' | ')' | '[' | ']' | '"' | '\'' | '<' | '>'
            )
    }) {
        let tok = raw_tok.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != ':');
        if tok.len() >= 4 && tok.matches(':').count() >= 2 {
            // Exclude HH:MM:SS timestamps (3 segments of pure 1-2 decimal digits without `::`).
            let segs: Vec<&str> = tok.split(':').collect();
            let looks_like_hms = !tok.contains("::")
                && segs.len() == 3
                && segs.iter().all(|s| {
                    !s.is_empty() && s.len() <= 2 && s.bytes().all(|b| b.is_ascii_digit())
                });
            if !looks_like_hms
                && segs
                    .iter()
                    .all(|s| s.len() <= 4 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                && tok.parse::<std::net::Ipv6Addr>().is_ok()
            {
                return true;
            }
        }
    }
    false
}

/// Returns true if `text` contains a Windows user profile path (`\Users\<name>` / `/Users/<name>`)
/// or the active OS username (when `>= 3` ASCII/UTF-8 chars and not a generic protocol token).
pub fn contains_windows_username(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("\\users\\") || lower.contains("/users/") {
        return true;
    }
    if let Ok(user) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
        let u = user.trim();
        if u.len() >= 3 {
            let u_lower = u.to_ascii_lowercase();
            // Avoid false positives if someone's username happens to be a generic UI word.
            let generic = matches!(
                u_lower.as_str(),
                "user" | "admin" | "root" | "test" | "local" | "guest" | "system" | "default"
            );
            if !generic && lower.contains(&u_lower) {
                return true;
            }
        }
    }
    false
}

/// Strips any raw IPv4/IPv6 tokens and Windows user-profile segments from arbitrary text.
pub fn redact_sensitive_tokens(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let cand = &input[start..i];
            if cand.trim_matches('.').matches('.').count() == 3
                && cand.trim_matches('.').parse::<Ipv4Addr>().is_ok()
            {
                out.push_str("[REDACTED]");
            } else {
                out.push_str(cand);
            }
        } else {
            let ch = input[i..].chars().next().expect("valid utf8");
            out.push(ch);
            i += ch.len_utf8();
        }
    }

    // Also scrub `\Users\<name>` or `/Users/<name>` paths if ever present.
    let mut cleaned = out;
    for marker in ["\\Users\\", "\\users\\", "/Users/", "/users/"] {
        while let Some(pos) = cleaned.find(marker) {
            let start = pos + marker.len();
            let rest = &cleaned[start..];
            let end_rel = rest
                .find(['\\', '/', ' ', '\t', '\n', '\r', ')', ']'])
                .unwrap_or(rest.len());
            let mut next = String::with_capacity(cleaned.len());
            next.push_str(&cleaned[..pos]);
            next.push_str("[REDACTED_PATH]");
            next.push_str(&rest[end_rel..]);
            cleaned = next;
        }
    }

    // Scrub raw IPv6 tokens if any remain.
    if contains_any_ip_literal(&cleaned) {
        let words: Vec<String> = cleaned
            .split(' ')
            .map(|w| {
                if contains_any_ip_literal(w) {
                    "[REDACTED]".to_string()
                } else {
                    w.to_string()
                }
            })
            .collect();
        cleaned = words.join(" ");
    }

    // Scrub current Windows username if non-generic.
    if let Ok(user) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
        let u = user.trim();
        if u.len() >= 3 {
            let u_lower = u.to_ascii_lowercase();
            let generic = matches!(
                u_lower.as_str(),
                "user" | "admin" | "root" | "test" | "local" | "guest" | "system" | "default"
            );
            if !generic {
                cleaned = replace_case_insensitive(&cleaned, u, "[REDACTED]");
            }
        }
    }

    cleaned
}

fn replace_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let h_lower = haystack.to_ascii_lowercase();
    let n_lower = needle.to_ascii_lowercase();
    if h_lower.len() != haystack.len() || !h_lower.contains(&n_lower) {
        return haystack.to_string();
    }
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0usize;
    for (idx, _) in h_lower.match_indices(&n_lower) {
        if haystack.is_char_boundary(idx) && haystack.is_char_boundary(idx + needle.len()) {
            out.push_str(&haystack[last..idx]);
            out.push_str(replacement);
            last = idx + needle.len();
        }
    }
    out.push_str(&haystack[last..]);
    out
}

fn macro_region_zh(country: &str) -> (&'static str, &'static str) {
    match country.trim().to_ascii_uppercase().as_str() {
        "US" | "CA" => ("北美大区", "NORTH AMERICA"),
        "JP" | "KR" | "TW" => ("东亚合规区", "EAST ASIA"),
        "SG" => ("东南亚合规区", "SE ASIA"),
        "GB" | "IE" | "DE" | "FR" | "NL" | "SE" | "CH" | "FI" | "NO" => ("欧洲大区", "EUROPE"),
        "AU" | "NZ" => ("大洋洲大区", "OCEANIA"),
        "HK" | "CN" | "RU" => ("受限地区", "RESTRICTED"),
        _ => ("海外节点", "OVERSEAS"),
    }
}

fn grade_title_zh(grade: SafetyGrade) -> &'static str {
    match grade {
        SafetyGrade::S => "S 级 · 极低封号风险",
        SafetyGrade::A => "A 级 · 出口纯净合规",
        SafetyGrade::B => "B 级 · 可用（建议优化）",
        SafetyGrade::C => "C 级 · 存在风控隐患",
        SafetyGrade::F => "F 级 · 高危封号风险",
    }
}

fn ascii_asn_label(class: AsnClassification) -> &'static str {
    match class {
        AsnClassification::IspResidential => "NATIVE ISP RESIDENTIAL",
        AsnClassification::BusinessIsp => "BUSINESS ISP LINE",
        AsnClassification::MobileCellular => "MOBILE CARRIER",
        AsnClassification::EducationGov => "EDU / GOV NETWORK",
        AsnClassification::DatacenterHosting => "DATACENTER / VPS",
        AsnClassification::PublicProxyVpnTor => "SHARED VPN / TOR",
        AsnClassification::Unknown => "UNCLASSIFIED ASN",
    }
}

/// Builds a strictly allowlisted, desensitized shareable Health Card from a live [`GuardSnapshot`].
///
/// Guarantees ZERO raw IP literals and ZERO Windows usernames leak into any field or Markdown snippet.
pub fn build_sanitized_health_card(snap: &GuardSnapshot, now_secs: u64) -> SanitizedHealthCard {
    let risk = &snap.risk_assessment;
    let safety_score = if risk.evaluated_at > 0 {
        risk.score
    } else if snap.is_tripped() {
        25
    } else if snap.all_enabled_pass() {
        88
    } else {
        55
    };
    let grade = if risk.evaluated_at > 0 {
        risk.grade
    } else {
        SafetyGrade::from_score(safety_score)
    };

    // Strict allowlist: country ISO-2 code + broad macro-region ONLY (never real city or IP).
    let country_code = risk
        .ip_purity
        .country
        .as_deref()
        .or_else(|| {
            snap.targets
                .iter()
                .find(|t| t.state == TargetState::Pass && t.country.is_some())
                .and_then(|t| t.country.as_deref())
        })
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
        .unwrap_or_else(|| "UN".into());
    let (macro_zh, _macro_en) = macro_region_zh(&country_code);
    let region_badge = if country_code == "UN" {
        "待探测 · 未知大区".to_string()
    } else {
        format!("{country_code} · {macro_zh}")
    };

    // ASN purity badge: classification + fraud score ONLY (never IP or org leak).
    let asn_purity_badge = format!(
        "{} · 欺诈值 {}%",
        risk.ip_purity.classification.label_zh(),
        risk.ip_purity.abuse_risk_score.min(100)
    );

    // WFP kernel shield badge.
    let wfp_shield_badge = if snap.wfp.sublayer_registered && snap.wfp.dynamic_session_open {
        if snap.wfp.boot_time_filters_armed {
            "WFP 动态+开机双子层已激活 (0ms 防抢跑)".to_string()
        } else {
            "WFP 动态子层已激活 (0ms 防抢跑)".to_string()
        }
    } else if snap.leak_shield.enabled {
        format!(
            "应用级防漏护盾生效 ({} 条规则)",
            snap.leak_shield.active_rules
        )
    } else {
        "基础守卫就绪".to_string()
    };

    // Protocol leak & DNS coherence badge.
    let stun_txt = if risk.stun_leak.leaked {
        "STUN 存在穿透"
    } else {
        "WebRTC STUN 0 泄露"
    };
    let quic_txt = if snap.leak_shield.quic_blocked || risk.electron_hygiene.quic_disabled_flag {
        "QUIC 已封堵"
    } else {
        "QUIC 未封堵"
    };
    let dns_txt = if risk.dns_coherence.domestic_resolver_detected {
        "DNS 疑似分流异常"
    } else if risk.dns_coherence.coherent {
        "DNS 地理一致"
    } else {
        "DNS 待核验"
    };
    let leak_hygiene_badge = format!("{stun_txt} · {quic_txt} · {dns_txt}");

    // Spatiotemporal geo-velocity stability badge (never city names or IPs).
    let geo_stability_badge = if risk.geo_velocity_alert.is_some() {
        "检测到跨洲瞬移预警 · 已触发防封冷却".to_string()
    } else {
        format!(
            "0 次跨洲瞬移 · 24h 涉及 {} 国",
            risk.distinct_countries_24h.max(1)
        )
    };

    // Sovereign vault & CLI hook badge (counts & latency only, never user-chosen names).
    let vault_count = snap.vaults.len().max(snap.config.vaults.len());
    let hook_txt = if snap.hooks.claude_code_hook_installed {
        let lat_ms = (snap.hooks.last_gate_latency_us as f64 / 1000.0).max(0.1);
        format!("CLI 门禁 {:.1}ms", lat_ms)
    } else {
        "CLI 门禁待接入".to_string()
    };
    let vault_isolation_badge = format!("{vault_count} 账号物理分仓 · {hook_txt}");

    let cg_version = if snap.version.trim().is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        redact_sensitive_tokens(snap.version.trim())
    };

    let raw_md = format!(
        concat!(
            "### 🛡️ ClaudeGuard v5 防封体检报告卡\n\n",
            "- **综合防封安全分**：**{score} / 100**（`{grade_title}`）\n",
            "- **脱敏出口大区**：`{region}`\n\n",
            "| 审计维度 | 实测状态 |\n",
            "| :--- | :--- |\n",
            "| 出口纯净度 | {asn} |\n",
            "| 内核级护盾 | {wfp} |\n",
            "| 协议零泄露 | {leak} |\n",
            "| 时空轨迹稳定度 | {geo} |\n",
            "| 主权隔离与门禁 | {vault} |\n\n",
            "> 由 ClaudeGuard v{ver} 本地离线审计生成 · 零真实 IP / 零用户名 / 零隐私路径包含\n"
        ),
        score = safety_score,
        grade_title = grade_title_zh(grade),
        region = region_badge,
        asn = asn_purity_badge,
        wfp = wfp_shield_badge,
        leak = leak_hygiene_badge,
        geo = geo_stability_badge,
        vault = vault_isolation_badge,
        ver = cg_version,
    );

    let markdown_snippet = redact_sensitive_tokens(&raw_md);
    debug_assert!(
        !contains_any_ip_literal(&markdown_snippet),
        "health card markdown must never contain raw IP literals"
    );
    debug_assert!(
        !contains_windows_username(&markdown_snippet),
        "health card markdown must never contain Windows usernames"
    );

    SanitizedHealthCard {
        generated_at: now_secs,
        cg_version,
        safety_score,
        grade,
        region_badge: redact_sensitive_tokens(&region_badge),
        asn_purity_badge: redact_sensitive_tokens(&asn_purity_badge),
        wfp_shield_badge: redact_sensitive_tokens(&wfp_shield_badge),
        leak_hygiene_badge: redact_sensitive_tokens(&leak_hygiene_badge),
        geo_stability_badge: redact_sensitive_tokens(&geo_stability_badge),
        vault_isolation_badge: redact_sensitive_tokens(&vault_isolation_badge),
        markdown_snippet,
        saved_png_path: None,
    }
}

/// Renders a lossless `1200 x 680` Frost Ceramic (light) or Obsidian (dark) PNG poster
/// directly in pure Rust with ZERO external crates and ZERO text metadata chunks.
pub fn render_health_card_png(
    card: &SanitizedHealthCard,
    snap: Option<&GuardSnapshot>,
    is_dark: bool,
) -> Vec<u8> {
    let w = CARD_WIDTH as usize;
    let h = CARD_HEIGHT as usize;
    let mut canvas = RgbCanvas::new(
        w,
        h,
        if is_dark {
            (16, 20, 28)
        } else {
            (244, 247, 251)
        },
    );

    // Palette tokens following Frost Ceramic Light / Obsidian Dark harmony.
    let card_bg = if is_dark {
        (26, 32, 44)
    } else {
        (255, 255, 255)
    };
    let inset_bg = if is_dark {
        (20, 25, 36)
    } else {
        (246, 248, 252)
    };
    let border_col = if is_dark {
        (46, 56, 76)
    } else {
        (222, 228, 238)
    };
    let ink_primary = if is_dark {
        (241, 245, 249)
    } else {
        (15, 23, 42)
    };
    let ink_muted = if is_dark {
        (148, 163, 184)
    } else {
        (100, 116, 139)
    };
    let accent = match card.grade {
        SafetyGrade::S | SafetyGrade::A => {
            if is_dark {
                (52, 211, 153)
            } else {
                (16, 163, 127)
            }
        }
        SafetyGrade::B | SafetyGrade::C => {
            if is_dark {
                (251, 191, 36)
            } else {
                (217, 119, 6)
            }
        }
        SafetyGrade::F => {
            if is_dark {
                (248, 113, 113)
            } else {
                (220, 38, 38)
            }
        }
    };
    let ring_track = if is_dark {
        (40, 49, 68)
    } else {
        (229, 235, 245)
    };

    // Outer frame card.
    canvas.fill_rounded_rect(28, 28, w - 56, h - 56, 26, card_bg, Some(border_col));

    // Top brand header strip.
    canvas.draw_text(68, 58, 3, "CLAUDEGUARD V5 SOVEREIGN SHIELD", ink_primary);
    canvas.draw_text(
        68,
        92,
        2,
        "PRE-FLIGHT ANTI-BAN HEALTH CARD  |  ZERO IP / ZERO PII",
        ink_muted,
    );

    // Top-right region pill (pure country ISO-2 + macro region ASCII).
    let cc = card
        .region_badge
        .split_whitespace()
        .next()
        .filter(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase()))
        .unwrap_or("UN");
    let (_, macro_en) = macro_region_zh(cc);
    let region_ascii = format!("REGION: {cc} - {macro_en}");
    canvas.fill_rounded_rect(790, 56, 342, 48, 14, inset_bg, Some(border_col));
    canvas.draw_text(812, 73, 2, &region_ascii, ink_primary);

    // Left hero gauge panel.
    canvas.fill_rounded_rect(64, 132, 376, 444, 22, inset_bg, Some(border_col));
    let cx = 252.0_f32;
    let cy = 304.0_f32;
    canvas.draw_score_ring(
        cx,
        cy,
        118.0,
        20.0,
        card.safety_score as f32 / 100.0,
        ring_track,
        accent,
    );

    let score_str = format!("{}", card.safety_score);
    let score_w = measure_text_px(&score_str, 8);
    canvas.draw_text(
        (cx as usize).saturating_sub(score_w / 2),
        262,
        8,
        &score_str,
        ink_primary,
    );
    let denom = "/ 100";
    let denom_w = measure_text_px(denom, 2);
    canvas.draw_text(
        (cx as usize).saturating_sub(denom_w / 2),
        336,
        2,
        denom,
        ink_muted,
    );

    // Grade pill inside left panel.
    canvas.fill_rounded_rect(122, 464, 260, 52, 16, card_bg, Some(accent));
    let grade_txt = format!("GRADE {}  SAFETY SCORE", card.grade.code());
    let gw = measure_text_px(&grade_txt, 2);
    canvas.draw_text(
        (252usize).saturating_sub(gw / 2),
        483,
        2,
        &grade_txt,
        accent,
    );

    // Right 2x3 metrics Bento grid (pure ASCII desensitized telemetry).
    let asn_line = snap
        .map(|s| {
            format!(
                "{} (ABUSE {}%)",
                ascii_asn_label(s.risk_assessment.ip_purity.classification),
                s.risk_assessment.ip_purity.abuse_risk_score.min(100)
            )
        })
        .unwrap_or_else(|| "ISP PURITY VERIFIED".into());
    let wfp_line = snap
        .map(|s| {
            if s.wfp.sublayer_registered {
                format!("WFP DYNAMIC ({} FILTERS)", s.wfp.active_filter_count)
            } else {
                format!("SHIELD ACTIVE ({} RULES)", s.leak_shield.active_rules)
            }
        })
        .unwrap_or_else(|| "KERNEL SHIELD ARMED".into());
    let stun_line = snap
        .map(|s| {
            if s.risk_assessment.stun_leak.leaked {
                "STUN LEAK DETECTED".to_string()
            } else {
                "STUN 0 LEAK / QUIC BLOCKED".to_string()
            }
        })
        .unwrap_or_else(|| "WEBRTC / QUIC HARDENED".into());
    let dns_line = snap
        .map(|s| {
            if s.risk_assessment.dns_coherence.domestic_resolver_detected {
                "DNS MISMATCH ALERT".to_string()
            } else {
                "REMOTE DNS COHERENT".to_string()
            }
        })
        .unwrap_or_else(|| "DNS COHERENCE OK".into());
    let geo_line = snap
        .map(|s| {
            if s.risk_assessment.geo_velocity_alert.is_some() {
                "GEO-VELOCITY COOLDOWN".to_string()
            } else {
                format!(
                    "0 TELEPORTS / {} COUNTRY 24H",
                    s.risk_assessment.distinct_countries_24h.max(1)
                )
            }
        })
        .unwrap_or_else(|| "STABLE EGRESS TRAJECTORY".into());
    let vault_line = snap
        .map(|s| {
            let vc = s.vaults.len().max(s.config.vaults.len());
            let lat_us = s.hooks.last_gate_latency_us;
            format!("{vc} VAULTS / HOOK {lat_us}US")
        })
        .unwrap_or_else(|| "SOVEREIGN ISOLATION READY".into());

    let tiles: [(&str, String); 6] = [
        ("01  EGRESS ASN PURITY", asn_line),
        ("02  KERNEL WFP SHIELD", wfp_line),
        ("03  WEBRTC & QUIC HYGIENE", stun_line),
        ("04  DNS & TIMEZONE COHERENCE", dns_line),
        ("05  7D GEO-VELOCITY LEDGER", geo_line),
        ("06  VAULTS & CLI FAST GATE", vault_line),
    ];

    for (idx, (kicker, value)) in tiles.iter().enumerate() {
        let col = idx % 2;
        let row = idx / 2;
        let tx = 468 + col * 340;
        let ty = 132 + row * 154;
        canvas.fill_rounded_rect(tx, ty, 322, 134, 18, inset_bg, Some(border_col));
        canvas.fill_rounded_rect(tx + 20, ty + 24, 8, 22, 4, accent, None);
        canvas.draw_text(tx + 38, ty + 28, 2, kicker, ink_muted);
        let safe_val = sanitize_ascii_only(&redact_sensitive_tokens(value));
        let clipped: String = safe_val.chars().take(24).collect();
        canvas.draw_text(tx + 22, ty + 74, 2, &clipped, ink_primary);
    }

    // Bottom footer bar.
    let safe_ver = sanitize_ascii_only(&card.cg_version);
    let footer = format!(
        "GENERATED LOCALLY BY CLAUDEGUARD V{safe_ver}  |  STRICT ALLOWLIST REDACTION  |  NO RAW IP OR USERNAME"
    );
    canvas.draw_text(68, 608, 2, &footer, ink_muted);

    encode_png_rgb_lossless(CARD_WIDTH, CARD_HEIGHT, &canvas.rgb)
}

/// Exports the desensitized PNG health card to `dir` (or Desktop / temp directory) and updates `card.saved_png_path`.
pub fn export_health_card_png(
    card: &mut SanitizedHealthCard,
    snap: Option<&GuardSnapshot>,
    is_dark: bool,
    dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let target_dir = if let Some(d) = dir {
        d.to_path_buf()
    } else if let Some(profile) = std::env::var_os("USERPROFILE") {
        let desktop = PathBuf::from(profile).join("Desktop");
        if desktop.is_dir() {
            desktop
        } else {
            std::env::temp_dir()
        }
    } else {
        std::env::temp_dir()
    };
    std::fs::create_dir_all(&target_dir).map_err(|e| format!("无法创建导出目录：{}", e))?;
    let filename = format!("ClaudeGuard-HealthCard-{}.png", card.generated_at);
    let path = target_dir.join(filename);
    let png_bytes = render_health_card_png(card, snap, is_dark);
    std::fs::write(&path, &png_bytes).map_err(|e| format!("写入防封体检卡 PNG 失败：{}", e))?;
    card.saved_png_path = Some(path.to_string_lossy().into_owned());
    Ok(path)
}

fn sanitize_ascii_only(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c.to_ascii_uppercase()
            } else {
                ' '
            }
        })
        .collect()
}

// ==================== Pure-Rust RGB Canvas & 5x7 Pixel Font ====================

struct RgbCanvas {
    w: usize,
    h: usize,
    rgb: Vec<u8>,
}

impl RgbCanvas {
    fn new(w: usize, h: usize, bg: (u8, u8, u8)) -> Self {
        let mut rgb = vec![0u8; w * h * 3];
        for px in rgb.as_chunks_mut::<3>().0 {
            px[0] = bg.0;
            px[1] = bg.1;
            px[2] = bg.2;
        }
        Self { w, h, rgb }
    }

    #[inline]
    fn blend_pixel(&mut self, x: usize, y: usize, col: (u8, u8, u8), alpha: f32) {
        if x >= self.w || y >= self.h || alpha <= 0.001 {
            return;
        }
        let a = alpha.clamp(0.0, 1.0);
        let idx = (y * self.w + x) * 3;
        if a >= 0.999 {
            self.rgb[idx] = col.0;
            self.rgb[idx + 1] = col.1;
            self.rgb[idx + 2] = col.2;
        } else {
            let inv = 1.0 - a;
            self.rgb[idx] = (self.rgb[idx] as f32 * inv + col.0 as f32 * a).round() as u8;
            self.rgb[idx + 1] = (self.rgb[idx + 1] as f32 * inv + col.1 as f32 * a).round() as u8;
            self.rgb[idx + 2] = (self.rgb[idx + 2] as f32 * inv + col.2 as f32 * a).round() as u8;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fill_rounded_rect(
        &mut self,
        x0: usize,
        y0: usize,
        rw: usize,
        rh: usize,
        radius: usize,
        fill: (u8, u8, u8),
        border: Option<(u8, u8, u8)>,
    ) {
        let r = (radius as f32).min(rw as f32 * 0.5).min(rh as f32 * 0.5);
        let x1 = (x0 + rw).min(self.w);
        let y1 = (y0 + rh).min(self.h);
        let cx = x0 as f32 + rw as f32 * 0.5;
        let cy = y0 as f32 + rh as f32 * 0.5;
        let hx = rw as f32 * 0.5 - r;
        let hy = rh as f32 * 0.5 - r;

        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let qy = (py - cy).abs() - hy;
            for x in x0..x1 {
                let px = x as f32 + 0.5;
                let qx = (px - cx).abs() - hx;
                let dist = qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0) - r;
                if dist <= 0.5 {
                    let cov = (0.5 - dist).clamp(0.0, 1.0);
                    let col = if let Some(bcol) = border {
                        if dist > -1.5 { bcol } else { fill }
                    } else {
                        fill
                    };
                    self.blend_pixel(x, y, col, cov);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_score_ring(
        &mut self,
        cx: f32,
        cy: f32,
        radius: f32,
        thickness: f32,
        fraction: f32,
        track_col: (u8, u8, u8),
        arc_col: (u8, u8, u8),
    ) {
        let frac = fraction.clamp(0.0, 1.0);
        let half_t = thickness * 0.5;
        let pad = (radius + half_t + 3.0).ceil() as isize;
        let min_x = ((cx as isize) - pad).max(0) as usize;
        let max_x = ((cx as isize) + pad).min(self.w as isize - 1) as usize;
        let min_y = ((cy as isize) - pad).max(0) as usize;
        let max_y = ((cy as isize) + pad).min(self.h as isize - 1) as usize;
        let sweep = frac * std::f32::consts::TAU;

        for y in min_y..=max_y {
            let dy = (y as f32 + 0.5) - cy;
            for x in min_x..=max_x {
                let dx = (x as f32 + 0.5) - cx;
                let d = dx.hypot(dy);
                let ring_sdf = (d - radius).abs() - half_t;
                if ring_sdf <= 0.8 {
                    let cov = (0.8 - ring_sdf).clamp(0.0, 1.0);
                    // Clockwise from 12 o'clock (-PI/2).
                    let mut angle = dy.atan2(dx) + std::f32::consts::FRAC_PI_2;
                    if angle < 0.0 {
                        angle += std::f32::consts::TAU;
                    }
                    let col = if angle <= sweep { arc_col } else { track_col };
                    self.blend_pixel(x, y, col, cov);
                }
            }
        }
    }

    fn draw_text(&mut self, mut x: usize, y: usize, scale: usize, text: &str, col: (u8, u8, u8)) {
        let step = 6 * scale;
        for ch in text.chars() {
            let glyph = glyph_5x7(ch.to_ascii_uppercase());
            for (row_idx, &bits) in glyph.iter().enumerate() {
                for col_idx in 0..5usize {
                    if (bits & (1 << (4 - col_idx))) != 0 {
                        for sy in 0..scale {
                            for sx in 0..scale {
                                self.blend_pixel(
                                    x + col_idx * scale + sx,
                                    y + row_idx * scale + sy,
                                    col,
                                    1.0,
                                );
                            }
                        }
                    }
                }
            }
            x = x.saturating_add(step);
            if x >= self.w {
                break;
            }
        }
    }
}

fn measure_text_px(text: &str, scale: usize) -> usize {
    let count = text.chars().count();
    if count == 0 {
        0
    } else {
        count * 6 * scale - scale
    }
}

fn glyph_5x7(ch: char) -> [u8; 7] {
    match ch {
        'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'B' => [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
        'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        'D' => [0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C],
        'E' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
        'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        'G' => [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F],
        'H' => [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'I' => [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
        'J' => [0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C],
        'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
        'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        'Q' => [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
        'R' => [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
        'S' => [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
        'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11],
        'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        'Y' => [0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04],
        'Z' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
        '0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        '1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        '2' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
        '3' => [0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E],
        '4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        '5' => [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
        '6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        '7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        '9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        '-' => [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
        '/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        ':' => [0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
        '|' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        '%' => [0x19, 0x19, 0x02, 0x04, 0x08, 0x13, 0x13],
        '(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        ')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        '&' => [0x0C, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0D],
        '+' => [0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00],
        _ => [0x00; 7],
    }
}

// ==================== Pure-Rust Lossless PNG Encoder (Zero Metadata) ====================

fn encode_png_rgb_lossless(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    let row_bytes = width as usize * 3;
    let mut raw = Vec::with_capacity((row_bytes + 1) * height as usize);
    for y in 0..height as usize {
        raw.push(0u8); // Filter type 0 (None)
        let start = y * row_bytes;
        raw.extend_from_slice(&rgb[start..start + row_bytes]);
    }

    let zlib_data = wrap_zlib_stored(&raw);

    let mut out = Vec::with_capacity(64 + zlib_data.len());
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8; // bit depth
    ihdr[9] = 2; // color type: Truecolor RGB
    ihdr[10] = 0; // compression: deflate
    ihdr[11] = 0; // filter
    ihdr[12] = 0; // interlace: none
    write_png_chunk(&mut out, *b"IHDR", &ihdr);
    write_png_chunk(&mut out, *b"IDAT", &zlib_data);
    write_png_chunk(&mut out, *b"IEND", &[]);
    out
}

fn write_png_chunk(dst: &mut Vec<u8>, chunk_type: [u8; 4], data: &[u8]) {
    dst.extend_from_slice(&(data.len() as u32).to_be_bytes());
    dst.extend_from_slice(&chunk_type);
    dst.extend_from_slice(data);
    let mut crc = crc32_update(0xFFFF_FFFF, &chunk_type);
    crc = crc32_update(crc, data);
    dst.extend_from_slice(&(!crc).to_be_bytes());
}

fn wrap_zlib_stored(raw: &[u8]) -> Vec<u8> {
    const MAX_BLOCK: usize = 65_535;
    let blocks = raw.len().div_ceil(MAX_BLOCK).max(1);
    let mut out = Vec::with_capacity(2 + raw.len() + blocks * 5 + 4);
    // Zlib header: CMF=0x78 (deflate, 32K window), FLG=0x01 (FCHECK valid, no dict).
    out.push(0x78);
    out.push(0x01);

    let mut offset = 0usize;
    while offset < raw.len() || offset == 0 {
        let end = (offset + MAX_BLOCK).min(raw.len());
        let is_final = end >= raw.len();
        let len = (end - offset) as u16;
        let nlen = !len;
        out.push(u8::from(is_final));
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(&raw[offset..end]);
        offset = end;
        if is_final {
            break;
        }
    }

    let adler = adler32(raw);
    out.extend_from_slice(&adler.to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::{DemoScenario, build_demo_snapshot};

    #[test]
    fn ip_and_username_detectors_catch_leaks_cleanly() {
        assert!(contains_any_ip_literal("egress 198.51.100.98 ok"));
        assert!(contains_any_ip_literal("ipv6 2001:db8::1 leaked"));
        assert!(!contains_any_ip_literal(
            "ClaudeGuard v5.0.0 at 12:34:56 score 94/100"
        ));
        assert!(contains_windows_username(
            r"C:\Users\alice\AppData\Local\Claude"
        ));
        assert!(!contains_windows_username("US · 北美大区 · 原生住宅 ISP"));
    }

    #[test]
    fn health_card_markdown_and_png_leak_zero_ips_and_zero_usernames() {
        let mut snap = build_demo_snapshot(DemoScenario::Pass);
        // Inject raw IPs & Windows paths into snapshot fields to verify hard redaction.
        snap.risk_assessment.ip_purity.ip = Some("198.51.100.98".into());
        snap.risk_assessment.ip_purity.city = Some("Los Angeles".into());
        snap.risk_assessment.stun_leak.reflexive_ip = Some("203.0.113.45".into());
        snap.vaults[0].vault_dir = r"C:\Users\alice_secret\AppData\Local\ClaudeGuard\vaults".into();

        let card = build_sanitized_health_card(&snap, 1_760_000_123);
        assert_eq!(card.safety_score, 94);
        assert_eq!(card.grade, SafetyGrade::S);
        assert!(card.region_badge.starts_with("US"));
        assert!(!card.region_badge.contains("Los Angeles"));

        for field in [
            &card.region_badge,
            &card.asn_purity_badge,
            &card.wfp_shield_badge,
            &card.leak_hygiene_badge,
            &card.geo_stability_badge,
            &card.vault_isolation_badge,
            &card.markdown_snippet,
        ] {
            assert!(
                !contains_any_ip_literal(field),
                "IP literal leaked in field: {field}"
            );
            assert!(
                !contains_windows_username(field),
                "username leaked in field: {field}"
            );
            assert!(!field.contains("198.51.100.98"));
            assert!(!field.contains("203.0.113.45"));
            assert!(!field.contains("alice_secret"));
        }

        // Verify pure-Rust lossless PNG output headers, dimensions, zero text metadata, and zero leaks.
        for dark in [false, true] {
            let png = render_health_card_png(&card, Some(&snap), dark);
            assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
            assert_eq!(&png[12..16], b"IHDR");
            let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
            let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
            assert_eq!((w, h), (CARD_WIDTH, CARD_HEIGHT));

            // Walk all PNG chunks verifying CRC32 and absence of text metadata chunks.
            let mut pos = 8usize;
            let mut saw_idat = false;
            let mut saw_iend = false;
            while pos + 12 <= png.len() {
                let len = u32::from_be_bytes([png[pos], png[pos + 1], png[pos + 2], png[pos + 3]])
                    as usize;
                let ctype = &png[pos + 4..pos + 8];
                let cdata = &png[pos + 8..pos + 8 + len];
                let expected_crc = u32::from_be_bytes([
                    png[pos + 8 + len],
                    png[pos + 9 + len],
                    png[pos + 10 + len],
                    png[pos + 11 + len],
                ]);
                let mut crc = crc32_update(0xFFFF_FFFF, ctype);
                crc = crc32_update(crc, cdata);
                assert_eq!(!crc, expected_crc, "invalid PNG CRC for chunk {:?}", ctype);
                assert!(
                    ctype != b"tEXt" && ctype != b"iTXt" && ctype != b"zTXt",
                    "PNG must contain zero text metadata chunks"
                );
                if ctype == b"IDAT" {
                    saw_idat = true;
                }
                if ctype == b"IEND" {
                    saw_iend = true;
                }
                pos += 12 + len;
            }
            assert!(saw_idat && saw_iend);
            assert_eq!(pos, png.len());

            let png_lossy = String::from_utf8_lossy(&png);
            assert!(!png_lossy.contains("198.51.100.98"));
            assert!(!png_lossy.contains("203.0.113.45"));
            assert!(!png_lossy.contains("alice_secret"));
        }
    }
}
