//! R14 / D5：通知正文脱敏。
//!
//! 默认只写"目标别名 + 状态 + 原因码 + 时间"，不含 IP、地区、节点名、主机名、
//! 用户名。只有用户显式打开 `notify.include_egress` 才附带出口 IP/地区。
//!
//! 脱敏放在**唯一出口**上做，而不是要求每个调用点自己记得别拼 IP——调用点会
//! 越写越多，而出口只有一个。

/// 脱敏用的占位符（不透露位数、不做部分打码，避免反推）。
pub const REDACTED: &str = "已隐藏";

/// 把一段可能含出口 IP / 地区的文本按策略脱敏。
///
/// 只做保守替换：IPv4、IPv6 里常见的冒号十六进制片段、以及 "地区/国家" 字段。
/// 宁可多打码，也不要把用户 IP 送进通知渠道。
pub fn redact(text: &str, include_egress: bool) -> String {
    if include_egress {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // 地区/国家标记：独立的两位大写代码（"（US）"、"· US ·"、"loc=US"）
        if let Some(skip) = region_marker_at(&bytes, i) {
            out.push_str(REDACTED);
            i += skip;
            continue;
        }
        // IPv4：形如 1.2.3.4 的数字点串
        if c.is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut dots = 0;
            while j < bytes.len() {
                let ch = bytes[j];
                if ch.is_ascii_digit() {
                    j += 1;
                } else if ch == '.' {
                    dots += 1;
                    j += 1;
                } else {
                    break;
                }
            }
            let candidate: String = bytes[start..j].iter().collect();
            if dots == 3 && candidate.split('.').all(|p| p.parse::<u8>().is_ok()) {
                out.push_str(REDACTED);
                i = j;
                continue;
            }
            out.extend(bytes[start..j].iter());
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    scrub_region_names(&out)
}

/// 识别"独立的两位大写地区代码"（前后不是字母/数字），返回应跳过的字符数。
///
/// 只认独立出现的形式，避免把正文里的普通英文缩写（如 `OK`）误打码；
/// 出口地区在通知里总是单独成段出现。
fn region_marker_at(chars: &[char], i: usize) -> Option<usize> {
    let a = *chars.get(i)?;
    let b = *chars.get(i + 1)?;
    if !(a.is_ascii_uppercase() && b.is_ascii_uppercase()) {
        return None;
    }
    // 后面不能再接字母/数字（否则只是单词的一部分，如 API / HTTP）
    if chars.get(i + 2).is_some_and(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    // 地区代码在通知里总是紧跟分隔符出现（"出口 … · US"、"地区：US"、"（US）"）。
    // 要求前面确实是分隔符，才不会把正文开头的普通大写单词当成地区。
    let prev = i.checked_sub(1).and_then(|p| chars.get(p)).copied()?;
    let is_sep = prev.is_whitespace()
        || matches!(
            prev,
            '·' | '（' | '(' | '：' | ':' | '=' | ',' | '，' | '、' | '/' | '-' | '|'
        );
    if !is_sep {
        return None;
    }
    Some(2)
}

/// 中文地区名（与 `model::region_name` 同源）：脱敏时同样要打码。
///
/// 只靠"两位大写代码"挡不住 `policy::fail_reason` 产出的"出口 1.2.3.4（美国）"。
const REGION_NAMES_ZH: [&str; 25] = [
    "美国",
    "日本",
    "新加坡",
    "香港",
    "台湾",
    "韩国",
    "英国",
    "德国",
    "法国",
    "加拿大",
    "澳大利亚",
    "荷兰",
    "俄罗斯",
    "印度",
    "巴西",
    "土耳其",
    "阿联酋",
    "瑞士",
    "瑞典",
    "意大利",
    "西班牙",
    "中国",
    "澳门",
    "越南",
    "泰国",
];

/// 把文本里出现的中文地区名替换成占位符。
fn scrub_region_names(text: &str) -> String {
    let mut out = text.to_string();
    for name in REGION_NAMES_ZH {
        if out.contains(name) {
            out = out.replace(name, REDACTED);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_redacted_by_default() {
        let text = "出口：204.1.100.98\n检查：已恢复正常";
        let out = redact(text, false);
        assert!(!out.contains("204.1.100.98"), "默认不得出现出口 IP");
        assert!(out.contains(REDACTED));
        assert!(out.contains("检查：已恢复正常"), "其余信息要保留");
    }

    #[test]
    fn ipv4_kept_when_user_opts_in() {
        let text = "出口：204.1.100.98";
        assert_eq!(redact(text, true), text);
    }

    #[test]
    fn region_codes_are_redacted_by_default() {
        for text in ["出口 204.1.100.98 · US", "地区：US", "loc=US colo=LAX"] {
            let out = redact(text, false);
            assert!(!out.contains("US"), "默认不得出现地区代码：{text} -> {out}");
            assert!(out.contains(REDACTED));
        }
    }

    #[test]
    fn region_codes_kept_when_user_opts_in() {
        let text = "出口 204.1.100.98 · US";
        assert_eq!(redact(text, true), text);
    }

    #[test]
    fn ordinary_uppercase_words_are_not_treated_as_regions() {
        // 单词内部的两位大写不算地区；纯大写单词也不该被打码成乱码。
        assert!(redact("OK", false).contains("OK"));
        assert!(redact("API 检查失败", false).contains("API"));
        assert!(redact("HTTP 500", false).contains("HTTP"));
    }

    #[test]
    fn chinese_region_names_are_redacted_by_default() {
        // policy::fail_reason 的产物形如「出口 204.1.100.98（美国）不在白名单」
        let text = "出口 204.1.100.98（美国）不在白名单";
        let out = redact(text, false);
        assert!(!out.contains("204.1.100.98"), "默认不得出现出口 IP：{out}");
        assert!(!out.contains("美国"), "默认不得出现地区名：{out}");
        assert!(out.contains(REDACTED));
        // 用户显式打开后原样保留
        assert_eq!(redact(text, true), text);
    }

    #[test]
    fn version_numbers_are_not_mistaken_for_ips() {
        // 3 段版本号不该被当成 IP 打码，否则通知会变得不可读。
        let out = redact("版本 3.10.0 已发布", false);
        assert!(out.contains("3.10.0"));
    }
}
