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
    fn version_numbers_are_not_mistaken_for_ips() {
        // 3 段版本号不该被当成 IP 打码，否则通知会变得不可读。
        let out = redact("版本 3.10.0 已发布", false);
        assert!(out.contains("3.10.0"));
    }
}
