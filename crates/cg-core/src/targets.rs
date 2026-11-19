//! Built-in targets and strict target table validation (including IPv4 CIDR rules).

use cg_protocol::{
    AnchorKind, BUILTIN_TARGET_IDS, Target, default_builtin_targets, ensure_builtin_targets,
    is_builtin_target, is_known_region, normalize_ip_or_cidr, normalize_region,
};

pub const BUILTIN_IDS: [&str; 4] = BUILTIN_TARGET_IDS;

pub fn is_builtin(id: &str) -> bool {
    is_builtin_target(id)
}

pub fn default_targets(expect_ips: &[String], expect_regions: &[String]) -> Vec<Target> {
    default_builtin_targets(expect_ips, expect_regions)
}

pub fn ensure_builtins(
    targets: Vec<Target>,
    fallback_ips: &[String],
    fallback_regions: &[String],
) -> Vec<Target> {
    ensure_builtin_targets(targets, fallback_ips, fallback_regions)
}

fn strict_ips(name: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in raw {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let Some(norm) = normalize_ip_or_cidr(text) else {
            return Err(format!("{name}：白名单 IP/CIDR 无法识别：{text}"));
        };
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
    Ok(out)
}

fn strict_regions(name: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in raw {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let Some(code) = normalize_region(text) else {
            return Err(format!(
                "{name}：出口地区无法识别：{text}（填两字母代码，如 US、JP）"
            ));
        };
        if !is_known_region(&code) {
            return Err(format!("{name}：没有这个国家/地区代码：{text}"));
        }
        if !out.contains(&code) {
            out.push(code);
        }
    }
    Ok(out)
}

fn check_url(target: &Target) -> Result<(), String> {
    let url = target.anchor_url.trim();
    if url.is_empty() {
        return Err(format!("{}：请填写探测地址", target.name));
    }
    if url.len() > 300 {
        return Err(format!("{}：探测地址太长（上限 300 字符）", target.name));
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(format!("{}：探测地址必须以 https:// 开头", target.name));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.starts_with(':') || host.contains(' ') {
        return Err(format!("{}：探测地址缺少主机名", target.name));
    }
    Ok(())
}

/// Validates and normalizes a complete target list before configuration persistence.
pub fn validate(targets: Vec<Target>) -> Result<Vec<Target>, String> {
    let mut pending = targets;
    for target in pending.iter_mut() {
        target.id = target.id.trim().to_ascii_lowercase();
    }
    for id in BUILTIN_IDS {
        if !pending.iter().any(|t| t.id == id) {
            return Err(format!("缺少内置目标 {id}，请点“恢复默认”"));
        }
    }

    let mut out: Vec<Target> = Vec::new();
    let defaults = default_targets(&[], &[]);
    for mut target in pending {
        if target.id.is_empty() || target.id.len() > 24 {
            return Err("目标 id 不能为空且不超过 24 个字符".into());
        }
        if !target
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("目标 id 只能包含小写字母、数字、下划线和连字符".into());
        }
        if out.iter().any(|t| t.id == target.id) {
            return Err(format!("目标 id 重复：{}", target.id));
        }

        target.name = target.name.trim().to_string();
        if target.name.is_empty() || target.name.chars().count() > 16 {
            return Err("目标名称不能为空且不超过 16 个字".into());
        }

        target.anchor_url = target.anchor_url.trim().to_string();
        check_url(&target)?;

        target.expect_ips = strict_ips(&target.name, &target.expect_ips)?;
        target.expect_regions = strict_regions(&target.name, &target.expect_regions)?;
        if target.anchor_kind != AnchorKind::Reachability
            && target.expect_ips.is_empty()
            && target.expect_regions.is_empty()
        {
            return Err(format!(
                "{}：至少要填一个白名单 IP/CIDR 或出口地区（都不填会一直熔断）",
                target.name
            ));
        }

        target.timeout_secs = target.timeout_secs.clamp(3, 60);

        if is_builtin(&target.id) {
            target.builtin = true;
            if let Some(base) = defaults.iter().find(|t| t.id == target.id) {
                target.bind_agent = base.bind_agent.clone();
            }
        } else {
            target.builtin = false;
            target.bind_agent = None;
        }
        out.push(target);
    }

    out.sort_by_key(|t| {
        BUILTIN_IDS
            .iter()
            .position(|id| *id == t.id)
            .unwrap_or(BUILTIN_IDS.len())
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_cidr_and_normalizes_host_bits() {
        let mut targets = default_targets(&["198.51.100.98/24".into()], &["usa".into()]);
        let validated = validate(targets.clone()).expect("valid cidr and region");
        assert_eq!(validated[1].expect_ips, vec!["198.51.100.0/24"]);
        assert_eq!(validated[1].expect_regions, vec!["US"]);

        targets[1].expect_ips = vec!["198.51.100.0/33".into()];
        assert!(validate(targets).is_err());
    }

    #[test]
    fn validate_rejects_bad_urls_missing_builtins_empty_lists_and_unknown_regions() {
        let mut targets = default_targets(&["198.51.100.98".into()], &[]);
        targets[1].anchor_url = "http://claude.ai/cdn-cgi/trace".into();
        assert!(validate(targets).is_err());

        let mut targets = default_targets(&["198.51.100.98".into()], &[]);
        targets[1].expect_ips.clear();
        assert!(validate(targets).is_err());

        let mut targets = default_targets(&[], &["ZZ".into()]);
        assert!(validate(targets.clone()).is_err());

        targets.remove(0);
        assert!(validate(targets).is_err());
    }

    #[test]
    fn ensure_builtins_restores_deleted_target_with_fallback_allowlist() {
        let claude = default_targets(&["198.51.100.98".into()], &["US".into()])[1].clone();
        let restored = ensure_builtins(vec![claude], &[], &[]);
        assert_eq!(restored.len(), 4);
        assert_eq!(restored[0].id, "local");
        assert_eq!(restored[0].expect_ips, vec!["198.51.100.98"]);
        assert_eq!(restored[2].id, "codex");
        assert_eq!(restored[2].expect_regions, vec!["US"]);
    }
}
