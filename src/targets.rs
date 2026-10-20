//! 内置监控目标与目标表校验。

use crate::model::{is_known_region, normalize_ip, normalize_region, AnchorKind, Target};

pub const BUILTIN_IDS: [&str; 4] = ["local", "claude", "codex", "antigravity"];

pub fn is_builtin(id: &str) -> bool {
    BUILTIN_IDS.contains(&id)
}

/// 迁移用：旧配置可能混着空白/注释，非法项静默丢弃。
fn clean_ips(raw: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ip in raw.iter().filter_map(|s| normalize_ip(s)) {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// 迁移用：地区宽松归一（认不出的保留大写原文，避免丢用户配置）。
fn clean_regions(raw: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for region in raw
        .iter()
        .filter_map(|s| normalize_region(s).or_else(|| Some(s.trim().to_ascii_uppercase())))
        .filter(|s| !s.is_empty())
    {
        if !out.contains(&region) {
            out.push(region);
        }
    }
    out
}

/// 校验并归一用户提交的白名单 IP；非法项直接拒绝（SPEC §11）。
fn strict_ips(name: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let Some(ip) = normalize_ip(text) else {
            return Err(format!("{name}：白名单 IP 无法识别：{text}"));
        };
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(out)
}

/// 校验并归一用户提交的期望地区；未知代码拒绝，避免“永远命中不了”导致误熔断。
fn strict_regions(name: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
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

/// 用户填写的探测地址：必须 https、有主机名、长度受限。
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

/// 四个内置目标；`local` / `claude` / `codex` 共享迁移来的白名单，
/// `antigravity` 只判 Google 组的可达性（无出口 IP 回显端点）。
///
/// `local` 默认关闭：本机常规流量的出口往往和 AI 应用的代理出口不是同一个 IP
/// （Claude/Codex 走指定节点，浏览器走默认节点），默认开启会在首次启动就熔断。
/// 需要监管本机出口的用户在设置里打开即可。
pub fn default_targets(expect_ips: &[String], expect_regions: &[String]) -> Vec<Target> {
    let ips = clean_ips(expect_ips);
    let regions = clean_regions(expect_regions);
    vec![
        Target {
            id: "local".into(),
            name: "本机出口".into(),
            builtin: true,
            enabled: false,
            anchor_url: "https://cloudflare.com/cdn-cgi/trace".into(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: ips.clone(),
            expect_regions: regions.clone(),
            timeout_secs: 12,
            bind_agent: None,
        },
        Target {
            id: "claude".into(),
            name: "Claude 出口".into(),
            builtin: true,
            enabled: true,
            anchor_url: "https://claude.ai/cdn-cgi/trace".into(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: ips.clone(),
            expect_regions: regions.clone(),
            timeout_secs: 12,
            bind_agent: Some("claude".into()),
        },
        Target {
            id: "codex".into(),
            name: "Codex 出口".into(),
            builtin: true,
            enabled: true,
            anchor_url: "https://chatgpt.com/cdn-cgi/trace".into(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: ips,
            expect_regions: regions,
            timeout_secs: 12,
            bind_agent: Some("chatgpt".into()),
        },
        Target {
            id: "antigravity".into(),
            name: "反重力出口".into(),
            builtin: true,
            enabled: true,
            anchor_url: "https://cloudcode-pa.googleapis.com/".into(),
            anchor_kind: AnchorKind::Reachability,
            expect_ips: Vec::new(),
            expect_regions: Vec::new(),
            timeout_secs: 12,
            bind_agent: Some("antigravity".into()),
        },
    ]
}

/// 补齐被手工删掉的内置目标（保持原有顺序，缺失的追加到末尾）。
///
/// 补出来的目标必须带上白名单，否则会按“未配置白名单”永久 Fail（SPEC §1）；
/// 优先用调用方传入的旧白名单，其次从现有其它目标里复制。
pub fn ensure_builtins(
    mut targets: Vec<Target>,
    fallback_ips: &[String],
    fallback_regions: &[String],
) -> Vec<Target> {
    let mut ips = clean_ips(fallback_ips);
    let mut regions = clean_regions(fallback_regions);
    if ips.is_empty() && regions.is_empty() {
        if let Some(src) = targets
            .iter()
            .find(|t| !(t.expect_ips.is_empty() && t.expect_regions.is_empty()))
        {
            ips = src.expect_ips.clone();
            regions = src.expect_regions.clone();
        }
    }
    let fallback = default_targets(&ips, &regions);
    for builtin in fallback {
        if !targets.iter().any(|t| t.id == builtin.id) {
            targets.push(builtin);
        }
    }
    targets.sort_by_key(|t| {
        BUILTIN_IDS
            .iter()
            .position(|id| *id == t.id)
            .unwrap_or(BUILTIN_IDS.len())
    });
    targets
}

/// 校验并归一用户提交的整张目标表。返回可直接落盘的目标列表。
pub fn validate(targets: Vec<Target>) -> Result<Vec<Target>, String> {
    // 先统一 id 形态，再检查内置目标是否存在（避免 "Claude" 大小写误报）。
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
                "{}：至少要填一个白名单 IP 或出口地区（都不填会一直熔断）",
                target.name
            ));
        }

        target.timeout_secs = target.timeout_secs.clamp(3, 60);

        if is_builtin(&target.id) {
            target.builtin = true;
            let fallback = default_targets(&[], &[]);
            if let Some(base) = fallback.iter().find(|t| t.id == target.id) {
                target.bind_agent = base.bind_agent.clone();
            }
        } else {
            target.builtin = false;
            target.bind_agent = None;
        }
        out.push(target);
    }

    // 内置目标顺序固定，自定义目标排在其后。
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

    fn reachability_target(id: &str, url: &str) -> Target {
        Target {
            id: id.into(),
            name: id.into(),
            builtin: false,
            enabled: true,
            anchor_url: url.into(),
            anchor_kind: AnchorKind::Reachability,
            expect_ips: vec![],
            expect_regions: vec![],
            timeout_secs: 12,
            bind_agent: None,
        }
    }

    #[test]
    fn defaults_have_four_builtins_in_order() {
        let targets = default_targets(&["204.1.100.98".into()], &["US".into()]);
        let ids: Vec<&str> = targets.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["local", "claude", "codex", "antigravity"]);
        assert!(targets.iter().all(|t| t.builtin));
        assert_eq!(targets[1].bind_agent.as_deref(), Some("claude"));
        assert_eq!(targets[3].anchor_kind, AnchorKind::Reachability);
        assert_eq!(targets[1].expect_ips, vec!["204.1.100.98"]);
        assert_eq!(targets[1].expect_regions, vec!["US"]);
    }

    #[test]
    fn ensure_builtins_adds_missing_with_fallback_whitelist() {
        let only_claude = default_targets(&["204.1.100.98".into()], &[])[1].clone();
        let targets = ensure_builtins(vec![only_claude], &[], &[]);
        assert_eq!(targets.len(), 4);
        let local = targets.iter().find(|t| t.id == "local").unwrap();
        assert_eq!(local.expect_ips, vec!["204.1.100.98"]);
    }

    #[test]
    fn validate_accepts_defaults() {
        let targets = default_targets(&["204.1.100.98".into()], &[]);
        assert!(validate(targets).is_ok());
    }

    #[test]
    fn validate_rejects_empty_expectations() {
        let mut targets = default_targets(&[], &[]);
        targets[0].expect_ips.clear();
        let err = validate(targets).unwrap_err();
        assert!(err.contains("白名单"));
    }

    #[test]
    fn validate_rejects_bad_id_and_duplicates() {
        let mut targets = default_targets(&["1.1.1.1".into()], &[]);
        targets[1].id = "Bad Id!".into();
        assert!(validate(targets).is_err());

        let mut targets = default_targets(&["1.1.1.1".into()], &[]);
        targets.push(reachability_target("claude", "https://example.com/"));
        assert!(validate(targets).is_err());
    }

    #[test]
    fn validate_normalizes_ip_and_region() {
        let mut targets = default_targets(&[], &[]);
        for t in targets.iter_mut().take(3) {
            t.expect_ips = vec!["204.1.100.98".into(), " 204.1.100.98 ".into()];
            t.expect_regions = vec!["usa".into()];
            t.timeout_secs = 999;
        }
        let out = validate(targets).unwrap();
        let claude = out.iter().find(|t| t.id == "claude").unwrap();
        assert_eq!(claude.expect_ips, vec!["204.1.100.98"]);
        assert_eq!(claude.expect_regions, vec!["US"]);
        assert_eq!(claude.timeout_secs, 60);
    }

    #[test]
    fn validate_rejects_http_and_hostless_urls() {
        let mut targets = default_targets(&["1.1.1.1".into()], &[]);
        targets[1].anchor_url = "http://claude.ai/cdn-cgi/trace".into();
        assert!(validate(targets).unwrap_err().contains("https://"));

        let mut targets = default_targets(&["1.1.1.1".into()], &[]);
        targets[1].anchor_url = "https://".into();
        assert!(validate(targets).unwrap_err().contains("主机名"));

        let mut targets = default_targets(&["1.1.1.1".into()], &[]);
        targets.push(reachability_target("probe", "abc"));
        assert!(validate(targets).unwrap_err().contains("https://"));
    }

    #[test]
    fn validate_rejects_bad_ip_and_unknown_region() {
        let mut targets = default_targets(&[], &[]);
        for t in targets.iter_mut().take(3) {
            t.expect_ips = vec!["999.1.1.1".into()];
            t.expect_regions = vec![];
        }
        assert!(validate(targets).unwrap_err().contains("白名单 IP"));

        let mut targets = default_targets(&[], &[]);
        for t in targets.iter_mut().take(3) {
            t.expect_ips = vec![];
            t.expect_regions = vec!["ZZ".into()];
        }
        assert!(validate(targets).unwrap_err().contains("国家/地区"));
    }

    #[test]
    fn validate_normalizes_builtin_ids_case_insensitively() {
        let mut targets = default_targets(&["1.1.1.1".into()], &[]);
        targets[1].id = " Claude ".into();
        let out = validate(targets).unwrap();
        assert_eq!(out[1].id, "claude");
        assert!(out[1].builtin);
    }
}
