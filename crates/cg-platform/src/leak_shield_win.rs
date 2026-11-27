//! Native Windows OS-level 4-Vector Leak Shield (`INetFwPolicy2` / `INetFwRule`).
//!
//! Blocks non-proxied side-channel leaks for guarded AI executables using dedicated
//! `ClaudeGuard-Shield-*` outbound firewall rules (cleanly separated from Quarantine/Lockdown
//! rules and removed automatically on Flow B disarm / uninstall):
//! 1. **QUIC / HTTP3 (`UDP:443`)**: Prevents Electron/Chromium AI clients from bypassing HTTP
//!    proxies via UDP QUIC connections.
//! 2. **Cleartext Direct DNS (`UDP/TCP:53`) & Public DoH (`1.1.1.1`, `8.8.8.8`, `9.9.9.9` on 443/853)**:
//!    Prevents local ISP DNS / direct DoH resolution leaks outside the proxy tunnel.
//! 3. **Direct Global IPv6 (`2000::/3`)**: Prevents dual-stack home networks from leaking real
//!    IPv6 addresses when the local proxy handles IPv4 only.
//!
//! Vector 4 is Safe Launch `--disable-quic` applied in `cg-gui`.

use std::path::PathBuf;

use cg_protocol::LeakShieldStatus;

use crate::traits::PlatformResult;

/// Distinct rule name prefix managed exclusively by the Leak Shield.
pub const SHIELD_RULE_PREFIX: &str = "ClaudeGuard-Shield-";

const PUBLIC_DOH_REMOTES: &str = concat!(
    "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,",
    "223.5.5.5,223.6.6.6,119.29.29.29,94.140.14.14,",
    "2606:4700:4700::1111,2606:4700:4700::1001,",
    "2001:4860:4860::8888,2001:4860:4860::8844,2620:fe::fe"
);
const GLOBAL_IPV6_RANGE: &str = "2000::/3,64:ff9b::/96";

#[derive(Clone, Debug)]
struct ShieldRuleSpec {
    name: String,
    program: PathBuf,
    protocol: i32,
    remote_ports: Option<&'static str>,
    remote_addresses: Option<&'static str>,
}

const PROTO_TCP: i32 = 6;
const PROTO_UDP: i32 = 17;
const PROTO_ANY: i32 = 256;

fn build_shield_specs(
    app_paths: &[PathBuf],
    block_quic: bool,
    block_dns_doh: bool,
    block_ipv6: bool,
) -> Vec<ShieldRuleSpec> {
    let mut specs = Vec::new();
    for (idx, raw_exe) in app_paths.iter().enumerate() {
        if crate::wfp_win::is_non_pe_script_shim(raw_exe) {
            continue;
        }
        let exe = crate::firewall_com::resolve_program_path_for_firewall(raw_exe);
        if crate::wfp_win::is_non_pe_script_shim(&exe) {
            continue;
        }
        let stem = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("app");
        let tag = format!("{stem}-{idx}");
        if block_quic {
            specs.push(ShieldRuleSpec {
                name: format!("{SHIELD_RULE_PREFIX}QUIC-{tag}"),
                program: exe.clone(),
                protocol: PROTO_UDP,
                remote_ports: Some("443"),
                remote_addresses: None,
            });
        }
        if block_dns_doh {
            specs.push(ShieldRuleSpec {
                name: format!("{SHIELD_RULE_PREFIX}DNS-UDP-{tag}"),
                program: exe.clone(),
                protocol: PROTO_UDP,
                remote_ports: Some("53"),
                remote_addresses: None,
            });
            specs.push(ShieldRuleSpec {
                name: format!("{SHIELD_RULE_PREFIX}DNS-TCP-{tag}"),
                program: exe.clone(),
                protocol: PROTO_TCP,
                remote_ports: Some("53"),
                remote_addresses: None,
            });
            specs.push(ShieldRuleSpec {
                name: format!("{SHIELD_RULE_PREFIX}DoH-{tag}"),
                program: exe.clone(),
                protocol: PROTO_TCP,
                remote_ports: Some("443,853"),
                remote_addresses: Some(PUBLIC_DOH_REMOTES),
            });
            specs.push(ShieldRuleSpec {
                name: format!("{SHIELD_RULE_PREFIX}DoH-UDP-{tag}"),
                program: exe.clone(),
                protocol: PROTO_UDP,
                remote_ports: Some("443,853"),
                remote_addresses: Some(PUBLIC_DOH_REMOTES),
            });
        }
        if block_ipv6 {
            specs.push(ShieldRuleSpec {
                name: format!("{SHIELD_RULE_PREFIX}IPv6-{tag}"),
                program: exe.clone(),
                protocol: PROTO_ANY,
                remote_ports: None,
                remote_addresses: Some(GLOBAL_IPV6_RANGE),
            });
        }
    }
    specs
}

fn summarize_shield(
    quic_blocked: bool,
    dns_doh_blocked: bool,
    ipv6_blocked: bool,
    active_rules: usize,
) -> String {
    if !quic_blocked && !dns_doh_blocked && !ipv6_blocked {
        return "防泄露护盾未开启（仅被动观测）".into();
    }
    let mut parts = Vec::new();
    if quic_blocked {
        parts.push("QUIC UDP:443");
    }
    if dns_doh_blocked {
        parts.push("直连 DNS/DoH");
    }
    if ipv6_blocked {
        parts.push("公网 IPv6");
    }
    format!(
        "已拦截 {}（生效 {} 条护盾规则）",
        parts.join(" + "),
        active_rules
    )
}

/// Synchronizes Windows Firewall `ClaudeGuard-Shield-*` rules to match desired vectors.
///
/// Fail-closed invariant:
/// - Propagates `?` (`map_win_err`) on EVERY `rule.Set*` COM call BEFORE `rules.Add(&rule)` so an
///   invalid `ApplicationName` can NEVER create a wildcard OS-wide block rule.
/// - Adds all desired shield rules BEFORE removing pre-existing `ClaudeGuard-Shield-*` COM instances
///   so mid-sync errors never fail open.
#[cfg(windows)]
pub fn sync_leak_shield(
    app_paths: &[PathBuf],
    block_quic: bool,
    block_dns_doh: bool,
    block_ipv6: bool,
) -> PlatformResult<LeakShieldStatus> {
    use windows::core::BSTR;
    use windows::Win32::Foundation::VARIANT_TRUE;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK,
        NET_FW_RULE_DIR_OUT,
    };
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};

    use crate::com::{map_win_err, ComGuard};
    use crate::firewall_com::ComFirewallEngine;
    use crate::traits::{PlatformError, FW_PROFILE_ALL};

    let _com = ComGuard::init_mta()?;
    let policy: INetFwPolicy2 = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL) }
        .map_err(|e| map_win_err(e, "CoCreateInstance(NetFwPolicy2)"))?;
    let rules = unsafe { policy.Rules() }.map_err(|e| map_win_err(e, "INetFwPolicy2::Rules"))?;

    let specs = build_shield_specs(app_paths, block_quic, block_dns_doh, block_ipv6);
    if specs.is_empty() {
        let _ = remove_shield_rules_with_collection(&rules);
        return Ok(LeakShieldStatus {
            enabled: false,
            quic_blocked: false,
            dns_doh_blocked: false,
            ipv6_blocked: false,
            active_rules: 0,
            summary: summarize_shield(false, false, false, 0),
        });
    }

    // Snapshot pre-existing COM rule pointers BEFORE adding replacements so we can delete ONLY
    // stale instances after new rules are safely active.
    let old_pairs = ComFirewallEngine::enumerate_com_rules_with_prefix(&rules, SHIELD_RULE_PREFIX)?;

    let mut added = 0usize;
    for spec in &specs {
        let prog_str = spec.program.to_string_lossy();
        if prog_str.trim().is_empty() {
            return Err(PlatformError::InvalidInput(
                "护盾规则可执行文件路径为空，已拒绝创建全局规则".to_string(),
            ));
        }
        let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_ALL) }
            .map_err(|e| map_win_err(e, "CoCreateInstance(NetFwRule)"))?;
        unsafe {
            rule.SetName(&BSTR::from(spec.name.as_str()))
                .map_err(|e| map_win_err(e, "INetFwRule::SetName"))?;
            rule.SetDescription(&BSTR::from(
                "ClaudeGuard v4 4-Vector Leak Shield (auto-managed)",
            ))
            .map_err(|e| map_win_err(e, "INetFwRule::SetDescription"))?;
            rule.SetGrouping(&BSTR::from("ClaudeGuard Shield"))
                .map_err(|e| map_win_err(e, "INetFwRule::SetGrouping"))?;
            rule.SetApplicationName(&BSTR::from(prog_str.as_ref()))
                .map_err(|e| map_win_err(e, "INetFwRule::SetApplicationName"))?;
            rule.SetProtocol(spec.protocol)
                .map_err(|e| map_win_err(e, "INetFwRule::SetProtocol"))?;
            if let Some(ports) = spec.remote_ports {
                rule.SetRemotePorts(&BSTR::from(ports))
                    .map_err(|e| map_win_err(e, "INetFwRule::SetRemotePorts"))?;
            }
            if let Some(addrs) = spec.remote_addresses {
                rule.SetRemoteAddresses(&BSTR::from(addrs))
                    .map_err(|e| map_win_err(e, "INetFwRule::SetRemoteAddresses"))?;
            }
            rule.SetDirection(NET_FW_RULE_DIR_OUT)
                .map_err(|e| map_win_err(e, "INetFwRule::SetDirection"))?;
            rule.SetAction(NET_FW_ACTION_BLOCK)
                .map_err(|e| map_win_err(e, "INetFwRule::SetAction"))?;
            rule.SetProfiles(FW_PROFILE_ALL)
                .map_err(|e| map_win_err(e, "INetFwRule::SetProfiles"))?;
            rule.SetEnabled(VARIANT_TRUE)
                .map_err(|e| map_win_err(e, "INetFwRule::SetEnabled"))?;
            rules
                .Add(&rule)
                .map_err(|e| map_win_err(e, "INetFwRules::Add"))?;
        }
        added += 1;
    }

    // Now that all new rules are committed, remove pre-existing shield instances via sentinel rename.
    let pid = std::process::id();
    for (seq, (old_rule, old_rec)) in old_pairs.iter().enumerate() {
        let sentinel = format!("__CG_SHIELD_OLD_{pid}_{seq}");
        if unsafe { old_rule.SetName(&BSTR::from(&sentinel)) }.is_ok() {
            let _ = unsafe { rules.Remove(&BSTR::from(&sentinel)) };
        } else {
            let _ = unsafe { rules.Remove(&BSTR::from(old_rec.name.as_str())) };
        }
    }

    Ok(LeakShieldStatus {
        enabled: added > 0,
        quic_blocked: block_quic && added > 0,
        dns_doh_blocked: block_dns_doh && added > 0,
        ipv6_blocked: block_ipv6 && added > 0,
        active_rules: added,
        summary: summarize_shield(block_quic, block_dns_doh, block_ipv6, added),
    })
}

/// Removes every `ClaudeGuard-Shield-*` rule from Windows Firewall.
#[cfg(windows)]
pub fn clear_leak_shield() -> PlatformResult<usize> {
    use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, NetFwPolicy2};
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};

    use crate::com::{map_win_err, ComGuard};

    let _com = ComGuard::init_mta()?;
    let policy: INetFwPolicy2 = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL) }
        .map_err(|e| map_win_err(e, "CoCreateInstance(NetFwPolicy2)"))?;
    let rules = unsafe { policy.Rules() }.map_err(|e| map_win_err(e, "INetFwPolicy2::Rules"))?;
    Ok(remove_shield_rules_with_collection(&rules))
}

/// Read-only inspection of currently active `ClaudeGuard-Shield-*` firewall rules.
#[cfg(windows)]
pub fn inspect_leak_shield() -> LeakShieldStatus {
    let eng = crate::firewall_com::ComFirewallEngine::new();
    let Ok(rules) = crate::traits::FirewallEngine::enumerate_rules(&eng, SHIELD_RULE_PREFIX) else {
        return LeakShieldStatus {
            summary: "无法查询防火墙护盾状态".into(),
            ..LeakShieldStatus::default()
        };
    };
    let active_rules = rules.iter().filter(|r| r.enabled).count();
    let quic_blocked = rules.iter().any(|r| r.enabled && r.name.contains("QUIC-"));
    let dns_doh_blocked = rules
        .iter()
        .any(|r| r.enabled && (r.name.contains("DNS-") || r.name.contains("DoH-")));
    let ipv6_blocked = rules.iter().any(|r| r.enabled && r.name.contains("IPv6-"));
    LeakShieldStatus {
        enabled: active_rules > 0,
        quic_blocked,
        dns_doh_blocked,
        ipv6_blocked,
        active_rules,
        summary: summarize_shield(quic_blocked, dns_doh_blocked, ipv6_blocked, active_rules),
    }
}

#[cfg(windows)]
fn remove_shield_rules_with_collection(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
) -> usize {
    use windows::core::BSTR;
    let eng = crate::firewall_com::ComFirewallEngine::new();
    let existing = crate::traits::FirewallEngine::enumerate_rules(&eng, SHIELD_RULE_PREFIX)
        .unwrap_or_default();
    let mut removed = 0usize;
    for r in existing {
        if unsafe { rules.Remove(&BSTR::from(r.name.as_str())) }.is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(not(windows))]
pub fn sync_leak_shield(
    _app_paths: &[PathBuf],
    _block_quic: bool,
    _block_dns_doh: bool,
    _block_ipv6: bool,
) -> PlatformResult<LeakShieldStatus> {
    Ok(LeakShieldStatus::default())
}

#[cfg(not(windows))]
pub fn clear_leak_shield() -> PlatformResult<usize> {
    Ok(0)
}

#[cfg(not(windows))]
pub fn inspect_leak_shield() -> LeakShieldStatus {
    LeakShieldStatus::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_expected_rules_per_enabled_vector_and_strips_verbatim_prefix() {
        let exes = vec![PathBuf::from(r"\\?\C:\Apps\Claude.exe")];
        let specs = build_shield_specs(&exes, true, true, true);
        assert_eq!(specs.len(), 6);
        assert!(specs
            .iter()
            .all(|s| s.program == std::path::Path::new(r"C:\Apps\Claude.exe")));
        assert!(specs
            .iter()
            .any(|s| s.name.contains("QUIC-") && s.protocol == PROTO_UDP));
        assert!(specs.iter().any(|s| {
            s.name.contains("DoH-")
                && s.protocol == PROTO_TCP
                && s.remote_ports == Some("443,853")
                && s.remote_addresses
                    .is_some_and(|a| a.contains("223.5.5.5") && a.contains("2620:fe::fe"))
        }));
        assert!(specs.iter().any(|s| {
            s.name.contains("DoH-UDP-")
                && s.protocol == PROTO_UDP
                && s.remote_ports == Some("443,853")
        }));
        assert!(specs.iter().any(|s| {
            s.name.contains("IPv6-") && s.remote_addresses == Some("2000::/3,64:ff9b::/96")
        }));

        let quic_only = build_shield_specs(&exes, true, false, false);
        assert_eq!(quic_only.len(), 1);
    }
}
