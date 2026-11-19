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

const PUBLIC_DOH_REMOTES: &str =
    "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,2606:4700:4700::1111,2001:4860:4860::8888";
const GLOBAL_IPV6_RANGE: &str = "2000::/3";

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
    for (idx, exe) in app_paths.iter().enumerate() {
        let stem = exe
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("app");
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
    format!("已拦截 {}（生效 {} 条护盾规则）", parts.join(" + "), active_rules)
}

/// Synchronizes Windows Firewall `ClaudeGuard-Shield-*` rules to match desired vectors.
#[cfg(windows)]
pub fn sync_leak_shield(
    app_paths: &[PathBuf],
    block_quic: bool,
    block_dns_doh: bool,
    block_ipv6: bool,
) -> PlatformResult<LeakShieldStatus> {
    use windows::Win32::Foundation::VARIANT_TRUE;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK,
        NET_FW_RULE_DIR_OUT,
    };
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};
    use windows::core::BSTR;

    use crate::com::ComGuard;
    use crate::traits::{PlatformError, FW_PROFILE_ALL};

    let _com = ComGuard::init_mta()?;
    let policy: INetFwPolicy2 = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL) }
        .map_err(|e| PlatformError::Com {
            code: e.code().0,
            context: format!("创建 INetFwPolicy2 失败：{e}"),
        })?;
    let rules = unsafe { policy.Rules() }.map_err(|e| PlatformError::Com {
        code: e.code().0,
        context: format!("获取防火墙规则集合失败：{e}"),
    })?;

    // Clear previous shield rules first so toggled-off vectors leave zero residue.
    let _ = remove_shield_rules_with_collection(&rules);

    let specs = build_shield_specs(app_paths, block_quic, block_dns_doh, block_ipv6);
    if specs.is_empty() {
        return Ok(LeakShieldStatus {
            enabled: false,
            quic_blocked: false,
            dns_doh_blocked: false,
            ipv6_blocked: false,
            active_rules: 0,
            summary: summarize_shield(false, false, false, 0),
        });
    }

    let mut added = 0usize;
    for spec in &specs {
        let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_ALL) }
            .map_err(|e| PlatformError::Com {
                code: e.code().0,
                context: format!("创建护盾规则对象失败：{e}"),
            })?;
        unsafe {
            let _ = rule.SetName(&BSTR::from(spec.name.as_str()));
            let _ = rule.SetDescription(&BSTR::from(
                "ClaudeGuard v4 4-Vector Leak Shield (auto-managed)",
            ));
            let _ = rule.SetGrouping(&BSTR::from("ClaudeGuard Shield"));
            let _ = rule.SetApplicationName(&BSTR::from(spec.program.to_string_lossy().as_ref()));
            let _ = rule.SetProtocol(spec.protocol);
            if let Some(ports) = spec.remote_ports {
                let _ = rule.SetRemotePorts(&BSTR::from(ports));
            }
            if let Some(addrs) = spec.remote_addresses {
                let _ = rule.SetRemoteAddresses(&BSTR::from(addrs));
            }
            let _ = rule.SetDirection(NET_FW_RULE_DIR_OUT);
            let _ = rule.SetAction(NET_FW_ACTION_BLOCK);
            let _ = rule.SetProfiles(FW_PROFILE_ALL);
            let _ = rule.SetEnabled(VARIANT_TRUE);
            rules
                .Add(&rule)
                .map_err(|e| PlatformError::AccessDenied(format!("写入护盾规则失败：{e}")))?;
        }
        added += 1;
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

    use crate::com::ComGuard;
    use crate::traits::PlatformError;

    let _com = ComGuard::init_mta()?;
    let policy: INetFwPolicy2 = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL) }
        .map_err(|e| PlatformError::Com {
            code: e.code().0,
            context: format!("创建 INetFwPolicy2 失败：{e}"),
        })?;
    let rules = unsafe { policy.Rules() }.map_err(|e| PlatformError::Com {
        code: e.code().0,
        context: format!("获取防火墙规则集合失败：{e}"),
    })?;
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
    let quic_blocked = rules
        .iter()
        .any(|r| r.enabled && r.name.contains("QUIC-"));
    let dns_doh_blocked = rules
        .iter()
        .any(|r| r.enabled && (r.name.contains("DNS-") || r.name.contains("DoH-")));
    let ipv6_blocked = rules
        .iter()
        .any(|r| r.enabled && r.name.contains("IPv6-"));
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
    fn builds_expected_rules_per_enabled_vector() {
        let exes = vec![PathBuf::from(r"C:\Apps\Claude.exe")];
        let specs = build_shield_specs(&exes, true, true, true);
        assert_eq!(specs.len(), 5);
        assert!(specs.iter().any(|s| s.name.contains("QUIC-") && s.protocol == PROTO_UDP));
        assert!(specs.iter().any(|s| s.name.contains("DoH-") && s.remote_addresses.is_some()));
        assert!(specs.iter().any(|s| s.name.contains("IPv6-") && s.remote_addresses == Some("2000::/3")));

        let quic_only = build_shield_specs(&exes, true, false, false);
        assert_eq!(quic_only.len(), 1);
    }
}
