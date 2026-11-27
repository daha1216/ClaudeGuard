//! Mode-aware Chromium / Electron anti-leak launch argument planner (`M3`).
//!
//! Critical invariant (TUN vs `--host-resolver-rules` mutual exclusion):
//! `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1 , EXCLUDE ::1"`
//! MUST ONLY be injected alongside an explicit `--proxy-server=...` under `AccessLevel::SystemProxy`
//! (and NEVER under `AccessLevel::Tun`, `Uncovered`, `Unknown`, or `antigravity` with active
//! `version.dll` Winsock hook injection), otherwise Chromium returns `ERR_NAME_NOT_RESOLVED` or
//! double-proxies traffic.

use cg_protocol::AccessLevel;

pub const FLAG_DISABLE_QUIC: &str = "--disable-quic";
pub const FLAG_WEBRTC_DISABLE_NON_PROXIED_UDP: &str =
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp";
pub const FLAG_WEBRTC_ENFORCE_PERMISSION: &str = "--enforce-webrtc-ip-permission-check";
pub const HOST_RESOLVER_RULES_VALUE: &str =
    "MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1 , EXCLUDE ::1";

/// Electron / Chromium-based GUI agents that accept Chromium networking flags.
pub const ELECTRON_AGENT_IDS: &[&str] = &[
    "claude",
    "chatgpt",
    "antigravity",
    "cursor",
    "windsurf",
    "trae",
];

/// Returns `true` when `agent_id` is an Electron / Chromium-based desktop client.
///
/// Native Rust apps such as `zed` and CLI tools return `false`.
pub fn is_electron_agent(agent_id: &str) -> bool {
    let norm = agent_id.trim();
    ELECTRON_AGENT_IDS
        .iter()
        .any(|id| norm.eq_ignore_ascii_case(id))
}

/// Input parameters for computing Electron anti-leak launch flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HygienePlanInput {
    pub agent_id: String,
    pub access_level: AccessLevel,
    /// Proxy endpoint (`"127.0.0.1:7890"` or `"http://127.0.0.1:7890"`).
    pub proxy_addr: Option<String>,
    /// True when launching `antigravity` with an active `version.dll` Winsock hook.
    pub antigravity_version_dll_active: bool,
    /// Master config toggle (`Config::enforce_electron_hygiene_flags`).
    pub enabled: bool,
}

/// Planned Chromium/Electron launch arguments and explanatory metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HygienePlan {
    pub args: Vec<String>,
    pub quic_disabled: bool,
    pub webrtc_locked: bool,
    pub proxy_and_resolver_locked: bool,
    pub note: String,
}

/// Result of auditing a live process command line for anti-leak hygiene flags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandLineHygieneAudit {
    pub quic_disabled: bool,
    pub webrtc_locked: bool,
    pub host_resolver_enforced: bool,
    pub proxy_server_enforced: bool,
    pub fully_guarded: bool,
}

fn normalize_proxy_server_arg(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | ';'))
    {
        return None;
    }
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let scheme_l = scheme.to_ascii_lowercase();
        if !matches!(scheme_l.as_str(), "http" | "https" | "socks5" | "socks5h")
            || rest.trim().is_empty()
        {
            return None;
        }
        return Some(format!("{scheme_l}://{rest}"));
    }
    // Must at least look like host:port
    if !trimmed.contains(':') {
        return None;
    }
    Some(format!("http://{trimmed}"))
}

/// Plans mode-aware anti-leak Chromium/Electron launch flags with full audit metadata.
pub fn plan_electron_hygiene(input: &HygienePlanInput) -> HygienePlan {
    if !input.enabled {
        return HygienePlan {
            note: "已关闭 Electron 防漏参数注入".to_string(),
            ..HygienePlan::default()
        };
    }

    if !is_electron_agent(&input.agent_id) {
        return HygienePlan {
            note: format!(
                "客户端 {} 非 Chromium/Electron 架构，跳过防漏参数注入",
                input.agent_id
            ),
            ..HygienePlan::default()
        };
    }

    let mut args = vec![
        FLAG_DISABLE_QUIC.to_string(),
        FLAG_WEBRTC_DISABLE_NON_PROXIED_UDP.to_string(),
        FLAG_WEBRTC_ENFORCE_PERMISSION.to_string(),
    ];

    let is_antigravity = input.agent_id.trim().eq_ignore_ascii_case("antigravity");
    let mut proxy_and_resolver_locked = false;

    let note = match input.access_level {
        AccessLevel::SystemProxy if is_antigravity && input.antigravity_version_dll_active => {
            "Antigravity 已挂载 version.dll 透明注入：仅启用 QUIC/WebRTC 锁，跳过 --proxy-server 与 --host-resolver-rules 防双重代理冲突".to_string()
        }
        AccessLevel::SystemProxy => {
            if let Some(proxy_url) = normalize_proxy_server_arg(input.proxy_addr.as_deref()) {
                args.push(format!("--proxy-server={proxy_url}"));
                args.push(format!("--host-resolver-rules={HOST_RESOLVER_RULES_VALUE}"));
                proxy_and_resolver_locked = true;
                "SystemProxy 模式：已启用 QUIC/WebRTC 锁 + 强制远端代理 DNS 解析（零 Dnscache 泄露）"
                    .to_string()
            } else {
                "SystemProxy 模式缺少有效代理地址：仅启用 QUIC/WebRTC 锁（不单独注入 --host-resolver-rules）"
                    .to_string()
            }
        }
        AccessLevel::Tun => {
            "TUN 透明网卡模式：已启用 QUIC/WebRTC 锁，跳过 --host-resolver-rules 以保留 Fake-IP 正常解析"
                .to_string()
        }
        AccessLevel::Uncovered | AccessLevel::Unknown => {
            "当前接入路径非 SystemProxy：仅启用 QUIC/WebRTC 锁（避免无代理时断网）".to_string()
        }
    };

    HygienePlan {
        args,
        quic_disabled: true,
        webrtc_locked: true,
        proxy_and_resolver_locked,
        note,
    }
}

/// Convenience helper returning the planned anti-leak CLI argument list for an Electron client.
pub fn plan_electron_hygiene_args(
    agent_id: &str,
    access_level: AccessLevel,
    proxy_addr: Option<&str>,
    antigravity_version_dll_active: bool,
) -> Vec<String> {
    plan_electron_hygiene(&HygienePlanInput {
        agent_id: agent_id.to_string(),
        access_level,
        proxy_addr: proxy_addr.map(ToString::to_string),
        antigravity_version_dll_active,
        enabled: true,
    })
    .args
}

/// Alias matching the master spec naming (`plan_chromium_hygiene_args`).
pub fn plan_chromium_hygiene_args(
    agent_id: &str,
    access_level: AccessLevel,
    proxy_addr: Option<&str>,
    antigravity_version_dll_active: bool,
) -> Vec<String> {
    plan_electron_hygiene_args(
        agent_id,
        access_level,
        proxy_addr,
        antigravity_version_dll_active,
    )
}

/// Formats planned arguments into a Windows command-line / `.lnk` `SetArguments` string,
/// quoting `--flag="value with spaces"` cleanly for Chromium's Windows parser.
pub fn format_args_for_windows_cmdline(args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        if !arg.contains(char::is_whitespace) {
            parts.push(arg.clone());
        } else if let Some((flag, val)) = arg.split_once('=') {
            let escaped = val.replace('"', r#"\""#);
            parts.push(format!(r#"{flag}="{escaped}""#));
        } else {
            let escaped = arg.replace('"', r#"\""#);
            parts.push(format!(r#""{escaped}""#));
        }
    }
    parts.join(" ")
}

/// Pure command-line auditor evaluating whether a live Chromium/Electron process carries
/// the required anti-leak flags for the active `access_level`.
pub fn audit_cmdline_hygiene(
    cmdline: &str,
    access_level: AccessLevel,
    antigravity_version_dll_active: bool,
) -> CommandLineHygieneAudit {
    let lower = cmdline.to_ascii_lowercase();
    let quic_disabled = lower.contains("--disable-quic");
    let webrtc_locked = lower.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        && lower.contains("--enforce-webrtc-ip-permission-check");
    let host_resolver_enforced =
        lower.contains("--host-resolver-rules=") && lower.contains("map * ~notfound");
    let proxy_server_enforced = lower.contains("--proxy-server=");

    let need_resolver_lock =
        access_level == AccessLevel::SystemProxy && !antigravity_version_dll_active;
    let fully_guarded = quic_disabled
        && webrtc_locked
        && (!need_resolver_lock || (host_resolver_enforced && proxy_server_enforced));

    CommandLineHygieneAudit {
        quic_disabled,
        webrtc_locked,
        host_resolver_enforced,
        proxy_server_enforced,
        fully_guarded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_proxy_injects_full_hygiene_including_proxy_and_host_resolver_rules() {
        for agent in ["claude", "chatgpt", "cursor", "windsurf", "trae"] {
            let args = plan_electron_hygiene_args(
                agent,
                AccessLevel::SystemProxy,
                Some("127.0.0.1:7890"),
                false,
            );
            assert!(args.iter().any(|a| a == FLAG_DISABLE_QUIC));
            assert!(
                args.iter()
                    .any(|a| a == FLAG_WEBRTC_DISABLE_NON_PROXIED_UDP)
            );
            assert!(args.iter().any(|a| a == FLAG_WEBRTC_ENFORCE_PERMISSION));
            assert!(
                args.iter()
                    .any(|a| a == "--proxy-server=http://127.0.0.1:7890")
            );
            assert!(args.iter().any(|a| a.starts_with(
                "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1"
            )));
        }
    }

    #[test]
    fn tun_mode_never_injects_proxy_server_or_host_resolver_rules() {
        let plan = plan_electron_hygiene(&HygienePlanInput {
            agent_id: "claude".into(),
            access_level: AccessLevel::Tun,
            proxy_addr: Some("127.0.0.1:7890".into()),
            antigravity_version_dll_active: false,
            enabled: true,
        });
        assert!(plan.quic_disabled);
        assert!(plan.webrtc_locked);
        assert!(!plan.proxy_and_resolver_locked);
        assert_eq!(plan.args.len(), 3);
        assert!(!plan.args.iter().any(|a| a.starts_with("--proxy-server")));
        assert!(
            !plan
                .args
                .iter()
                .any(|a| a.starts_with("--host-resolver-rules"))
        );
    }

    #[test]
    fn antigravity_with_active_version_dll_skips_proxy_and_resolver_rules() {
        let with_dll = plan_electron_hygiene(&HygienePlanInput {
            agent_id: "antigravity".into(),
            access_level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            antigravity_version_dll_active: true,
            enabled: true,
        });
        assert!(with_dll.quic_disabled);
        assert!(with_dll.webrtc_locked);
        assert!(!with_dll.proxy_and_resolver_locked);
        assert!(
            !with_dll
                .args
                .iter()
                .any(|a| a.starts_with("--proxy-server"))
        );
        assert!(
            !with_dll
                .args
                .iter()
                .any(|a| a.starts_with("--host-resolver-rules"))
        );

        // Without version.dll under SystemProxy, Antigravity gets full proxy + host-resolver locks.
        let without_dll = plan_electron_hygiene(&HygienePlanInput {
            agent_id: "antigravity".into(),
            access_level: AccessLevel::SystemProxy,
            proxy_addr: Some("http://127.0.0.1:7897".into()),
            antigravity_version_dll_active: false,
            enabled: true,
        });
        assert!(without_dll.proxy_and_resolver_locked);
        assert!(
            without_dll
                .args
                .iter()
                .any(|a| a == "--proxy-server=http://127.0.0.1:7897")
        );
        assert!(
            without_dll
                .args
                .iter()
                .any(|a| a.starts_with("--host-resolver-rules="))
        );
    }

    #[test]
    fn non_electron_disabled_and_missing_proxy_behave_safely() {
        assert!(!is_electron_agent("zed"));
        assert!(
            plan_electron_hygiene_args(
                "zed",
                AccessLevel::SystemProxy,
                Some("127.0.0.1:7890"),
                false
            )
            .is_empty()
        );

        let disabled = plan_electron_hygiene(&HygienePlanInput {
            agent_id: "claude".into(),
            access_level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            antigravity_version_dll_active: false,
            enabled: false,
        });
        assert!(disabled.args.is_empty());

        // Missing proxy_addr under SystemProxy must NEVER emit --host-resolver-rules alone.
        let no_proxy = plan_electron_hygiene_args("claude", AccessLevel::SystemProxy, None, false);
        assert_eq!(no_proxy.len(), 3);
        assert!(
            !no_proxy
                .iter()
                .any(|a| a.starts_with("--host-resolver-rules"))
        );
    }

    #[test]
    fn formats_windows_cmdline_and_audits_live_command_line() {
        let args = plan_chromium_hygiene_args(
            "claude",
            AccessLevel::SystemProxy,
            Some("127.0.0.1:7890"),
            false,
        );
        let cmdline = format!(
            r#""C:\Apps\Claude.exe" {}"#,
            format_args_for_windows_cmdline(&args)
        );
        assert!(cmdline.contains(
            r#"--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1 , EXCLUDE ::1""#
        ));

        let audit_ok = audit_cmdline_hygiene(&cmdline, AccessLevel::SystemProxy, false);
        assert!(audit_ok.fully_guarded);
        assert!(audit_ok.quic_disabled);
        assert!(audit_ok.webrtc_locked);
        assert!(audit_ok.host_resolver_enforced);
        assert!(audit_ok.proxy_server_enforced);

        let audit_bare = audit_cmdline_hygiene(r#""C:\Apps\Claude.exe""#, AccessLevel::Tun, false);
        assert!(!audit_bare.fully_guarded);
    }
}
