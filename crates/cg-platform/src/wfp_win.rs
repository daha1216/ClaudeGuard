//! M1: Dual-Session Windows Filtering Platform (WFP) dynamic & boot-time sublayer engine.
//!
//! Architecture highlights:
//! - **Dual-Session Lifecycle**:
//!   - **Dynamic Session (`FWPM_SESSION_FLAG_DYNAMIC`)**: Hosts runtime Per-App split-permit
//!     sandwiches, 4-Vector Leak Shield, and dynamic quarantine/lockdown/cut filters under
//!     `CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID` (`Weight = 0xFF00`). When the process exits or
//!     crashes, Windows BFE kernel atomically purges all dynamic filters in 0ms—never leaving
//!     the host network locked out.
//!   - **Persistent / Boot-Time Opt-In Session**: Only activated when the user explicitly opts in
//!     (`wfp_boot_guard = true`, default `false`), placing `FWPM_FILTER_FLAG_BOOTTIME` filters in
//!     `CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID` (`Weight = 0xFF10`) with idempotent
//!     `clear_persistent_filters()` readback verification.
//! - **Per-App Split-Permit Sandwich (`ALE_AUTH_CONNECT_V4/V6`)**:
//!   - `15` GlobalCut (`!IS_LOOPBACK`, excluding daemon self if configured)
//!   - `14` Per-App Quarantine / Lockdown (`ALE_AUTH_CONNECT` + `ALE_AUTH_RECV_ACCEPT`, `!IS_LOOPBACK`)
//!   - `13` 4-Vector Leak Shield (QUIC `UDP:443`, direct DNS/DoT `53`/`853`, public DoH `:443`, public IPv6)
//!   - `11` Loopback Permit (`FWP_CONDITION_FLAG_IS_LOOPBACK`)
//!   - `10` Active Verified TUN `NET_LUID` Permit (`FWPM_CONDITION_IP_LOCAL_INTERFACE`)
//!   - `9`  Optional RFC1918 LAN Dev Exemption (`REMOTE_PORT != 53`)
//!   - `2`  Physical NIC Hard-Block (catch-all per-app direct egress block when `strict_tunnel_only`)
//! - **Real-Time Kernel Attribution (`FwpmNetEventSubscribe4`)**:
//!   - O(1) `filter_id -> WfpFilterAttribution` lookup discarding unrelated OS drops immediately,
//!     recording ClaudeGuard drops into a bounded 256-entry ring buffer without blocking RPC threads.
//! - **`HybridFirewallEngine`**:
//!   - Smoothly routes between `WfpFirewallEngine` and `ComFirewallEngine` per `FirewallBackendPref`
//!     (`AutoWfpFirst`, `WfpOnly`, `ComLegacy`), degrading gracefully when non-elevated or if BFE
//!     is unavailable.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use cg_protocol::{FirewallBackendPref, LeakShieldStatus, WfpBlockedEvent, WfpStatus};

use crate::firewall_com::{
    duplicate_rule_indices, normalize_program_path, resolve_program_path_for_firewall,
    ComFirewallEngine,
};
use crate::traits::{
    Coverage, FirewallEngine, FirewallProfileStatus, FirewallRuleRecord, FirewallRuleSpec,
    PlatformError, PlatformResult, RemoveReport, RuleAction, RuleDirection, FW_PROFILE_ALL,
};

// ==================== Stable GUIDs, Weights & Constants ====================

/// Raw 128-bit value for [`CLAUDEGUARD_WFP_PROVIDER_GUID`] (dynamic session provider).
pub const CLAUDEGUARD_WFP_PROVIDER_GUID_U128: u128 = 0x9c4e_7a21_5b38_4f19_a8d2_61e0_c3f9_4b01;
/// Raw 128-bit value for [`CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID`].
pub const CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID_U128: u128 =
    0x9c4e_7a22_5b38_4f19_a8d2_61e0_c3f9_4b02;
/// Raw 128-bit value for [`CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID`].
pub const CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID_U128: u128 =
    0x9c4e_7a23_5b38_4f19_a8d2_61e0_c3f9_4b03;
/// Raw 128-bit value for [`CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID`] (persistent/boot-time provider,
/// kept separate from the dynamic provider to avoid BFE `FWP_E_LIFETIME_MISMATCH`).
pub const CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID_U128: u128 =
    0x9c4e_7a24_5b38_4f19_a8d2_61e0_c3f9_4b04;

/// Stable ClaudeGuard WFP Dynamic Provider GUID.
#[cfg(windows)]
pub const CLAUDEGUARD_WFP_PROVIDER_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(CLAUDEGUARD_WFP_PROVIDER_GUID_U128);

/// Stable ClaudeGuard WFP Persistent / Boot-Time Provider GUID.
#[cfg(windows)]
pub const CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID_U128);

/// Stable Dynamic Sublayer GUID (`Weight = 0xFF00`).
#[cfg(windows)]
pub const CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID_U128);

/// Stable Persistent / Boot-Time Sublayer GUID (`Weight = 0xFF10`).
#[cfg(windows)]
pub const CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID_U128);

/// Dynamic sublayer priority weight (`0xFF00` = 65280).
pub const WFP_SUBLAYER_WEIGHT_DYNAMIC: u16 = 0xFF00;
/// Persistent / Boot-Time sublayer priority weight (`0xFF10` = 65296, outranks dynamic sublayer).
pub const WFP_SUBLAYER_WEIGHT_PERSISTENT: u16 = 0xFF10;

/// Intra-sublayer explicit `FWP_UINT8` filter weight: Global Emergency Cut.
pub const WFP_WEIGHT_GLOBAL_CUT: u8 = 15;
/// Intra-sublayer explicit `FWP_UINT8` filter weight: Per-App Quarantine / Lockdown / Boot Guard.
pub const WFP_WEIGHT_QUARANTINE_OR_LOCKDOWN: u8 = 14;
/// Intra-sublayer explicit `FWP_UINT8` filter weight: 4-Vector Leak Shield (QUIC / DNS / DoH / IPv6).
pub const WFP_WEIGHT_LEAK_SHIELD: u8 = 13;
/// Intra-sublayer explicit `FWP_UINT8` filter weight: Loopback Permit (`IS_LOOPBACK`).
pub const WFP_WEIGHT_LOOPBACK_PERMIT: u8 = 11;
/// Intra-sublayer explicit `FWP_UINT8` filter weight: Verified Active TUN `NET_LUID` Permit.
pub const WFP_WEIGHT_ACTIVE_TUN_PERMIT: u8 = 10;
/// Intra-sublayer explicit `FWP_UINT8` filter weight: Optional RFC1918 LAN Dev Exemption (`!= 53`).
pub const WFP_WEIGHT_LAN_EXEMPT_PERMIT: u8 = 9;
/// Intra-sublayer explicit `FWP_UINT8` filter weight: Catch-All Physical NIC Hard-Block.
pub const WFP_WEIGHT_DIRECT_NIC_BLOCK: u8 = 2;

/// Bounded capacity of the real-time WFP blocked-packet event ring buffer.
pub const WFP_EVENT_RING_CAPACITY: usize = 256;

/// Canonical backend identifier when the Dynamic WFP kernel sublayer is active.
pub const BACKEND_WFP_DYNAMIC: &str = "windows-wfp-v5-dynamic";
/// Canonical backend identifier when Windows Firewall COM (`INetFwPolicy2`) is active.
pub const BACKEND_COM_LEGACY: &str = "windows-com-netfwpolicy2";
/// Canonical backend identifier when `WfpOnly` was requested but WFP could not open.
pub const BACKEND_WFP_UNAVAILABLE: &str = "wfp-unavailable";
/// Canonical backend identifier on non-Windows platforms.
pub const BACKEND_UNSUPPORTED: &str = "unsupported";

/// Public IPv4 DoH resolver endpoints blocked by the 4-Vector Leak Shield on port 443.
pub const PUBLIC_DOH_IPV4: &[Ipv4Addr] = &[
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(1, 0, 0, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(8, 8, 4, 4),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(149, 112, 112, 112),
    Ipv4Addr::new(223, 5, 5, 5),
    Ipv4Addr::new(223, 6, 6, 6),
    Ipv4Addr::new(119, 29, 29, 29),
    Ipv4Addr::new(114, 114, 114, 114),
    Ipv4Addr::new(94, 140, 14, 14),
];

/// Public IPv6 DoH resolver endpoints blocked by the 4-Vector Leak Shield on port 443.
pub const PUBLIC_DOH_IPV6: &[Ipv6Addr] = &[
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
    Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe),
    Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009),
    Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x0001),
    Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x0001),
];

/// Global / non-loopback IPv6 leak CIDRs blocked when `block_global_ipv6` is enabled.
pub const GLOBAL_IPV6_CIDRS: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3),
    (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
];

/// RFC1918 private LAN CIDRs optionally exempted (with `REMOTE_PORT != 53`) when `allow_lan_dev_servers` is enabled.
pub const RFC1918_LAN_CIDRS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
];

// ==================== Pure Host-Byte-Order Conversion Helpers ====================

/// Convert an [`Ipv4Addr`] to WFP **host byte order** (`u32::from_be_bytes(ip.octets())`).
///
/// Unlike WinSock `SOCKADDR_IN`, WFP `FWP_V4_ADDR_AND_MASK` and `FWPM_NET_EVENT_HEADER3` store
/// IPv4 addresses in host byte order (`127.0.0.1` -> `0x7F00_0001`).
#[inline]
pub fn ipv4_to_wfp_host_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

/// Build a WFP host-byte-order IPv4 subnet mask for `prefix_len` (`0..=32`).
#[inline]
pub fn ipv4_prefix_mask_host_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_len.min(32))
    }
}

/// Build a masked `(addr, mask)` pair in WFP host byte order for `FWP_V4_ADDR_AND_MASK`.
#[inline]
pub fn ipv4_and_mask_host_u32(ip: Ipv4Addr, prefix_len: u8) -> (u32, u32) {
    let mask = ipv4_prefix_mask_host_u32(prefix_len);
    let addr = ipv4_to_wfp_host_u32(ip) & mask;
    (addr, mask)
}

/// Restore a standard [`Ipv4Addr`] from a WFP host-byte-order `u32`.
#[inline]
pub fn ipv4_from_wfp_host_u32(host_u32: u32) -> Ipv4Addr {
    Ipv4Addr::from(host_u32.to_be_bytes())
}

/// Build a masked `(octets, prefix_len)` pair for `FWP_V6_ADDR_AND_MASK`.
#[inline]
pub fn ipv6_and_prefix(ip: Ipv6Addr, prefix_len: u8) -> ([u8; 16], u8) {
    let plen = prefix_len.min(128);
    let mut octets = ip.octets();
    let full_bytes = (plen / 8) as usize;
    let rem_bits = plen % 8;
    if full_bytes < 16 {
        if rem_bits != 0 {
            let mask = !((1u8 << (8 - rem_bits)) - 1);
            octets[full_bytes] &= mask;
            for b in &mut octets[(full_bytes + 1)..] {
                *b = 0;
            }
        } else {
            for b in &mut octets[full_bytes..] {
                *b = 0;
            }
        }
    }
    (octets, plen)
}

// ==================== Runtime Posture & Attribution Models ====================

/// Complete desired runtime posture for the WFP Dynamic Sublayer (`Weight = 0xFF00`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WfpRuntimePostureSpec {
    /// `(agent_id, covered_exe_paths)` pairs guarded by Leak Shield and optional Tunnel-Only wall.
    pub guarded_apps: Vec<(String, Vec<PathBuf>)>,
    /// When `true`, inserts the Per-App Split-Permit Sandwich (Loopback 11 -> Active TUN 10 ->
    /// optional LAN 9 -> Physical NIC Hard-Block 2).
    pub strict_tunnel_only: bool,
    /// Verified 64-bit `NET_LUID.Value` of the active default-routed TUN adapter, if any.
    pub active_tun_luid: Option<u64>,
    /// Friendly name of the active TUN adapter for diagnostics.
    pub active_tun_name: Option<String>,
    /// Vector 1: block QUIC (`UDP:443`) on V4 & V6.
    pub block_quic_udp443: bool,
    /// Vector 2: block direct non-loopback DNS (`53`), DoT (`853`), and public DoH (`443`).
    pub block_direct_dns_doh: bool,
    /// Vector 3: block direct non-loopback global IPv6 (`2000::/3`, `64:ff9b::/96`, `fc00::/7`).
    pub block_global_ipv6: bool,
    /// Opt-in RFC1918 LAN development exemption (`REMOTE_PORT != 53`, default `false`).
    pub allow_lan_dev_servers: bool,
    /// `(agent_id, exe_paths)` currently quarantined or locked down (Weight 14).
    pub locked_or_quarantined_apps: Vec<(String, Vec<PathBuf>)>,
    /// When `true`, installs Weight 15 GlobalCut blocking all non-loopback outbound connections.
    pub global_cut_active: bool,
    /// Optional daemon executable excluded from Weight 15 GlobalCut so local IPC/health stays alive.
    pub daemon_self_exe: Option<PathBuf>,
    /// Optional non-loopback configured proxy endpoint `(ip, port)` permitted at Weight 11 (TCP)
    /// when `strict_tunnel_only` is active (e.g. LAN gateway / Surge Mac `192.168.1.2:7890`).
    pub active_proxy_endpoint: Option<(std::net::IpAddr, u16)>,
}

/// O(1) metadata stored per active WFP `filter_id` for zero-noise kernel event attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WfpFilterAttribution {
    pub agent_id: String,
    pub filter_reason: String,
    pub layer: String,
}

/// Thread-safe, bounded 256-entry ring buffer and O(1) `filter_id` attribution table shared
/// with the `FwpmNetEventSubscribe4` system RPC callback.
pub struct WfpEventStore {
    filter_meta: RwLock<HashMap<u64, WfpFilterAttribution>>,
    total_blocked_packets: AtomicU64,
    seq_gen: AtomicU64,
    ring: Mutex<VecDeque<WfpBlockedEvent>>,
}

impl Default for WfpEventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for WfpEventStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WfpEventStore")
            .field(
                "total_blocked_packets",
                &self.total_blocked_packets.load(Ordering::Relaxed),
            )
            .field("seq_gen", &self.seq_gen.load(Ordering::Relaxed))
            .finish()
    }
}

impl WfpEventStore {
    pub fn new() -> Self {
        Self {
            filter_meta: RwLock::new(HashMap::new()),
            total_blocked_packets: AtomicU64::new(0),
            seq_gen: AtomicU64::new(0),
            ring: Mutex::new(VecDeque::with_capacity(WFP_EVENT_RING_CAPACITY)),
        }
    }

    /// Replace the active `filter_id -> attribution` lookup map atomically.
    pub fn replace_filter_map(&self, next: HashMap<u64, WfpFilterAttribution>) {
        if let Ok(mut guard) = self.filter_meta.write() {
            *guard = next;
        }
    }

    /// Insert or update a single filter attribution entry.
    pub fn insert_filter_meta(&self, filter_id: u64, meta: WfpFilterAttribution) {
        if let Ok(mut guard) = self.filter_meta.write() {
            guard.insert(filter_id, meta);
        }
    }

    /// Remove multiple `filter_id` entries from the attribution table.
    pub fn remove_filter_ids(&self, ids: &[u64]) {
        if ids.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.filter_meta.write() {
            for id in ids {
                guard.remove(id);
            }
        }
    }

    /// Non-blocking O(1) attribution lookup intended for the BFE RPC callback thread.
    pub fn lookup_try(&self, filter_id: u64) -> Option<WfpFilterAttribution> {
        self.filter_meta
            .try_read()
            .ok()
            .and_then(|map| map.get(&filter_id).cloned())
    }

    /// Record a kernel-blocked drop event if and only if `filter_id` belongs to ClaudeGuard.
    ///
    /// Returns `true` when the drop matched an owned filter and was recorded; `false` when
    /// discarded as unrelated background OS traffic.
    #[allow(clippy::too_many_arguments)]
    pub fn record_blocked_drop(
        &self,
        filter_id: u64,
        timestamp_ms: u64,
        pid: Option<u32>,
        app_path: String,
        remote_ip: String,
        remote_port: u16,
        protocol: &str,
        fallback_layer: &str,
    ) -> bool {
        let Some(meta) = self.lookup_try(filter_id) else {
            return false;
        };

        self.total_blocked_packets.fetch_add(1, Ordering::Relaxed);
        let seq = self.seq_gen.fetch_add(1, Ordering::Relaxed) + 1;
        let layer = if meta.layer.is_empty() {
            fallback_layer.to_string()
        } else {
            meta.layer
        };

        let event = WfpBlockedEvent {
            seq,
            timestamp_ms,
            pid,
            agent_id: meta.agent_id,
            app_path,
            remote_ip,
            remote_port,
            protocol: protocol.to_string(),
            layer,
            filter_reason: meta.filter_reason,
        };

        if let Ok(mut ring) = self.ring.try_lock() {
            while ring.len() >= WFP_EVENT_RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(event);
        }
        true
    }

    /// Clear all buffered blocked-packet events and reset the displayed total counter.
    pub fn clear_events(&self) {
        if let Ok(mut ring) = self.ring.lock() {
            ring.clear();
        }
        self.total_blocked_packets.store(0, Ordering::Relaxed);
    }

    /// Snapshot `(total_blocked_packets, recent_blocked_events)` cleanly for `WfpStatus`.
    pub fn snapshot_events(&self) -> (u64, Vec<WfpBlockedEvent>) {
        let total = self.total_blocked_packets.load(Ordering::Relaxed);
        let events = self
            .ring
            .lock()
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default();
        (total, events)
    }
}

fn summarize_wfp_shield(
    quic_blocked: bool,
    dns_doh_blocked: bool,
    ipv6_blocked: bool,
    active_rules: usize,
) -> String {
    if !quic_blocked && !dns_doh_blocked && !ipv6_blocked {
        return "WFP 防泄露护盾未开启（仅被动观测）".into();
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
        "WFP 内核护盾已拦截 {}（生效 {} 条内核过滤器）",
        parts.join(" + "),
        active_rules
    )
}

fn infer_reason_from_rule_name(name: &str, program: &Option<PathBuf>) -> &'static str {
    let lower = name.trim().to_ascii_lowercase();
    if program.is_none() || lower.contains("cut all") || lower.contains("lockdown") {
        "panic_lockdown"
    } else if lower.contains("quic") {
        "quic_shield"
    } else if lower.contains("dns") || lower.contains("doh") {
        "doh_shield"
    } else if lower.contains("ipv6") {
        "ipv6_shield"
    } else if lower.contains("boot") {
        "boot_time_guard"
    } else {
        "app_quarantine"
    }
}

fn infer_agent_id_from_rule_name(name: &str) -> String {
    if let Some(start) = name.rfind('(') {
        if let Some(end) = name[start + 1..].find(')') {
            let inner = name[start + 1..start + 1 + end].trim();
            if !inner.is_empty() {
                return inner.to_ascii_lowercase();
            }
        }
    }
    String::new()
}

fn protocol_label(ip_proto: u8) -> &'static str {
    match ip_proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        _ => "other",
    }
}

/// Returns `true` when `path` is a text/batch script shim (`.cmd`, `.bat`, `.ps1`, `.vbs`, `.sh`)
/// rather than a native PE image, so WFP/COM firewall engines skip script wrappers cleanly.
pub fn is_non_pe_script_shim(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "cmd" | "bat" | "ps1" | "vbs" | "sh"
            )
        })
}

fn infer_agent_id_from_exe_path(path: &std::path::Path) -> String {
    let low = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if low.contains("antigravity") || name.starts_with("language_server") || name == "agy.exe" {
        "antigravity".into()
    } else if low.contains("claude-code")
        || low.contains(r"\.local\share\claude\")
        || low.contains(r"\.local\bin\claude")
        || low.contains(r"\.claude\")
    {
        "claude-code".into()
    } else if low.contains("claude") {
        "claude".into()
    } else if low.contains(r"@openai\codex")
        || (!low.contains(r"\windowsapps\")
            && !low.contains(r"\programs\codex\")
            && name.starts_with("codex"))
    {
        "codex".into()
    } else if low.contains("chatgpt") || low.contains("openai") || low.contains("codex") {
        "chatgpt".into()
    } else {
        path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
    }
}

/// Pure classifier identifying Hyper-V / WSL2 virtual adapters (`vEthernet (WSL)`, etc.)
/// so WFP `strict_tunnel_only` permits localhost-equivalent IDE/LSP/MCP traffic into WSL2.
pub fn is_wsl_virtual_adapter_name(desc: &str, friendly: &str) -> bool {
    let dl = desc.trim().to_ascii_lowercase();
    let fl = friendly.trim().to_ascii_lowercase();
    fl.contains("vethernet (wsl")
        || dl.contains("vethernet (wsl")
        || fl == "wsl"
        || fl.starts_with("wsl ")
        || fl.ends_with(" (wsl)")
        || (dl.contains("hyper-v virtual ethernet") && fl.contains("wsl"))
}

// ==================== Windows Native WFP Implementation ====================

#[cfg(windows)]
pub mod win_impl {
    use super::*;
    use std::ffi::c_void;
    use std::net::IpAddr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_SUCCESS, E_ACCESSDENIED, FWP_E_ALREADY_EXISTS,
        FWP_E_FILTER_NOT_FOUND, FWP_E_IN_USE, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND,
        HANDLE,
    };
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    const RPC_C_AUTHN_WINNT: u32 = 10;
    const FWP_E_ALREADY_EXISTS_U32: u32 = FWP_E_ALREADY_EXISTS.0 as u32;
    const FWP_E_SUBLAYER_NOT_FOUND_U32: u32 = FWP_E_SUBLAYER_NOT_FOUND.0 as u32;
    const FWP_E_FILTER_NOT_FOUND_U32: u32 = FWP_E_FILTER_NOT_FOUND.0 as u32;
    const FWP_E_PROVIDER_NOT_FOUND_U32: u32 = FWP_E_PROVIDER_NOT_FOUND.0 as u32;
    const FWP_E_IN_USE_U32: u32 = FWP_E_IN_USE.0 as u32;
    const E_ACCESSDENIED_U32: u32 = E_ACCESSDENIED.0 as u32;

    const ALE_CONNECT_LAYERS: [(GUID, &str); 2] = [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ale_auth_connect_v4"),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ale_auth_connect_v6"),
    ];

    const ALE_RECV_LAYERS: [(GUID, &str); 2] = [
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            "ale_auth_recv_accept_v4",
        ),
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "ale_auth_recv_accept_v6",
        ),
    ];

    const ALL_MANAGED_LAYERS: [GUID; 4] = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ];

    /// Map a Win32 / WFP status code to a structured [`PlatformError`].
    pub fn wfp_err(code: u32, ctx: &str) -> PlatformError {
        if code == ERROR_ACCESS_DENIED.0 || code == E_ACCESSDENIED_U32 {
            PlatformError::AccessDenied(format!("{ctx} failed with WFP code 0x{code:08X}"))
        } else {
            PlatformError::Com {
                code: code as i32,
                context: format!("WFP {ctx} (0x{code:08X})"),
            }
        }
    }

    /// Construct a WFP host-byte-order `FWP_V4_ADDR_AND_MASK`.
    #[inline]
    pub fn v4_addr_mask(ip: Ipv4Addr, prefix_len: u8) -> FWP_V4_ADDR_AND_MASK {
        let (addr, mask) = ipv4_and_mask_host_u32(ip, prefix_len);
        FWP_V4_ADDR_AND_MASK { addr, mask }
    }

    /// Construct a WFP `FWP_V6_ADDR_AND_MASK`.
    #[inline]
    pub fn v6_addr_mask(ip: Ipv6Addr, prefix_len: u8) -> FWP_V6_ADDR_AND_MASK {
        let (addr, prefix_length) = ipv6_and_prefix(ip, prefix_len);
        FWP_V6_ADDR_AND_MASK {
            addr,
            prefixLength: prefix_length,
        }
    }

    /// Construct an explicit `FWP_UINT8` filter weight (`1..=15`).
    #[inline]
    pub fn explicit_u8_weight(weight: u8) -> FWP_VALUE0 {
        let mut val = FWP_VALUE0 {
            r#type: FWP_UINT8,
            ..Default::default()
        };
        val.Anonymous.uint8 = weight;
        val
    }

    /// RAII wrapper for a BFE session `HANDLE` returned by `FwpmEngineOpen0`.
    ///
    /// For `FWPM_SESSION_FLAG_DYNAMIC` sessions, closing the handle causes Windows BFE to
    /// atomically purge all dynamic filters owned by the session in 0ms.
    pub struct WfpSessionHandle(HANDLE);

    // SAFETY: BFE RPC engine handles are safe to share across threads when serialized by a mutex.
    unsafe impl Send for WfpSessionHandle {}
    unsafe impl Sync for WfpSessionHandle {}

    impl WfpSessionHandle {
        pub fn open(dynamic: bool, name: &str) -> PlatformResult<Self> {
            let mut name_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let mut desc_w: Vec<u16> = "ClaudeGuard v5 WFP Kernel Guard"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let session = FWPM_SESSION0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name_w.as_mut_ptr()),
                    description: PWSTR(desc_w.as_mut_ptr()),
                },
                flags: if dynamic {
                    FWPM_SESSION_FLAG_DYNAMIC
                } else {
                    0
                },
                txnWaitTimeoutInMSec: 15_000,
                ..Default::default()
            };
            let mut handle = HANDLE::default();
            let rc = unsafe {
                FwpmEngineOpen0(
                    PCWSTR::null(),
                    RPC_C_AUTHN_WINNT,
                    None,
                    Some(&session),
                    &mut handle,
                )
            };
            if rc != ERROR_SUCCESS.0 {
                return Err(wfp_err(rc, "FwpmEngineOpen0"));
            }
            if handle.is_invalid() || handle.0.is_null() {
                return Err(PlatformError::Io(
                    "FwpmEngineOpen0 returned an invalid handle".into(),
                ));
            }
            Ok(Self(handle))
        }

        pub fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for WfpSessionHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() && !self.0 .0.is_null() {
                unsafe {
                    let _ = FwpmEngineClose0(self.0);
                }
            }
        }
    }

    /// RAII atomic WFP transaction guard.
    ///
    /// Automatically calls `FwpmTransactionAbort0` on `Drop` unless [`commit`](Self::commit)
    /// succeeded, preventing half-written rules from ever reaching kernel BFE on errors or panics.
    pub struct WfpTransactionGuard {
        engine: HANDLE,
        committed: bool,
    }

    impl WfpTransactionGuard {
        pub fn begin(engine: HANDLE) -> PlatformResult<Self> {
            let rc = unsafe { FwpmTransactionBegin0(engine, 0) };
            if rc != ERROR_SUCCESS.0 {
                return Err(wfp_err(rc, "FwpmTransactionBegin0"));
            }
            Ok(Self {
                engine,
                committed: false,
            })
        }

        pub fn commit(mut self) -> PlatformResult<()> {
            let rc = unsafe { FwpmTransactionCommit0(self.engine) };
            if rc != ERROR_SUCCESS.0 {
                return Err(wfp_err(rc, "FwpmTransactionCommit0"));
            }
            self.committed = true;
            Ok(())
        }
    }

    impl Drop for WfpTransactionGuard {
        fn drop(&mut self) {
            if !self.committed {
                unsafe {
                    let _ = FwpmTransactionAbort0(self.engine);
                }
            }
        }
    }

    enum WfpAppIdStorage {
        BfeAllocated(*mut FWP_BYTE_BLOB),
        Synthesized {
            blob: Box<FWP_BYTE_BLOB>,
            _bytes: Box<[u8]>,
        },
    }

    /// Synthesizes a BFE-compatible lowercase UTF-16LE NUL-terminated NT device path byte buffer
    /// (`\device\harddiskvolumeN\...\0`) via `QueryDosDeviceW` when `FwpmGetAppIdFromFileName0`
    /// fails with `ERROR_ACCESS_DENIED` / `ERROR_CANT_ACCESS_FILE` on MSIX `WindowsApps` packages.
    pub fn synthesize_nt_device_app_id_bytes(dos_path: &Path) -> PlatformResult<Vec<u8>> {
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

        let cleaned = crate::process_win::strip_verbatim_win32_str(&dos_path.to_string_lossy())
            .replace('/', "\\");
        let trimmed = cleaned.trim();
        let bytes = trimmed.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return Err(PlatformError::InvalidInput(format!(
                "WFP AppId fallback requires an absolute DOS drive path: {trimmed}"
            )));
        }
        let drive_w: [u16; 3] = [(bytes[0].to_ascii_uppercase()) as u16, b':' as u16, 0];
        let mut dev_buf = vec![0u16; 1024];
        let chars =
            unsafe { QueryDosDeviceW(PCWSTR(drive_w.as_ptr()), Some(&mut dev_buf)) } as usize;
        if chars == 0 || chars >= dev_buf.len() {
            return Err(PlatformError::Io(format!(
                "QueryDosDeviceW failed for drive {}:",
                bytes[0] as char
            )));
        }
        let end = dev_buf[..chars]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(chars);
        let nt_prefix = String::from_utf16_lossy(&dev_buf[..end]);
        if nt_prefix.trim().is_empty() {
            return Err(PlatformError::Io(
                "QueryDosDeviceW returned empty NT device prefix".into(),
            ));
        }
        let rest = &trimmed[3..];
        let full_nt = format!(
            "{}\\{}",
            nt_prefix.trim_end_matches('\\'),
            rest.trim_start_matches('\\')
        )
        .to_lowercase();

        let utf16_le: Vec<u8> = full_nt
            .encode_utf16()
            .chain(Some(0u16))
            .flat_map(u16::to_le_bytes)
            .collect();
        Ok(utf16_le)
    }

    /// RAII wrapper for `FWP_BYTE_BLOB` allocated by `FwpmGetAppIdFromFileName0` (freed via
    /// `FwpmFreeMemory0` on drop) or synthesized via `QueryDosDeviceW` for restricted MSIX paths.
    pub struct WfpAppIdBlob(WfpAppIdStorage);

    impl WfpAppIdBlob {
        pub fn from_path(path: &Path) -> PlatformResult<Self> {
            let resolved = resolve_program_path_for_firewall(path);
            let display = resolved.to_string_lossy();
            if display.trim().is_empty() {
                return Err(PlatformError::InvalidInput(
                    "WFP AppId path cannot be empty".into(),
                ));
            }
            if is_non_pe_script_shim(&resolved) {
                return Err(PlatformError::InvalidInput(format!(
                    "WFP AppId skips non-PE script shim: {}",
                    resolved.display()
                )));
            }
            let wide: Vec<u16> = resolved.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut blob_ptr: *mut FWP_BYTE_BLOB = core::ptr::null_mut();
            let rc = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob_ptr) };
            if rc == ERROR_SUCCESS.0 && !blob_ptr.is_null() {
                return Ok(Self(WfpAppIdStorage::BfeAllocated(blob_ptr)));
            }

            // Fallback for MSIX `C:\Program Files\WindowsApps\...` conditional ACEs or AppExecLinks
            // where non-SYSTEM Admin receives ERROR_ACCESS_DENIED (5) or ERROR_CANT_ACCESS_FILE (1920).
            if let Ok(nt_bytes) = synthesize_nt_device_app_id_bytes(&resolved) {
                let mut boxed_bytes = nt_bytes.into_boxed_slice();
                let blob = Box::new(FWP_BYTE_BLOB {
                    size: boxed_bytes.len() as u32,
                    data: boxed_bytes.as_mut_ptr(),
                });
                return Ok(Self(WfpAppIdStorage::Synthesized {
                    blob,
                    _bytes: boxed_bytes,
                }));
            }

            Err(wfp_err(
                rc,
                &format!("FwpmGetAppIdFromFileName0({})", resolved.display()),
            ))
        }

        pub fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
            match &self.0 {
                WfpAppIdStorage::BfeAllocated(ptr) => *ptr,
                WfpAppIdStorage::Synthesized { blob, .. } => {
                    (&**blob as *const FWP_BYTE_BLOB).cast_mut()
                }
            }
        }
    }

    impl Drop for WfpAppIdBlob {
        fn drop(&mut self) {
            if let WfpAppIdStorage::BfeAllocated(ptr) = &mut self.0 {
                if !ptr.is_null() {
                    let mut raw: *mut c_void = (*ptr).cast();
                    unsafe {
                        FwpmFreeMemory0(&mut raw);
                    }
                    *ptr = core::ptr::null_mut();
                }
            }
        }
    }

    struct FilterEnumGuard {
        engine: HANDLE,
        enum_handle: HANDLE,
    }

    impl Drop for FilterEnumGuard {
        fn drop(&mut self) {
            if !self.enum_handle.is_invalid() && !self.enum_handle.0.is_null() {
                unsafe {
                    let _ = FwpmFilterDestroyEnumHandle0(self.engine, self.enum_handle);
                }
            }
        }
    }

    type FwpmNetEventSubscribe4Fn = unsafe extern "system" fn(
        engine_handle: HANDLE,
        subscription: *const FWPM_NET_EVENT_SUBSCRIPTION0,
        callback: FWPM_NET_EVENT_CALLBACK4,
        context: *mut c_void,
        events_handle: *mut HANDLE,
    ) -> u32;

    /// Dynamically resolves `FwpmNetEventSubscribe4` from `System32\fwpuclnt.dll` so Windows 10
    /// 1809 LTSC / Server 2019 hosts (which only export `Subscribe0..3`) degrade gracefully
    /// instead of aborting process startup with `STATUS_ENTRYPOINT_NOT_FOUND` (`0xC0000139`).
    fn resolve_fwpm_net_event_subscribe4() -> Option<FwpmNetEventSubscribe4Fn> {
        use std::sync::OnceLock;

        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LoadLibraryExW(
                lp_lib_file_name: *const u16,
                h_file: *mut c_void,
                dw_flags: u32,
            ) -> *mut c_void;
            fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *const c_void;
        }

        static FN_PTR: OnceLock<Option<FwpmNetEventSubscribe4Fn>> = OnceLock::new();
        *FN_PTR.get_or_init(|| unsafe {
            let dll_w: [u16; 13] = [
                b'f' as u16,
                b'w' as u16,
                b'p' as u16,
                b'u' as u16,
                b'c' as u16,
                b'l' as u16,
                b'n' as u16,
                b't' as u16,
                b'.' as u16,
                b'd' as u16,
                b'l' as u16,
                b'l' as u16,
                0,
            ];
            let hmod = LoadLibraryExW(
                dll_w.as_ptr(),
                core::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if hmod.is_null() {
                return None;
            }
            let proc = GetProcAddress(hmod, c"FwpmNetEventSubscribe4".as_ptr().cast::<u8>());
            if proc.is_null() {
                return None;
            }
            Some(core::mem::transmute::<
                *const c_void,
                FwpmNetEventSubscribe4Fn,
            >(proc))
        })
    }

    /// RAII wrapper for `FwpmNetEventSubscribe4` guaranteeing `FwpmNetEventUnsubscribe0`
    /// completes BEFORE the shared `Arc<WfpEventStore>` context pointer is reclaimed.
    pub struct WfpNetEventSubscription {
        engine: HANDLE,
        sub_handle: HANDLE,
        ctx_ptr: *const WfpEventStore,
    }

    // SAFETY: `ctx_ptr` points to a leaked `Arc<WfpEventStore>` (`Send + Sync`) and `sub_handle`
    // is only unsubscribed once on `Drop` while the parent `WfpSessionHandle` is still alive.
    unsafe impl Send for WfpNetEventSubscription {}
    unsafe impl Sync for WfpNetEventSubscription {}

    impl WfpNetEventSubscription {
        pub fn subscribe(engine: HANDLE, store: Arc<WfpEventStore>) -> PlatformResult<Self> {
            let Some(subscribe_fn) = resolve_fwpm_net_event_subscribe4() else {
                return Err(PlatformError::unsupported(
                    "wfp_net_events",
                    "FwpmNetEventSubscribe4 is not exported by fwpuclnt.dll on this Windows version",
                ));
            };
            let mut template = FWPM_NET_EVENT_ENUM_TEMPLATE0::default();
            let subscription = FWPM_NET_EVENT_SUBSCRIPTION0 {
                enumTemplate: &mut template,
                flags: 0,
                sessionKey: GUID::zeroed(),
            };
            let ctx_ptr = Arc::into_raw(store);
            let mut sub_handle = HANDLE::default();
            let rc = unsafe {
                subscribe_fn(
                    engine,
                    &subscription,
                    Some(wfp_net_event_callback_v4),
                    ctx_ptr.cast::<c_void>() as *mut c_void,
                    &mut sub_handle,
                )
            };
            if rc != ERROR_SUCCESS.0 || sub_handle.is_invalid() || sub_handle.0.is_null() {
                // Reclaim the leaked Arc immediately on subscription failure.
                unsafe {
                    drop(Arc::from_raw(ctx_ptr));
                }
                return Err(wfp_err(rc, "FwpmNetEventSubscribe4"));
            }
            Ok(Self {
                engine,
                sub_handle,
                ctx_ptr,
            })
        }
    }

    impl Drop for WfpNetEventSubscription {
        fn drop(&mut self) {
            if !self.sub_handle.is_invalid() && !self.sub_handle.0.is_null() {
                unsafe {
                    let _ = FwpmNetEventUnsubscribe0(self.engine, self.sub_handle);
                }
                self.sub_handle = HANDLE::default();
            }
            if !self.ctx_ptr.is_null() {
                unsafe {
                    drop(Arc::from_raw(self.ctx_ptr));
                }
                self.ctx_ptr = core::ptr::null();
            }
        }
    }

    /// Enable kernel BFE net-event collection (`FWPM_ENGINE_COLLECT_NET_EVENTS = 1`).
    pub fn enable_bfe_net_events(engine: HANDLE) -> PlatformResult<()> {
        let mut val = FWP_VALUE0 {
            r#type: FWP_UINT32,
            ..Default::default()
        };
        val.Anonymous.uint32 = 1;
        let rc = unsafe { FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &val) };
        if rc != ERROR_SUCCESS.0 {
            return Err(wfp_err(rc, "FwpmEngineSetOption0(COLLECT_NET_EVENTS)"));
        }
        Ok(())
    }

    /// Idempotently register the specified ClaudeGuard WFP Provider and Sublayer.
    ///
    /// Dynamic sessions MUST pass [`CLAUDEGUARD_WFP_PROVIDER_GUID`] with `persistent = false`,
    /// while persistent / boot-time sessions MUST pass [`CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID`]
    /// with `persistent = true` to avoid BFE `FWP_E_LIFETIME_MISMATCH` (`0x80320016`).
    pub fn ensure_provider_and_sublayer(
        engine: HANDLE,
        provider_guid: GUID,
        sublayer_guid: GUID,
        weight: u16,
        persistent: bool,
    ) -> PlatformResult<()> {
        let prov_label = if persistent {
            "ClaudeGuard Persistent Security Provider"
        } else {
            "ClaudeGuard Dynamic Security Provider"
        };
        let mut prov_name: Vec<u16> = prov_label.encode_utf16().chain(Some(0)).collect();
        let mut prov_key = provider_guid;
        let provider = FWPM_PROVIDER0 {
            providerKey: prov_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(prov_name.as_mut_ptr()),
                description: PWSTR(prov_name.as_mut_ptr()),
            },
            flags: if persistent {
                FWPM_PROVIDER_FLAG_PERSISTENT
            } else {
                0
            },
            ..Default::default()
        };
        let rc_p = unsafe { FwpmProviderAdd0(engine, &provider, PSECURITY_DESCRIPTOR::default()) };
        if rc_p != ERROR_SUCCESS.0 && rc_p != FWP_E_ALREADY_EXISTS_U32 {
            return Err(wfp_err(rc_p, "FwpmProviderAdd0"));
        }

        let sl_label = if persistent {
            "ClaudeGuard v5 Persistent Boot-Time Sublayer"
        } else {
            "ClaudeGuard v5 Dynamic Kernel Sublayer"
        };
        let mut sl_name: Vec<u16> = sl_label.encode_utf16().chain(Some(0)).collect();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_guid,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name.as_mut_ptr()),
                description: PWSTR(sl_name.as_mut_ptr()),
            },
            flags: if persistent {
                FWPM_SUBLAYER_FLAG_PERSISTENT
            } else {
                0
            },
            providerKey: &mut prov_key,
            weight,
            ..Default::default()
        };
        let rc_s = unsafe { FwpmSubLayerAdd0(engine, &sublayer, PSECURITY_DESCRIPTOR::default()) };
        if rc_s != ERROR_SUCCESS.0 && rc_s != FWP_E_ALREADY_EXISTS_U32 {
            return Err(wfp_err(rc_s, "FwpmSubLayerAdd0"));
        }
        Ok(())
    }

    fn decode_utf16_le_blob(blob: &FWP_BYTE_BLOB) -> String {
        if blob.size < 2 || blob.data.is_null() {
            return String::new();
        }
        let byte_len = (blob.size as usize).min(64 * 1024);
        let raw = unsafe { core::slice::from_raw_parts(blob.data, byte_len) };
        let mut units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16_lossy(&units)
    }

    /// `FwpmNetEventSubscribe4` system RPC callback.
    ///
    /// Performs O(1) `try_read()` attribution lookup, immediately discarding unrelated OS drops,
    /// and never panics across the FFI boundary or blocks on locks/disk I/O.
    ///
    /// # Safety
    ///
    /// `context`, when non-null, must point to a live [`WfpEventStore`] that outlives the
    /// subscription (guaranteed by [`WfpNetEventSubscription`] calling `FwpmNetEventUnsubscribe0`
    /// before dropping its `Arc<WfpEventStore>`). `event`, when non-null, must point to a valid
    /// `FWPM_NET_EVENT5` supplied by Windows BFE.
    pub unsafe extern "system" fn wfp_net_event_callback_v4(
        context: *mut c_void,
        event: *const FWPM_NET_EVENT5,
    ) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if context.is_null() || event.is_null() {
                return;
            }
            let ev = unsafe { &*event };
            if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                return;
            }
            let drop_ptr = unsafe { ev.Anonymous.classifyDrop };
            if drop_ptr.is_null() {
                return;
            }
            let filter_id = unsafe { (*drop_ptr).filterId };
            let store = unsafe { &*(context as *const WfpEventStore) };

            let Some(attr_snapshot) = store.lookup_try(filter_id) else {
                return;
            };

            let hdr = &ev.header;
            let flags = hdr.flags;
            let has_ip_ver = (flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET) != 0;
            let has_remote_addr = (flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) != 0;
            let has_remote_port = (flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) != 0;
            let has_ip_proto = (flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) != 0;
            let has_app_id = (flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) != 0;

            let (remote_ip_str, fallback_layer): (String, &str) = if has_ip_ver {
                if hdr.ipVersion == FWP_IP_VERSION_V4 {
                    let ip_s = if has_remote_addr {
                        IpAddr::V4(ipv4_from_wfp_host_u32(unsafe {
                            hdr.Anonymous2.remoteAddrV4
                        }))
                        .to_string()
                    } else {
                        String::new()
                    };
                    (ip_s, "ale_auth_connect_v4")
                } else if hdr.ipVersion == FWP_IP_VERSION_V6 {
                    let ip_s = if has_remote_addr {
                        IpAddr::V6(Ipv6Addr::from(unsafe {
                            hdr.Anonymous2.remoteAddrV6.byteArray16
                        }))
                        .to_string()
                    } else {
                        String::new()
                    };
                    (ip_s, "ale_auth_connect_v6")
                } else {
                    return;
                }
            } else {
                (String::new(), attr_snapshot.layer.as_str())
            };

            let app_path = if has_app_id {
                decode_utf16_le_blob(&hdr.appId)
            } else {
                String::new()
            };
            let remote_port = if has_remote_port { hdr.remotePort } else { 0 };
            let proto = if has_ip_proto {
                protocol_label(hdr.ipProtocol)
            } else {
                "other"
            };
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            store.record_blocked_drop(
                filter_id,
                timestamp_ms,
                None,
                app_path,
                remote_ip_str,
                remote_port,
                proto,
                fallback_layer,
            );
        }));
    }

    // ---- Filter Construction Helpers ----

    #[inline]
    fn cond_app_id(blob: &WfpAppIdBlob, match_type: FWP_MATCH_TYPE) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: match_type,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: blob.as_ptr(),
                },
            },
        }
    }

    #[inline]
    fn cond_loopback(is_loopback: bool) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: if is_loopback {
                FWP_MATCH_FLAGS_ALL_SET
            } else {
                FWP_MATCH_FLAGS_NONE_SET
            },
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            },
        }
    }

    #[inline]
    fn cond_ip_protocol(proto: u8) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: proto },
            },
        }
    }

    #[inline]
    fn cond_remote_port(port: u16, match_type: FWP_MATCH_TYPE) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: match_type,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_filter_raw(
        engine: HANDLE,
        provider_guid: GUID,
        sublayer_guid: GUID,
        layer_guid: GUID,
        weight: u8,
        action: FWP_ACTION_TYPE,
        flags: FWPM_FILTER_FLAGS,
        display_name: &str,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> PlatformResult<u64> {
        let mut name_w: Vec<u16> = display_name.encode_utf16().chain(Some(0)).collect();
        let mut prov = provider_guid;
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_w.as_mut_ptr()),
                description: PWSTR(name_w.as_mut_ptr()),
            },
            flags,
            providerKey: &mut prov,
            layerKey: layer_guid,
            subLayerKey: sublayer_guid,
            weight: explicit_u8_weight(weight),
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                core::ptr::null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: action,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut fid = 0u64;
        let rc = unsafe {
            FwpmFilterAdd0(
                engine,
                &filter,
                PSECURITY_DESCRIPTOR::default(),
                Some(&mut fid),
            )
        };
        if rc != ERROR_SUCCESS.0 {
            return Err(wfp_err(rc, &format!("FwpmFilterAdd0({display_name})")));
        }
        Ok(fid)
    }

    fn delete_filter_id_idempotent(engine: HANDLE, filter_id: u64) -> PlatformResult<bool> {
        let rc = unsafe { FwpmFilterDeleteById0(engine, filter_id) };
        if rc == ERROR_SUCCESS.0 {
            Ok(true)
        } else if rc == FWP_E_FILTER_NOT_FOUND_U32 {
            Ok(false)
        } else {
            Err(wfp_err(rc, "FwpmFilterDeleteById0"))
        }
    }

    /// Enumerate all filter IDs owned by `provider_guid` in `target_sublayer_guid` across the 4 ALE layers.
    pub fn enumerate_sublayer_filter_ids(
        engine: HANDLE,
        provider_guid: GUID,
        target_sublayer_guid: GUID,
        include_boottime: bool,
    ) -> PlatformResult<Vec<u64>> {
        let mut ids = Vec::new();
        let mut prov = provider_guid;
        let flags = if include_boottime {
            FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED
        } else {
            FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED
        };

        for layer in ALL_MANAGED_LAYERS {
            let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                providerKey: &mut prov,
                layerKey: layer,
                enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
                flags,
                actionMask: 0xFFFF_FFFF,
                ..Default::default()
            };
            let mut enum_handle = HANDLE::default();
            let rc =
                unsafe { FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle) };
            if rc != ERROR_SUCCESS.0 {
                return Err(wfp_err(rc, "FwpmFilterCreateEnumHandle0"));
            }
            let _enum_guard = FilterEnumGuard {
                engine,
                enum_handle,
            };

            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = core::ptr::null_mut();
                let mut returned: u32 = 0;
                let rc_e = unsafe {
                    FwpmFilterEnum0(engine, enum_handle, 128, &mut entries, &mut returned)
                };
                if rc_e != ERROR_SUCCESS.0 {
                    return Err(wfp_err(rc_e, "FwpmFilterEnum0"));
                }
                if returned > 0 && !entries.is_null() {
                    let slice = unsafe { core::slice::from_raw_parts(entries, returned as usize) };
                    for &ptr in slice {
                        if !ptr.is_null() {
                            let f = unsafe { &*ptr };
                            if f.subLayerKey == target_sublayer_guid {
                                ids.push(f.filterId);
                            }
                        }
                    }
                }
                if !entries.is_null() {
                    let mut raw: *mut c_void = entries.cast();
                    unsafe {
                        FwpmFreeMemory0(&mut raw);
                    }
                }
                if returned < 128 {
                    break;
                }
            }
        }
        Ok(ids)
    }

    /// Add Weight 15 GlobalCut filters on `ALE_AUTH_CONNECT_V4/V6` (`!IS_LOOPBACK`, optionally excluding daemon).
    fn add_global_cut_filters(
        engine: HANDLE,
        sublayer_guid: GUID,
        daemon_blob: Option<&WfpAppIdBlob>,
        reason: &str,
        attributions: &mut HashMap<u64, WfpFilterAttribution>,
    ) -> PlatformResult<Vec<u64>> {
        let mut created = Vec::with_capacity(2);
        for (layer, layer_name) in ALE_CONNECT_LAYERS {
            let mut conds = Vec::with_capacity(2);
            conds.push(cond_loopback(false));
            if let Some(blob) = daemon_blob {
                conds.push(cond_app_id(blob, FWP_MATCH_NOT_EQUAL));
            }
            let fid = add_filter_raw(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                sublayer_guid,
                layer,
                WFP_WEIGHT_GLOBAL_CUT,
                FWP_ACTION_BLOCK,
                FWPM_FILTER_FLAG_NONE,
                "ClaudeGuard Global Outbound Cut",
                &mut conds,
            )?;
            attributions.insert(
                fid,
                WfpFilterAttribution {
                    agent_id: String::new(),
                    filter_reason: reason.to_string(),
                    layer: layer_name.to_string(),
                },
            );
            created.push(fid);
        }
        Ok(created)
    }

    /// Add Weight 14 Per-App Quarantine / Lockdown / Boot-Time Guard filters (`!IS_LOOPBACK`).
    #[allow(clippy::too_many_arguments)]
    fn add_app_block_filters(
        engine: HANDLE,
        provider_guid: GUID,
        sublayer_guid: GUID,
        app_blob: &WfpAppIdBlob,
        agent_id: &str,
        reason: &str,
        include_outbound: bool,
        include_inbound: bool,
        flags: FWPM_FILTER_FLAGS,
        display_name: &str,
        attributions: &mut HashMap<u64, WfpFilterAttribution>,
    ) -> PlatformResult<Vec<u64>> {
        let mut created = Vec::with_capacity(4);
        if include_outbound {
            for (layer, layer_name) in ALE_CONNECT_LAYERS {
                let mut conds = [cond_app_id(app_blob, FWP_MATCH_EQUAL), cond_loopback(false)];
                let fid = add_filter_raw(
                    engine,
                    provider_guid,
                    sublayer_guid,
                    layer,
                    WFP_WEIGHT_QUARANTINE_OR_LOCKDOWN,
                    FWP_ACTION_BLOCK,
                    flags,
                    display_name,
                    &mut conds,
                )?;
                attributions.insert(
                    fid,
                    WfpFilterAttribution {
                        agent_id: agent_id.to_string(),
                        filter_reason: reason.to_string(),
                        layer: layer_name.to_string(),
                    },
                );
                created.push(fid);
            }
        }
        if include_inbound {
            for (layer, layer_name) in ALE_RECV_LAYERS {
                let mut conds = [cond_app_id(app_blob, FWP_MATCH_EQUAL), cond_loopback(false)];
                let fid = add_filter_raw(
                    engine,
                    provider_guid,
                    sublayer_guid,
                    layer,
                    WFP_WEIGHT_QUARANTINE_OR_LOCKDOWN,
                    FWP_ACTION_BLOCK,
                    flags,
                    display_name,
                    &mut conds,
                )?;
                attributions.insert(
                    fid,
                    WfpFilterAttribution {
                        agent_id: agent_id.to_string(),
                        filter_reason: reason.to_string(),
                        layer: layer_name.to_string(),
                    },
                );
                created.push(fid);
            }
        }
        Ok(created)
    }

    /// Add Weight 13 4-Vector Leak Shield filters for one resolved executable.
    ///
    /// - Vector 1 (`UDP:443`): excludes loopback (`!IS_LOOPBACK`) so localhost HTTP/3 dev servers work.
    /// - Vector 2 (`DNS/DoT/DoH`): when `active_tun_luid` is present, adds `IP_LOCAL_INTERFACE != tun_luid`
    ///   so DNS/DoH routed *through* the verified TUN adapter succeeds while physical NIC leaks are blocked.
    /// - Vector 3 (`IPv6`): when `active_tun_luid` is present, excludes `fc00::/7` ULA (preserving Mihomo /
    ///   sing-box IPv6 Fake-IP) and adds `IP_LOCAL_INTERFACE != tun_luid`.
    #[allow(clippy::too_many_arguments)]
    fn add_app_leak_shield_filters(
        engine: HANDLE,
        sublayer_guid: GUID,
        app_blob: &WfpAppIdBlob,
        agent_id: &str,
        block_quic: bool,
        block_dns_doh: bool,
        block_ipv6: bool,
        active_tun_luid: Option<u64>,
        attributions: &mut HashMap<u64, WfpFilterAttribution>,
    ) -> PlatformResult<Vec<u64>> {
        let mut created = Vec::new();
        let mut tun_luid_cell = active_tun_luid;

        // Vector 1: Non-loopback QUIC UDP:443 (V4 + V6)
        if block_quic {
            for (layer, layer_name) in ALE_CONNECT_LAYERS {
                let mut conds = [
                    cond_app_id(app_blob, FWP_MATCH_EQUAL),
                    cond_loopback(false),
                    cond_ip_protocol(17),
                    cond_remote_port(443, FWP_MATCH_EQUAL),
                ];
                let fid = add_filter_raw(
                    engine,
                    CLAUDEGUARD_WFP_PROVIDER_GUID,
                    sublayer_guid,
                    layer,
                    WFP_WEIGHT_LEAK_SHIELD,
                    FWP_ACTION_BLOCK,
                    FWPM_FILTER_FLAG_NONE,
                    "ClaudeGuard Leak Shield QUIC UDP:443",
                    &mut conds,
                )?;
                attributions.insert(
                    fid,
                    WfpFilterAttribution {
                        agent_id: agent_id.to_string(),
                        filter_reason: "quic_shield".to_string(),
                        layer: layer_name.to_string(),
                    },
                );
                created.push(fid);
            }
        }

        // Vector 2: Direct DNS (53), DoT (853), and Public DoH (443) outside verified TUN
        if block_dns_doh {
            // (2a) Non-loopback port 53 or 853 on V4 & V6 (exempting verified active_tun_luid)
            for (layer, layer_name) in ALE_CONNECT_LAYERS {
                let mut conds = Vec::with_capacity(5);
                conds.push(cond_app_id(app_blob, FWP_MATCH_EQUAL));
                conds.push(cond_loopback(false));
                if let Some(ref mut luid_val) = tun_luid_cell {
                    conds.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                        matchType: FWP_MATCH_NOT_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT64,
                            Anonymous: FWP_CONDITION_VALUE0_0 { uint64: luid_val },
                        },
                    });
                }
                conds.push(cond_remote_port(53, FWP_MATCH_EQUAL));
                conds.push(cond_remote_port(853, FWP_MATCH_EQUAL));
                let fid = add_filter_raw(
                    engine,
                    CLAUDEGUARD_WFP_PROVIDER_GUID,
                    sublayer_guid,
                    layer,
                    WFP_WEIGHT_LEAK_SHIELD,
                    FWP_ACTION_BLOCK,
                    FWPM_FILTER_FLAG_NONE,
                    "ClaudeGuard Leak Shield Direct DNS/DoT",
                    &mut conds,
                )?;
                attributions.insert(
                    fid,
                    WfpFilterAttribution {
                        agent_id: agent_id.to_string(),
                        filter_reason: "doh_shield".to_string(),
                        layer: layer_name.to_string(),
                    },
                );
                created.push(fid);
            }

            // (2b) Public DoH IPv4 endpoints on port 443 (keep `v4_masks` alive across FwpmFilterAdd0)
            let mut v4_masks: Vec<FWP_V4_ADDR_AND_MASK> = PUBLIC_DOH_IPV4
                .iter()
                .map(|ip| v4_addr_mask(*ip, 32))
                .collect();
            let mut conds_v4 = Vec::with_capacity(4 + v4_masks.len());
            conds_v4.push(cond_app_id(app_blob, FWP_MATCH_EQUAL));
            conds_v4.push(cond_loopback(false));
            if let Some(ref mut luid_val) = tun_luid_cell {
                conds_v4.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    matchType: FWP_MATCH_NOT_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT64,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint64: luid_val },
                    },
                });
            }
            conds_v4.push(cond_remote_port(443, FWP_MATCH_EQUAL));
            for m in &mut v4_masks {
                conds_v4.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: m },
                    },
                });
            }
            let fid_doh_v4 = add_filter_raw(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                sublayer_guid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                WFP_WEIGHT_LEAK_SHIELD,
                FWP_ACTION_BLOCK,
                FWPM_FILTER_FLAG_NONE,
                "ClaudeGuard Leak Shield Public DoH IPv4",
                &mut conds_v4,
            )?;
            attributions.insert(
                fid_doh_v4,
                WfpFilterAttribution {
                    agent_id: agent_id.to_string(),
                    filter_reason: "doh_shield".to_string(),
                    layer: "ale_auth_connect_v4".to_string(),
                },
            );
            created.push(fid_doh_v4);

            // (2c) Public DoH IPv6 endpoints on port 443
            let mut v6_masks: Vec<FWP_V6_ADDR_AND_MASK> = PUBLIC_DOH_IPV6
                .iter()
                .map(|ip| v6_addr_mask(*ip, 128))
                .collect();
            let mut conds_v6 = Vec::with_capacity(4 + v6_masks.len());
            conds_v6.push(cond_app_id(app_blob, FWP_MATCH_EQUAL));
            conds_v6.push(cond_loopback(false));
            if let Some(ref mut luid_val) = tun_luid_cell {
                conds_v6.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    matchType: FWP_MATCH_NOT_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT64,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint64: luid_val },
                    },
                });
            }
            conds_v6.push(cond_remote_port(443, FWP_MATCH_EQUAL));
            for m in &mut v6_masks {
                conds_v6.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: m },
                    },
                });
            }
            let fid_doh_v6 = add_filter_raw(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                sublayer_guid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                WFP_WEIGHT_LEAK_SHIELD,
                FWP_ACTION_BLOCK,
                FWPM_FILTER_FLAG_NONE,
                "ClaudeGuard Leak Shield Public DoH IPv6",
                &mut conds_v6,
            )?;
            attributions.insert(
                fid_doh_v6,
                WfpFilterAttribution {
                    agent_id: agent_id.to_string(),
                    filter_reason: "doh_shield".to_string(),
                    layer: "ale_auth_connect_v6".to_string(),
                },
            );
            created.push(fid_doh_v6);
        }

        // Vector 3: Direct Public IPv6 Leak Shield (`2000::/3`, `64:ff9b::/96`; skip `fc00::/7` ULA
        // when TUN is active so Mihomo/sing-box Fake-IP v6 is never blocked).
        if block_ipv6 {
            let mut v6_ranges: Vec<FWP_V6_ADDR_AND_MASK> = GLOBAL_IPV6_CIDRS
                .iter()
                .filter(|(ip, plen)| {
                    !(tun_luid_cell.is_some() && ip.segments()[0] == 0xfc00 && *plen == 7)
                })
                .map(|(ip, plen)| v6_addr_mask(*ip, *plen))
                .collect();
            let mut conds_v6 = Vec::with_capacity(3 + v6_ranges.len());
            conds_v6.push(cond_app_id(app_blob, FWP_MATCH_EQUAL));
            conds_v6.push(cond_loopback(false));
            if let Some(ref mut luid_val) = tun_luid_cell {
                conds_v6.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    matchType: FWP_MATCH_NOT_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT64,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint64: luid_val },
                    },
                });
            }
            for m in &mut v6_ranges {
                conds_v6.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: m },
                    },
                });
            }
            let fid_v6 = add_filter_raw(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                sublayer_guid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                WFP_WEIGHT_LEAK_SHIELD,
                FWP_ACTION_BLOCK,
                FWPM_FILTER_FLAG_NONE,
                "ClaudeGuard Leak Shield Public IPv6",
                &mut conds_v6,
            )?;
            attributions.insert(
                fid_v6,
                WfpFilterAttribution {
                    agent_id: agent_id.to_string(),
                    filter_reason: "ipv6_shield".to_string(),
                    layer: "ale_auth_connect_v6".to_string(),
                },
            );
            created.push(fid_v6);
        }

        Ok(created)
    }

    /// Add the Per-App Split-Permit Sandwich (`ALE_AUTH_CONNECT_V4/V6`):
    /// - Weight `11`: PERMIT Loopback (`FWP_CONDITION_FLAG_IS_LOOPBACK`) + optional LAN `active_proxy_endpoint`
    /// - Weight `10`: PERMIT Verified Active TUN `NET_LUID` + WSL2 `vEthernet (WSL)` (`!= 53`)
    /// - Weight `9`:  Optional PERMIT RFC1918 LAN (`REMOTE_PORT != 53`)
    /// - Weight `2`:  BLOCK Catch-All Physical NIC Direct Egress (`direct_nic_bypass`)
    #[allow(clippy::too_many_arguments)]
    pub fn add_app_tunnel_only_sandwich(
        engine: HANDLE,
        sublayer_guid: GUID,
        app_blob: &WfpAppIdBlob,
        active_tun_luid: Option<u64>,
        wsl_luids: &[u64],
        allow_lan_dev_servers: bool,
        agent_id: &str,
        attributions: &mut HashMap<u64, WfpFilterAttribution>,
    ) -> PlatformResult<Vec<u64>> {
        add_app_tunnel_only_sandwich_with_proxy(
            engine,
            sublayer_guid,
            app_blob,
            active_tun_luid,
            wsl_luids,
            allow_lan_dev_servers,
            None,
            agent_id,
            attributions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_app_tunnel_only_sandwich_with_proxy(
        engine: HANDLE,
        sublayer_guid: GUID,
        app_blob: &WfpAppIdBlob,
        active_tun_luid: Option<u64>,
        wsl_luids: &[u64],
        allow_lan_dev_servers: bool,
        active_proxy_endpoint: Option<(IpAddr, u16)>,
        agent_id: &str,
        attributions: &mut HashMap<u64, WfpFilterAttribution>,
    ) -> PlatformResult<Vec<u64>> {
        let mut created = Vec::with_capacity(9 + wsl_luids.len() * 2);

        // (A0) Weight 11: Scoped TCP Permit for non-loopback configured proxy endpoint (e.g. LAN gateway proxy)
        if let Some((proxy_ip, proxy_port)) = active_proxy_endpoint {
            if proxy_port > 0 && !proxy_ip.is_loopback() && !proxy_ip.is_unspecified() {
                match proxy_ip {
                    IpAddr::V4(v4) => {
                        let mut mask_v4 = v4_addr_mask(v4, 32);
                        let mut conds_v4 = [
                            cond_app_id(app_blob, FWP_MATCH_EQUAL),
                            cond_ip_protocol(6),
                            cond_remote_port(proxy_port, FWP_MATCH_EQUAL),
                            FWPM_FILTER_CONDITION0 {
                                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V4_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v4AddrMask: &mut mask_v4,
                                    },
                                },
                            },
                        ];
                        let fid_v4 = add_filter_raw(
                            engine,
                            CLAUDEGUARD_WFP_PROVIDER_GUID,
                            sublayer_guid,
                            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                            WFP_WEIGHT_LOOPBACK_PERMIT,
                            FWP_ACTION_PERMIT,
                            FWPM_FILTER_FLAG_NONE,
                            "ClaudeGuard Active Proxy Endpoint Permit (V4)",
                            &mut conds_v4,
                        )?;
                        created.push(fid_v4);

                        // Also permit dual-stack IPv4-mapped IPv6 (`::ffff:a.b.c.d`) sockets
                        let mut mask_mapped = v6_addr_mask(v4.to_ipv6_mapped(), 128);
                        let mut conds_mapped = [
                            cond_app_id(app_blob, FWP_MATCH_EQUAL),
                            cond_ip_protocol(6),
                            cond_remote_port(proxy_port, FWP_MATCH_EQUAL),
                            FWPM_FILTER_CONDITION0 {
                                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V6_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v6AddrMask: &mut mask_mapped,
                                    },
                                },
                            },
                        ];
                        let fid_mapped = add_filter_raw(
                            engine,
                            CLAUDEGUARD_WFP_PROVIDER_GUID,
                            sublayer_guid,
                            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            WFP_WEIGHT_LOOPBACK_PERMIT,
                            FWP_ACTION_PERMIT,
                            FWPM_FILTER_FLAG_NONE,
                            "ClaudeGuard Active Proxy Endpoint Permit (Mapped V6)",
                            &mut conds_mapped,
                        )?;
                        created.push(fid_mapped);
                    }
                    IpAddr::V6(v6) => {
                        let mut mask_v6 = v6_addr_mask(v6, 128);
                        let mut conds_v6 = [
                            cond_app_id(app_blob, FWP_MATCH_EQUAL),
                            cond_ip_protocol(6),
                            cond_remote_port(proxy_port, FWP_MATCH_EQUAL),
                            FWPM_FILTER_CONDITION0 {
                                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V6_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v6AddrMask: &mut mask_v6,
                                    },
                                },
                            },
                        ];
                        let fid_v6 = add_filter_raw(
                            engine,
                            CLAUDEGUARD_WFP_PROVIDER_GUID,
                            sublayer_guid,
                            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            WFP_WEIGHT_LOOPBACK_PERMIT,
                            FWP_ACTION_PERMIT,
                            FWPM_FILTER_FLAG_NONE,
                            "ClaudeGuard Active Proxy Endpoint Permit (V6)",
                            &mut conds_v6,
                        )?;
                        created.push(fid_v6);
                    }
                }
            }
        }

        for (layer, layer_name) in ALE_CONNECT_LAYERS {
            // (A) Weight 11: Permit Loopback (127.0.0.1 proxy, Antigravity LSP, local MCP)
            let mut conds_lo = [cond_app_id(app_blob, FWP_MATCH_EQUAL), cond_loopback(true)];
            let fid_lo = add_filter_raw(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                sublayer_guid,
                layer,
                WFP_WEIGHT_LOOPBACK_PERMIT,
                FWP_ACTION_PERMIT,
                FWPM_FILTER_FLAG_NONE,
                "ClaudeGuard Loopback Permit",
                &mut conds_lo,
            )?;
            created.push(fid_lo);

            // (B) Weight 10: Permit Verified Active TUN NET_LUID
            if let Some(mut luid_val) = active_tun_luid {
                let mut conds_tun = [
                    cond_app_id(app_blob, FWP_MATCH_EQUAL),
                    FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT64,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint64: &mut luid_val,
                            },
                        },
                    },
                ];
                let fid_tun = add_filter_raw(
                    engine,
                    CLAUDEGUARD_WFP_PROVIDER_GUID,
                    sublayer_guid,
                    layer,
                    WFP_WEIGHT_ACTIVE_TUN_PERMIT,
                    FWP_ACTION_PERMIT,
                    FWPM_FILTER_FLAG_NONE,
                    "ClaudeGuard Active TUN NET_LUID Permit",
                    &mut conds_tun,
                )?;
                created.push(fid_tun);
            }

            // (B2) Weight 10: Permit WSL2 `vEthernet (WSL)` local virtual bridge (excluding DNS :53)
            for &wsl_raw in wsl_luids {
                if Some(wsl_raw) == active_tun_luid || wsl_raw == 0 {
                    continue;
                }
                let mut wsl_luid_val = wsl_raw;
                let mut conds_wsl = [
                    cond_app_id(app_blob, FWP_MATCH_EQUAL),
                    FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT64,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint64: &mut wsl_luid_val,
                            },
                        },
                    },
                    cond_remote_port(53, FWP_MATCH_NOT_EQUAL),
                ];
                let fid_wsl = add_filter_raw(
                    engine,
                    CLAUDEGUARD_WFP_PROVIDER_GUID,
                    sublayer_guid,
                    layer,
                    WFP_WEIGHT_ACTIVE_TUN_PERMIT,
                    FWP_ACTION_PERMIT,
                    FWPM_FILTER_FLAG_NONE,
                    "ClaudeGuard WSL2 Virtual Bridge Permit (Non-DNS)",
                    &mut conds_wsl,
                )?;
                created.push(fid_wsl);
            }

            // (C) Weight 2: Catch-All Physical NIC Hard-Block
            let mut conds_blk = [cond_app_id(app_blob, FWP_MATCH_EQUAL)];
            let fid_blk = add_filter_raw(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                sublayer_guid,
                layer,
                WFP_WEIGHT_DIRECT_NIC_BLOCK,
                FWP_ACTION_BLOCK,
                FWPM_FILTER_FLAG_NONE,
                "ClaudeGuard Physical NIC Hard Block",
                &mut conds_blk,
            )?;
            attributions.insert(
                fid_blk,
                WfpFilterAttribution {
                    agent_id: agent_id.to_string(),
                    filter_reason: "direct_nic_bypass".to_string(),
                    layer: layer_name.to_string(),
                },
            );
            created.push(fid_blk);
        }

        // (D) Optional Weight 9: RFC1918 LAN Dev Exemption on IPv4 (strictly excluding DNS port 53)
        if allow_lan_dev_servers {
            let mut lan_masks: Vec<FWP_V4_ADDR_AND_MASK> = RFC1918_LAN_CIDRS
                .iter()
                .map(|(ip, plen)| v4_addr_mask(*ip, *plen))
                .collect();
            let mut conds_lan = Vec::with_capacity(2 + lan_masks.len());
            conds_lan.push(cond_app_id(app_blob, FWP_MATCH_EQUAL));
            conds_lan.push(cond_remote_port(53, FWP_MATCH_NOT_EQUAL));
            for m in &mut lan_masks {
                conds_lan.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: m },
                    },
                });
            }
            let fid_lan = add_filter_raw(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                sublayer_guid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                WFP_WEIGHT_LAN_EXEMPT_PERMIT,
                FWP_ACTION_PERMIT,
                FWPM_FILTER_FLAG_NONE,
                "ClaudeGuard LAN Dev Exemption (Non-DNS)",
                &mut conds_lan,
            )?;
            created.push(fid_lan);
        }

        Ok(created)
    }

    /// Idempotently purge all persistent and boot-time ClaudeGuard WFP filters, remove the
    /// persistent sublayer and persistent provider, and verify `remaining == 0` via readback.
    pub fn clear_persistent_filters_native() -> PlatformResult<RemoveReport> {
        let session = WfpSessionHandle::open(false, "ClaudeGuard Persistent Cleanup")?;
        let engine = session.raw();

        let existing = enumerate_sublayer_filter_ids(
            engine,
            CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID,
            CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID,
            true,
        )?;
        let mut removed = 0usize;

        {
            let txn = WfpTransactionGuard::begin(engine)?;
            for fid in &existing {
                if delete_filter_id_idempotent(engine, *fid)? {
                    removed += 1;
                }
            }
            let rc_sl = unsafe {
                FwpmSubLayerDeleteByKey0(engine, &CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID)
            };
            if rc_sl != ERROR_SUCCESS.0
                && rc_sl != FWP_E_SUBLAYER_NOT_FOUND_U32
                && rc_sl != FWP_E_IN_USE_U32
            {
                return Err(wfp_err(rc_sl, "FwpmSubLayerDeleteByKey0(Persistent)"));
            }
            let rc_prov = unsafe {
                FwpmProviderDeleteByKey0(engine, &CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID)
            };
            if rc_prov != ERROR_SUCCESS.0
                && rc_prov != FWP_E_PROVIDER_NOT_FOUND_U32
                && rc_prov != FWP_E_IN_USE_U32
            {
                return Err(wfp_err(rc_prov, "FwpmProviderDeleteByKey0(Persistent)"));
            }
            txn.commit()?;
        }

        match enumerate_sublayer_filter_ids(
            engine,
            CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID,
            CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID,
            true,
        ) {
            Ok(left) => Ok(RemoveReport {
                removed,
                remaining: left.len(),
                query_ok: true,
            }),
            Err(_) => Ok(RemoveReport {
                removed,
                remaining: existing.len().saturating_sub(removed),
                query_ok: false,
            }),
        }
    }

    /// Synchronize opt-in `FWPM_FILTER_FLAG_BOOTTIME` filters in the persistent sublayer (`0xFF10`).
    pub fn sync_boot_time_guard_native(
        enable: bool,
        app_exes: &[PathBuf],
        event_store: Option<&WfpEventStore>,
    ) -> PlatformResult<usize> {
        let (count, _) = sync_boot_time_guard_with_attrs(enable, app_exes, event_store)?;
        Ok(count)
    }

    fn sync_boot_time_guard_with_attrs(
        enable: bool,
        app_exes: &[PathBuf],
        event_store: Option<&WfpEventStore>,
    ) -> PlatformResult<(usize, HashMap<u64, WfpFilterAttribution>)> {
        if !enable || app_exes.is_empty() {
            let _ = clear_persistent_filters_native()?;
            return Ok((0, HashMap::new()));
        }

        let session = WfpSessionHandle::open(false, "ClaudeGuard Boot-Time Guard")?;
        let engine = session.raw();

        let existing = enumerate_sublayer_filter_ids(
            engine,
            CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID,
            CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID,
            true,
        )?;

        let mut created_ids = Vec::new();
        let mut new_attrs = HashMap::new();

        {
            let txn = WfpTransactionGuard::begin(engine)?;
            ensure_provider_and_sublayer(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID,
                CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID,
                WFP_SUBLAYER_WEIGHT_PERSISTENT,
                true,
            )?;

            for fid in &existing {
                let _ = delete_filter_id_idempotent(engine, *fid)?;
            }

            let mut dedup_paths = HashSet::new();
            for raw_exe in app_exes {
                if is_non_pe_script_shim(raw_exe) {
                    continue;
                }
                let resolved = resolve_program_path_for_firewall(raw_exe);
                if is_non_pe_script_shim(&resolved) {
                    continue;
                }
                let key = normalize_program_path(&resolved.to_string_lossy());
                if key.is_empty() || !dedup_paths.insert(key) {
                    continue;
                }
                let Ok(blob) = WfpAppIdBlob::from_path(&resolved) else {
                    continue;
                };
                let agent_id = infer_agent_id_from_exe_path(&resolved);
                let ids = add_app_block_filters(
                    engine,
                    CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID,
                    CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID,
                    &blob,
                    &agent_id,
                    "boot_time_guard",
                    true,
                    false,
                    FWPM_FILTER_FLAG_BOOTTIME,
                    "ClaudeGuard Boot-Time App Guard",
                    &mut new_attrs,
                )?;
                created_ids.extend(ids);
            }
            txn.commit()?;
        }

        if let Some(store) = event_store {
            store.remove_filter_ids(&existing);
            for (fid, attr) in &new_attrs {
                store.insert_filter_meta(*fid, attr.clone());
            }
        }

        Ok((created_ids.len(), new_attrs))
    }

    // ---- Dynamic Session State & WfpFirewallEngine ----

    #[derive(Clone, Debug)]
    struct TrackedRuleEntry {
        record: FirewallRuleRecord,
        filter_ids: Vec<u64>,
        attributions: Vec<(u64, WfpFilterAttribution)>,
    }

    struct WfpDynamicState {
        rule_entries: Vec<TrackedRuleEntry>,
        posture_filter_ids: Vec<u64>,
        posture_attributions: HashMap<u64, WfpFilterAttribution>,
        posture_shield_filter_count: usize,
        posture_quic_blocked: bool,
        posture_dns_doh_blocked: bool,
        posture_ipv6_blocked: bool,
        shield_filter_ids: Vec<u64>,
        shield_attributions: HashMap<u64, WfpFilterAttribution>,
        shield_quic_blocked: bool,
        shield_dns_doh_blocked: bool,
        shield_ipv6_blocked: bool,
        boot_attributions: HashMap<u64, WfpFilterAttribution>,
        boot_time_filters_armed: bool,
        last_error: String,
    }

    impl WfpDynamicState {
        fn total_active_filters(&self) -> usize {
            let rule_count: usize = self.rule_entries.iter().map(|e| e.filter_ids.len()).sum();
            rule_count + self.posture_filter_ids.len() + self.shield_filter_ids.len()
        }

        fn rebuild_attribution_map(&self) -> HashMap<u64, WfpFilterAttribution> {
            let mut map = HashMap::new();
            for (fid, attr) in &self.boot_attributions {
                map.insert(*fid, attr.clone());
            }
            for entry in &self.rule_entries {
                for (fid, attr) in &entry.attributions {
                    map.insert(*fid, attr.clone());
                }
            }
            for (fid, attr) in &self.posture_attributions {
                map.insert(*fid, attr.clone());
            }
            for (fid, attr) in &self.shield_attributions {
                map.insert(*fid, attr.clone());
            }
            map
        }
    }

    /// Dual-session kernel Windows Filtering Platform (WFP) firewall engine.
    ///
    /// Drop order invariant: `net_event_sub` is declared BEFORE `session` so
    /// `FwpmNetEventUnsubscribe0` always finishes before `FwpmEngineClose0` runs.
    pub struct WfpFirewallEngine {
        net_event_sub: Option<WfpNetEventSubscription>,
        session: WfpSessionHandle,
        events: Arc<WfpEventStore>,
        state: Mutex<WfpDynamicState>,
        sublayer_registered: bool,
        net_event_subscribed: bool,
    }

    impl std::fmt::Debug for WfpFirewallEngine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WfpFirewallEngine")
                .field("sublayer_registered", &self.sublayer_registered)
                .field("net_event_subscribed", &self.net_event_subscribed)
                .finish()
        }
    }

    impl WfpFirewallEngine {
        /// Open a dynamic WFP session, register Provider + Dynamic Sublayer (`0xFF00`),
        /// enable BFE net-event collection, and attach `FwpmNetEventSubscribe4`.
        pub fn open() -> PlatformResult<Self> {
            let session = WfpSessionHandle::open(true, "ClaudeGuard v5 Dynamic Session")?;
            let engine = session.raw();

            {
                let txn = WfpTransactionGuard::begin(engine)?;
                ensure_provider_and_sublayer(
                    engine,
                    CLAUDEGUARD_WFP_PROVIDER_GUID,
                    CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                    WFP_SUBLAYER_WEIGHT_DYNAMIC,
                    false,
                )?;
                txn.commit()?;
            }

            let events = Arc::new(WfpEventStore::new());
            let mut last_error = String::new();
            let mut net_event_sub = None;

            if let Err(err) = enable_bfe_net_events(engine) {
                last_error = format!("BFE net-event collection unavailable: {err}");
            } else {
                match WfpNetEventSubscription::subscribe(engine, Arc::clone(&events)) {
                    Ok(sub) => {
                        net_event_sub = Some(sub);
                    }
                    Err(err) => {
                        last_error = format!("FwpmNetEventSubscribe4 unavailable: {err}");
                    }
                }
            }

            let net_event_subscribed = net_event_sub.is_some();

            // Check read-only whether persistent boot-time filters are currently armed and seed
            // `boot_attributions` so early boot drops remain attributed across dynamic re-syncs.
            let boot_ids = enumerate_sublayer_filter_ids(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID,
                CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID,
                true,
            )
            .unwrap_or_default();
            let boot_time_filters_armed = !boot_ids.is_empty();
            let mut boot_attributions = HashMap::with_capacity(boot_ids.len());
            for fid in boot_ids {
                boot_attributions.insert(
                    fid,
                    WfpFilterAttribution {
                        agent_id: String::new(),
                        filter_reason: "boot_time_guard".into(),
                        layer: String::new(),
                    },
                );
            }
            if !boot_attributions.is_empty() {
                events.replace_filter_map(boot_attributions.clone());
            }

            Ok(Self {
                net_event_sub,
                session,
                events,
                state: Mutex::new(WfpDynamicState {
                    rule_entries: Vec::new(),
                    posture_filter_ids: Vec::new(),
                    posture_attributions: HashMap::new(),
                    posture_shield_filter_count: 0,
                    posture_quic_blocked: false,
                    posture_dns_doh_blocked: false,
                    posture_ipv6_blocked: false,
                    shield_filter_ids: Vec::new(),
                    shield_attributions: HashMap::new(),
                    shield_quic_blocked: false,
                    shield_dns_doh_blocked: false,
                    shield_ipv6_blocked: false,
                    boot_attributions,
                    boot_time_filters_armed,
                    last_error,
                }),
                sublayer_registered: true,
                net_event_subscribed,
            })
        }

        pub(crate) fn active_rule_specs(&self) -> Vec<FirewallRuleSpec> {
            let Ok(guard) = self.state.lock() else {
                return Vec::new();
            };
            guard
                .rule_entries
                .iter()
                .map(|e| FirewallRuleSpec {
                    name: e.record.name.clone(),
                    program: (!e.record.program.trim().is_empty())
                        .then(|| PathBuf::from(&e.record.program)),
                    direction: e.record.direction,
                    action: e.record.action,
                    enabled: e.record.enabled,
                    description: None,
                    profiles: e.record.profiles,
                })
                .collect()
        }

        /// Atomically replace the runtime Per-App split-permit sandwich, 4-Vector Leak Shield,
        /// Quarantine/Lockdown, and GlobalCut filters inside a single BFE transaction.
        pub fn sync_tunnel_only_filters(
            &self,
            spec: &WfpRuntimePostureSpec,
        ) -> PlatformResult<WfpStatus> {
            let effective_tun_luid = spec
                .active_tun_luid
                .or_else(|| detect_active_tun_luid_native().map(|(_, luid)| luid));
            let wsl_luids = if spec.strict_tunnel_only {
                detect_wsl_adapter_luids_native()
            } else {
                Vec::new()
            };

            let mut guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;
            let engine = self.session.raw();

            let mut new_ids = Vec::new();
            let mut new_attrs = HashMap::new();
            let mut posture_shield_count = 0usize;
            let mut skipped_exes: Vec<String> = Vec::new();

            let txn_result: PlatformResult<()> = (|| {
                let txn = WfpTransactionGuard::begin(engine)?;

                // Replace BOTH previous posture filters and any standalone `shield_filter_ids` so
                // Weight-13 Leak Shield filters never duplicate (`2*N`) or survive Pause/Disarm.
                for &old_id in &guard.posture_filter_ids {
                    let _ = delete_filter_id_idempotent(engine, old_id)?;
                }
                for &old_id in &guard.shield_filter_ids {
                    let _ = delete_filter_id_idempotent(engine, old_id)?;
                }

                // Weight 15: Global Emergency Cut
                if spec.global_cut_active {
                    let daemon_blob = spec
                        .daemon_self_exe
                        .as_deref()
                        .and_then(|p| WfpAppIdBlob::from_path(p).ok());
                    let ids = add_global_cut_filters(
                        engine,
                        CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                        daemon_blob.as_ref(),
                        "panic_lockdown",
                        &mut new_attrs,
                    )?;
                    new_ids.extend(ids);
                }

                // Weight 14: Per-App Quarantine / Lockdown
                for (agent_id, exes) in &spec.locked_or_quarantined_apps {
                    let mut seen = HashSet::new();
                    for exe in exes {
                        if is_non_pe_script_shim(exe) {
                            continue;
                        }
                        let resolved = resolve_program_path_for_firewall(exe);
                        if is_non_pe_script_shim(&resolved) {
                            continue;
                        }
                        let norm = normalize_program_path(&resolved.to_string_lossy());
                        if norm.is_empty() || !seen.insert(norm) {
                            continue;
                        }
                        let blob = match WfpAppIdBlob::from_path(&resolved) {
                            Ok(b) => b,
                            Err(_) => {
                                skipped_exes.push(resolved.display().to_string());
                                continue;
                            }
                        };
                        let ids = add_app_block_filters(
                            engine,
                            CLAUDEGUARD_WFP_PROVIDER_GUID,
                            CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                            &blob,
                            agent_id,
                            "app_quarantine",
                            true,
                            true,
                            FWPM_FILTER_FLAG_NONE,
                            &format!("ClaudeGuard Quarantine/Lockdown ({agent_id})"),
                            &mut new_attrs,
                        )?;
                        new_ids.extend(ids);
                    }
                }

                // Weight 13 (4-Vector Leak Shield) + Weight 11/10/9/2 (Split-Permit Sandwich)
                for (agent_id, exes) in &spec.guarded_apps {
                    let mut seen = HashSet::new();
                    for exe in exes {
                        if is_non_pe_script_shim(exe) {
                            continue;
                        }
                        let resolved = resolve_program_path_for_firewall(exe);
                        if is_non_pe_script_shim(&resolved) {
                            continue;
                        }
                        let norm = normalize_program_path(&resolved.to_string_lossy());
                        if norm.is_empty() || !seen.insert(norm) {
                            continue;
                        }
                        let blob = match WfpAppIdBlob::from_path(&resolved) {
                            Ok(b) => b,
                            Err(_) => {
                                skipped_exes.push(resolved.display().to_string());
                                continue;
                            }
                        };

                        if spec.block_quic_udp443
                            || spec.block_direct_dns_doh
                            || spec.block_global_ipv6
                        {
                            let shield_ids = add_app_leak_shield_filters(
                                engine,
                                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                                &blob,
                                agent_id,
                                spec.block_quic_udp443,
                                spec.block_direct_dns_doh,
                                spec.block_global_ipv6,
                                effective_tun_luid,
                                &mut new_attrs,
                            )?;
                            posture_shield_count += shield_ids.len();
                            new_ids.extend(shield_ids);
                        }

                        if spec.strict_tunnel_only {
                            let sandwich_ids = add_app_tunnel_only_sandwich_with_proxy(
                                engine,
                                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                                &blob,
                                effective_tun_luid,
                                &wsl_luids,
                                spec.allow_lan_dev_servers,
                                spec.active_proxy_endpoint,
                                agent_id,
                                &mut new_attrs,
                            )?;
                            new_ids.extend(sandwich_ids);
                        }
                    }
                }

                txn.commit()
            })();

            if let Err(err) = txn_result {
                guard.last_error = err.to_string();
                return Err(err);
            }

            guard.shield_filter_ids.clear();
            guard.shield_attributions.clear();
            guard.shield_quic_blocked = false;
            guard.shield_dns_doh_blocked = false;
            guard.shield_ipv6_blocked = false;

            guard.posture_filter_ids = new_ids;
            guard.posture_attributions = new_attrs;
            guard.posture_shield_filter_count = posture_shield_count;
            guard.posture_quic_blocked = spec.block_quic_udp443 && posture_shield_count > 0;
            guard.posture_dns_doh_blocked = spec.block_direct_dns_doh && posture_shield_count > 0;
            guard.posture_ipv6_blocked = spec.block_global_ipv6 && posture_shield_count > 0;
            if skipped_exes.is_empty() {
                guard.last_error.clear();
            } else {
                guard.last_error = format!(
                    "部分可执行路径无法生成 WFP AppId（{} 项）：{}",
                    skipped_exes.len(),
                    skipped_exes[0]
                );
            }
            let full_map = guard.rebuild_attribution_map();
            drop(guard);

            self.events.replace_filter_map(full_map);
            Ok(self.status())
        }

        /// Synchronize standalone 4-Vector Leak Shield WFP filters in the dynamic sublayer.
        pub fn sync_leak_shield_wfp(
            &self,
            app_paths: &[PathBuf],
            block_quic: bool,
            block_dns_doh: bool,
            block_ipv6: bool,
        ) -> PlatformResult<LeakShieldStatus> {
            let active_tun_luid = detect_active_tun_luid_native().map(|(_, luid)| luid);
            let mut guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;
            let engine = self.session.raw();

            // When `sync_tunnel_only_filters` already maintains Weight-13 Leak Shield filters inside
            // `posture_filter_ids` with the exact same vector flags, avoid installing duplicate rules.
            let posture_already_covers = guard.posture_shield_filter_count > 0
                && guard.posture_quic_blocked == block_quic
                && guard.posture_dns_doh_blocked == block_dns_doh
                && guard.posture_ipv6_blocked == block_ipv6;

            let mut new_ids = Vec::new();
            let mut new_attrs = HashMap::new();

            let txn_result: PlatformResult<()> = (|| {
                let txn = WfpTransactionGuard::begin(engine)?;
                for &old_id in &guard.shield_filter_ids {
                    let _ = delete_filter_id_idempotent(engine, old_id)?;
                }

                if !posture_already_covers && (block_quic || block_dns_doh || block_ipv6) {
                    let mut seen = HashSet::new();
                    for raw_exe in app_paths {
                        if is_non_pe_script_shim(raw_exe) {
                            continue;
                        }
                        let resolved = resolve_program_path_for_firewall(raw_exe);
                        if is_non_pe_script_shim(&resolved) {
                            continue;
                        }
                        let norm = normalize_program_path(&resolved.to_string_lossy());
                        if norm.is_empty() || !seen.insert(norm) {
                            continue;
                        }
                        let Ok(blob) = WfpAppIdBlob::from_path(&resolved) else {
                            continue;
                        };
                        let agent_id = infer_agent_id_from_exe_path(&resolved);
                        let ids = add_app_leak_shield_filters(
                            engine,
                            CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                            &blob,
                            &agent_id,
                            block_quic,
                            block_dns_doh,
                            block_ipv6,
                            active_tun_luid,
                            &mut new_attrs,
                        )?;
                        new_ids.extend(ids);
                    }
                }
                txn.commit()
            })();

            if let Err(err) = txn_result {
                guard.last_error = err.to_string();
                return Err(err);
            }

            let count = new_ids.len();
            guard.shield_filter_ids = new_ids;
            guard.shield_attributions = new_attrs;
            guard.shield_quic_blocked = block_quic && count > 0;
            guard.shield_dns_doh_blocked = block_dns_doh && count > 0;
            guard.shield_ipv6_blocked = block_ipv6 && count > 0;
            let full_map = guard.rebuild_attribution_map();
            drop(guard);

            self.events.replace_filter_map(full_map);

            Ok(self.inspect_leak_shield())
        }

        /// Read-only inspection of active WFP 4-Vector Leak Shield filters (standalone + posture).
        pub fn inspect_leak_shield(&self) -> LeakShieldStatus {
            let Ok(guard) = self.state.lock() else {
                return LeakShieldStatus {
                    summary: "无法读取 WFP 护盾状态".into(),
                    ..LeakShieldStatus::default()
                };
            };
            let standalone_count = guard.shield_filter_ids.len();
            let posture_count = guard.posture_shield_filter_count;
            let active_rules = standalone_count + posture_count;
            let quic_blocked = (guard.shield_quic_blocked && standalone_count > 0)
                || (guard.posture_quic_blocked && posture_count > 0);
            let dns_doh_blocked = (guard.shield_dns_doh_blocked && standalone_count > 0)
                || (guard.posture_dns_doh_blocked && posture_count > 0);
            let ipv6_blocked = (guard.shield_ipv6_blocked && standalone_count > 0)
                || (guard.posture_ipv6_blocked && posture_count > 0);
            LeakShieldStatus {
                enabled: active_rules > 0,
                quic_blocked,
                dns_doh_blocked,
                ipv6_blocked,
                active_rules,
                summary: summarize_wfp_shield(
                    quic_blocked,
                    dns_doh_blocked,
                    ipv6_blocked,
                    active_rules,
                ),
            }
        }

        /// Atomically purge ALL dynamic WFP filters (`rule_entries`, `posture_filter_ids`,
        /// `shield_filter_ids`, and any orphaned dynamic sublayer filters) in a single transaction.
        pub fn clear_all_dynamic_filters(&self) -> PlatformResult<usize> {
            let mut guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;
            let engine = self.session.raw();
            let live_ids = enumerate_sublayer_filter_ids(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                false,
            )
            .unwrap_or_default();

            let mut to_delete: HashSet<u64> = live_ids.into_iter().collect();
            for entry in &guard.rule_entries {
                to_delete.extend(entry.filter_ids.iter().copied());
            }
            to_delete.extend(guard.posture_filter_ids.iter().copied());
            to_delete.extend(guard.shield_filter_ids.iter().copied());

            let mut removed = 0usize;
            if !to_delete.is_empty() {
                let txn = WfpTransactionGuard::begin(engine)?;
                for fid in to_delete {
                    if delete_filter_id_idempotent(engine, fid)? {
                        removed += 1;
                    }
                }
                txn.commit()?;
            }

            guard.rule_entries.clear();
            guard.posture_filter_ids.clear();
            guard.posture_attributions.clear();
            guard.posture_shield_filter_count = 0;
            guard.posture_quic_blocked = false;
            guard.posture_dns_doh_blocked = false;
            guard.posture_ipv6_blocked = false;
            guard.shield_filter_ids.clear();
            guard.shield_attributions.clear();
            guard.shield_quic_blocked = false;
            guard.shield_dns_doh_blocked = false;
            guard.shield_ipv6_blocked = false;
            guard.last_error.clear();
            let full_map = guard.rebuild_attribution_map();
            drop(guard);

            self.events.replace_filter_map(full_map);
            Ok(removed)
        }

        /// Synchronize opt-in persistent `FWPM_FILTER_FLAG_BOOTTIME` filters.
        pub fn sync_boot_time_guard(
            &self,
            enable: bool,
            app_exes: &[PathBuf],
        ) -> PlatformResult<usize> {
            let (count, boot_attrs) = sync_boot_time_guard_with_attrs(enable, app_exes, None)?;
            if let Ok(mut guard) = self.state.lock() {
                guard.boot_time_filters_armed = count > 0;
                guard.boot_attributions = boot_attrs;
                let full_map = guard.rebuild_attribution_map();
                drop(guard);
                self.events.replace_filter_map(full_map);
            }
            Ok(count)
        }

        /// Idempotently purge all persistent/boot-time filters and verify `remaining == 0`.
        pub fn clear_persistent_filters(&self) -> PlatformResult<RemoveReport> {
            let report = clear_persistent_filters_native()?;
            if let Ok(mut guard) = self.state.lock() {
                if report.clean() {
                    guard.boot_time_filters_armed = false;
                    guard.boot_attributions.clear();
                    let full_map = guard.rebuild_attribution_map();
                    drop(guard);
                    self.events.replace_filter_map(full_map);
                }
            }
            Ok(report)
        }

        /// Read an O(1) snapshot of current WFP engine state and blocked-packet ring buffer.
        pub fn status(&self) -> WfpStatus {
            let (total_blocked_packets, recent_blocked) = self.events.snapshot_events();
            let (boot_time_filters_armed, active_filter_count, last_error) = self
                .state
                .lock()
                .map(|g| {
                    (
                        g.boot_time_filters_armed,
                        g.total_active_filters(),
                        g.last_error.clone(),
                    )
                })
                .unwrap_or_default();

            let _ = &self.net_event_sub;
            WfpStatus {
                active_backend: BACKEND_WFP_DYNAMIC.to_string(),
                sublayer_registered: self.sublayer_registered,
                dynamic_session_open: true,
                boot_time_filters_armed,
                active_filter_count,
                net_event_subscribed: self.net_event_subscribed,
                total_blocked_packets,
                recent_blocked,
                last_error,
            }
        }

        /// Clear the in-memory blocked-packet ring buffer.
        pub fn clear_blocked_events(&self) {
            self.events.clear_events();
        }
    }

    impl FirewallEngine for WfpFirewallEngine {
        fn engine_name(&self) -> &'static str {
            BACKEND_WFP_DYNAMIC
        }

        fn profile_status(&self) -> PlatformResult<FirewallProfileStatus> {
            ComFirewallEngine::new()
                .profile_status()
                .or(Ok(FirewallProfileStatus {
                    domain_enabled: true,
                    private_enabled: true,
                    public_enabled: true,
                }))
        }

        fn ensure_profiles_enabled(&self) -> PlatformResult<bool> {
            // Kernel BFE enforces our dynamic sublayer regardless of MpsSvc profile toggles.
            Ok(true)
        }

        fn enumerate_rules(&self, prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>> {
            let prefix_lower = prefix.trim().to_ascii_lowercase();
            let live_ids: HashSet<u64> = enumerate_sublayer_filter_ids(
                self.session.raw(),
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                false,
            )?
            .into_iter()
            .collect();

            let guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;
            let out = guard
                .rule_entries
                .iter()
                .filter(|entry| {
                    entry
                        .record
                        .name
                        .to_ascii_lowercase()
                        .starts_with(&prefix_lower)
                        && !entry.filter_ids.is_empty()
                        && entry.filter_ids.iter().all(|id| live_ids.contains(id))
                })
                .map(|entry| entry.record.clone())
                .collect();
            Ok(out)
        }

        fn dedupe_rules(&self, prefix: &str) -> PlatformResult<usize> {
            let prefix_lower = prefix.trim().to_ascii_lowercase();
            let mut guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;

            let matching_indices: Vec<usize> = guard
                .rule_entries
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    e.record
                        .name
                        .to_ascii_lowercase()
                        .starts_with(&prefix_lower)
                })
                .map(|(i, _)| i)
                .collect();
            let matching_records: Vec<FirewallRuleRecord> = matching_indices
                .iter()
                .map(|&i| guard.rule_entries[i].record.clone())
                .collect();
            let dup_local = duplicate_rule_indices(&matching_records);
            if dup_local.is_empty() {
                return Ok(0);
            }

            let remove_set: HashSet<usize> =
                dup_local.into_iter().map(|i| matching_indices[i]).collect();

            let engine = self.session.raw();
            {
                let txn = WfpTransactionGuard::begin(engine)?;
                for &idx in &remove_set {
                    for &fid in &guard.rule_entries[idx].filter_ids {
                        let _ = delete_filter_id_idempotent(engine, fid)?;
                    }
                }
                txn.commit()?;
            }

            let mut idx = 0usize;
            guard.rule_entries.retain(|_| {
                let keep = !remove_set.contains(&idx);
                idx += 1;
                keep
            });
            let full_map = guard.rebuild_attribution_map();
            drop(guard);
            self.events.replace_filter_map(full_map);
            Ok(remove_set.len())
        }

        fn ensure_rules(&self, desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage> {
            if desired.is_empty() {
                return Ok(Coverage::default());
            }

            let mut guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;
            let engine = self.session.raw();

            // Reconcile tracked rules against live BFE filters so externally purged filters are re-added.
            if let Ok(live_vec) = enumerate_sublayer_filter_ids(
                engine,
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                false,
            ) {
                let live_set: HashSet<u64> = live_vec.into_iter().collect();
                guard.rule_entries.retain(|e| {
                    !e.filter_ids.is_empty() && e.filter_ids.iter().all(|id| live_set.contains(id))
                });
            }

            let mut newly_added = Vec::new();
            let mut added_count = 0usize;
            let mut last_err: Option<PlatformError> = None;
            let mut pruned_indices: HashSet<usize> = HashSet::new();

            {
                let txn = WfpTransactionGuard::begin(engine)?;
                for spec in desired {
                    if spec.program.as_deref().is_some_and(is_non_pe_script_shim) {
                        continue;
                    }
                    let norm_prog = spec
                        .program
                        .as_deref()
                        .map(|p| {
                            normalize_program_path(
                                &resolve_program_path_for_firewall(p).to_string_lossy(),
                            )
                        })
                        .unwrap_or_default();
                    let name_lower = spec.name.trim().to_ascii_lowercase();

                    let already_present =
                        guard
                            .rule_entries
                            .iter()
                            .chain(newly_added.iter())
                            .any(|e| {
                                e.record.name.trim().to_ascii_lowercase() == name_lower
                                    && normalize_program_path(&e.record.program) == norm_prog
                                    && e.record.direction == spec.direction
                                    && e.record.action == spec.action
                                    && e.record.enabled == spec.enabled
                            });
                    if already_present {
                        continue;
                    }

                    let reason = infer_reason_from_rule_name(&spec.name, &spec.program);
                    let agent_id = infer_agent_id_from_rule_name(&spec.name);
                    let filter_flags = if spec.enabled {
                        FWPM_FILTER_FLAG_NONE
                    } else {
                        FWPM_FILTER_FLAG_DISABLED
                    };
                    let mut attrs_map = HashMap::new();
                    let fids_res: PlatformResult<Vec<u64>> = (|| match (&spec.program, spec.action)
                    {
                        (None, RuleAction::Block) => add_global_cut_filters(
                            engine,
                            CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                            None,
                            reason,
                            &mut attrs_map,
                        ),
                        (Some(path), RuleAction::Block) => {
                            let blob = WfpAppIdBlob::from_path(path)?;
                            add_app_block_filters(
                                engine,
                                CLAUDEGUARD_WFP_PROVIDER_GUID,
                                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                                &blob,
                                &agent_id,
                                reason,
                                spec.direction == RuleDirection::Outbound,
                                spec.direction == RuleDirection::Inbound,
                                filter_flags,
                                &spec.name,
                                &mut attrs_map,
                            )
                        }
                        (Some(path), RuleAction::Allow) => {
                            let blob = WfpAppIdBlob::from_path(path)?;
                            let layers = if spec.direction == RuleDirection::Outbound {
                                &ALE_CONNECT_LAYERS
                            } else {
                                &ALE_RECV_LAYERS
                            };
                            let mut ids = Vec::with_capacity(2);
                            for (layer, _) in layers {
                                let mut conds = [cond_app_id(&blob, FWP_MATCH_EQUAL)];
                                let fid = add_filter_raw(
                                    engine,
                                    CLAUDEGUARD_WFP_PROVIDER_GUID,
                                    CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID,
                                    *layer,
                                    WFP_WEIGHT_LOOPBACK_PERMIT,
                                    FWP_ACTION_PERMIT,
                                    filter_flags,
                                    &spec.name,
                                    &mut conds,
                                )?;
                                ids.push(fid);
                            }
                            Ok(ids)
                        }
                        (None, RuleAction::Allow) => Err(PlatformError::InvalidInput(
                            "WFP engine refuses unscoped wildcard Allow rule".into(),
                        )),
                    })();

                    let fids = match fids_res {
                        Ok(ids) => ids,
                        Err(PlatformError::InvalidInput(msg)) => {
                            return Err(PlatformError::InvalidInput(msg));
                        }
                        Err(e) => {
                            last_err = Some(e);
                            continue;
                        }
                    };

                    let display_prog = spec
                        .program
                        .as_deref()
                        .map(|p| {
                            resolve_program_path_for_firewall(p)
                                .to_string_lossy()
                                .into_owned()
                        })
                        .unwrap_or_default();

                    newly_added.push(TrackedRuleEntry {
                        record: FirewallRuleRecord {
                            name: spec.name.clone(),
                            program: display_prog,
                            direction: spec.direction,
                            action: spec.action,
                            enabled: spec.enabled,
                            profiles: FW_PROFILE_ALL,
                        },
                        filter_ids: fids,
                        attributions: attrs_map.into_iter().collect(),
                    });
                    added_count += 1;
                }

                // Prune stale upgraded paths sharing managed Quarantine/Lockdown rule names (add-first, zero gap).
                if last_err.is_none() {
                    let managed_names: HashSet<String> = desired
                        .iter()
                        .map(|s| s.name.trim().to_ascii_lowercase())
                        .filter(|n| crate::firewall_com::is_prunable_managed_rule_name(n))
                        .collect();
                    if !managed_names.is_empty() {
                        for (idx, entry) in guard.rule_entries.iter().enumerate() {
                            let rec_name_l = entry.record.name.trim().to_ascii_lowercase();
                            if managed_names.contains(&rec_name_l)
                                && !desired.iter().any(|s| {
                                    crate::firewall_com::rule_matches_spec(&entry.record, s)
                                })
                            {
                                for &fid in &entry.filter_ids {
                                    let _ = delete_filter_id_idempotent(engine, fid)?;
                                }
                                pruned_indices.insert(idx);
                            }
                        }
                    }
                }

                txn.commit()?;
            }

            if !pruned_indices.is_empty() {
                let mut idx = 0usize;
                guard.rule_entries.retain(|_| {
                    let keep = !pruned_indices.contains(&idx);
                    idx += 1;
                    keep
                });
            }
            guard.rule_entries.extend(newly_added);
            let full_map = guard.rebuild_attribution_map();
            drop(guard);
            self.events.replace_filter_map(full_map);

            // Readback verify every desired non-script rule against live kernel BFE filters.
            let non_script_desired: Vec<FirewallRuleSpec> = desired
                .iter()
                .filter(|s| !s.program.as_deref().is_some_and(is_non_pe_script_shim))
                .cloned()
                .collect();
            let observed = self.enumerate_rules("").ok();
            let cov = crate::firewall_com::build_coverage(
                observed.as_deref(),
                &non_script_desired,
                added_count,
            );
            if !cov.complete() {
                if let Some(err) = last_err {
                    return Err(err);
                }
            }
            Ok(cov)
        }

        fn remove_rules_by_name(&self, names: &[String]) -> PlatformResult<RemoveReport> {
            let targets: HashSet<String> = names
                .iter()
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect();
            if targets.is_empty() {
                return Ok(RemoveReport {
                    removed: 0,
                    remaining: 0,
                    query_ok: true,
                });
            }

            let mut guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;
            let engine = self.session.raw();

            let mut removed = 0usize;
            {
                let txn = WfpTransactionGuard::begin(engine)?;
                for entry in &guard.rule_entries {
                    if targets.contains(&entry.record.name.trim().to_ascii_lowercase()) {
                        for &fid in &entry.filter_ids {
                            let _ = delete_filter_id_idempotent(engine, fid)?;
                        }
                        removed += 1;
                    }
                }
                txn.commit()?;
            }

            guard
                .rule_entries
                .retain(|e| !targets.contains(&e.record.name.trim().to_ascii_lowercase()));
            let full_map = guard.rebuild_attribution_map();
            drop(guard);
            self.events.replace_filter_map(full_map);

            match self.enumerate_rules("") {
                Ok(all) => {
                    let remaining = all
                        .iter()
                        .filter(|r| targets.contains(&r.name.trim().to_ascii_lowercase()))
                        .count();
                    Ok(RemoveReport {
                        removed,
                        remaining,
                        query_ok: true,
                    })
                }
                Err(_) => Ok(RemoveReport {
                    removed,
                    remaining: 0,
                    query_ok: false,
                }),
            }
        }

        fn remove_rules_with_prefix(&self, prefix: &str) -> PlatformResult<RemoveReport> {
            let prefix_lower = prefix.trim().to_ascii_lowercase();
            let mut guard = self
                .state
                .lock()
                .map_err(|_| PlatformError::Io("WFP state mutex poisoned".into()))?;
            let engine = self.session.raw();

            let mut removed = 0usize;
            {
                let txn = WfpTransactionGuard::begin(engine)?;
                for entry in &guard.rule_entries {
                    if entry
                        .record
                        .name
                        .trim()
                        .to_ascii_lowercase()
                        .starts_with(&prefix_lower)
                    {
                        for &fid in &entry.filter_ids {
                            let _ = delete_filter_id_idempotent(engine, fid)?;
                        }
                        removed += 1;
                    }
                }
                txn.commit()?;
            }

            guard.rule_entries.retain(|e| {
                !e.record
                    .name
                    .trim()
                    .to_ascii_lowercase()
                    .starts_with(&prefix_lower)
            });
            let full_map = guard.rebuild_attribution_map();
            drop(guard);
            self.events.replace_filter_map(full_map);

            match self.enumerate_rules(prefix) {
                Ok(rem) => Ok(RemoveReport {
                    removed,
                    remaining: rem.len(),
                    query_ok: true,
                }),
                Err(_) => Ok(RemoveReport {
                    removed,
                    remaining: 0,
                    query_ok: false,
                }),
            }
        }

        fn wfp_status(&self) -> WfpStatus {
            self.status()
        }

        fn clear_wfp_events(&self) {
            self.clear_blocked_events();
        }
    }

    unsafe fn pwstr_to_string(p: PWSTR) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while len < 4096 && *p.0.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(p.0, len))
            .trim()
            .to_string()
    }

    /// Detect the active Up TUN adapter verified to carry AI / Fake-IP public IPv4 routing
    /// (`104.18.0.1` + `160.79.104.10` / `1.1.1.1` / `8.8.8.8` / `198.18.0.1`) and return `(adapter_name, net_luid_u64)`.
    pub fn detect_active_tun_luid_native() -> Option<(String, u64)> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

        const FAMILY_UNSPEC: u32 = 0;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;

        let probe = crate::access_win::TunRouteProbe::query_os();

        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
            GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_SKIP_DNS_SERVER.0,
        );
        let mut size: u32 = 32 * 1024;
        for _ in 0..4 {
            let mut buffer: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
            let rc = unsafe {
                GetAdaptersAddresses(
                    FAMILY_UNSPEC,
                    flags,
                    None,
                    Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                    &mut size,
                )
            };
            if rc == 0 {
                let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
                while !current.is_null() {
                    let adapter = unsafe { &*current };
                    let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
                    let is_up = adapter.OperStatus == IfOperStatusUp
                        && unsafe {
                            crate::access_win::adapter_has_usable_unicast(
                                adapter.FirstUnicastAddress,
                            )
                        };
                    if is_up && probe.carries_ai_or_fakeip_route(if_index) {
                        let desc = unsafe { pwstr_to_string(adapter.Description) };
                        let friendly = unsafe { pwstr_to_string(adapter.FriendlyName) };
                        if let Some(label) =
                            crate::access_win::select_routed_tun(&[(desc, friendly, true, true)])
                        {
                            let luid = unsafe { adapter.Luid.Value };
                            if luid != 0 {
                                return Some((label, luid));
                            }
                        }
                    }
                    current = adapter.Next;
                }
                return None;
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                return None;
            }
        }
        None
    }

    /// Detect active (`IfOperStatusUp`) WSL2 / Hyper-V WSL virtual bridge `NET_LUID`s.
    pub fn detect_wsl_adapter_luids_native() -> Vec<u64> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

        const FAMILY_UNSPEC: u32 = 0;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;

        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
            GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_SKIP_DNS_SERVER.0,
        );
        let mut size: u32 = 32 * 1024;
        for _ in 0..4 {
            let mut buffer: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
            let rc = unsafe {
                GetAdaptersAddresses(
                    FAMILY_UNSPEC,
                    flags,
                    None,
                    Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                    &mut size,
                )
            };
            if rc == 0 {
                let mut luids = Vec::new();
                let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
                while !current.is_null() {
                    let adapter = unsafe { &*current };
                    if adapter.OperStatus == IfOperStatusUp {
                        let desc = unsafe { pwstr_to_string(adapter.Description) };
                        let friendly = unsafe { pwstr_to_string(adapter.FriendlyName) };
                        if is_wsl_virtual_adapter_name(&desc, &friendly) {
                            let luid = unsafe { adapter.Luid.Value };
                            if luid != 0 && !luids.contains(&luid) {
                                luids.push(luid);
                            }
                        }
                    }
                    current = adapter.Next;
                }
                return luids;
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                return Vec::new();
            }
        }
        Vec::new()
    }
}

#[cfg(windows)]
pub use win_impl::{
    v4_addr_mask, v6_addr_mask, WfpAppIdBlob, WfpFirewallEngine, WfpSessionHandle,
    WfpTransactionGuard,
};

// ==================== Non-Windows Stubs ====================

#[cfg(not(windows))]
#[derive(Debug, Default)]
pub struct WfpFirewallEngine;

#[cfg(not(windows))]
impl WfpFirewallEngine {
    pub fn open() -> PlatformResult<Self> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    pub fn sync_tunnel_only_filters(
        &self,
        _spec: &WfpRuntimePostureSpec,
    ) -> PlatformResult<WfpStatus> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    pub fn sync_leak_shield_wfp(
        &self,
        _app_paths: &[PathBuf],
        _block_quic: bool,
        _block_dns_doh: bool,
        _block_ipv6: bool,
    ) -> PlatformResult<LeakShieldStatus> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    pub fn sync_boot_time_guard(
        &self,
        _enable: bool,
        _app_exes: &[PathBuf],
    ) -> PlatformResult<usize> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    pub fn clear_persistent_filters(&self) -> PlatformResult<RemoveReport> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    pub fn status(&self) -> WfpStatus {
        WfpStatus {
            active_backend: BACKEND_UNSUPPORTED.to_string(),
            last_error: "Windows Filtering Platform is only supported on Windows".to_string(),
            ..WfpStatus::default()
        }
    }

    pub fn clear_blocked_events(&self) {}

    pub fn inspect_leak_shield(&self) -> LeakShieldStatus {
        LeakShieldStatus::default()
    }

    pub fn clear_all_dynamic_filters(&self) -> PlatformResult<usize> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    pub(crate) fn active_rule_specs(&self) -> Vec<FirewallRuleSpec> {
        Vec::new()
    }
}

#[cfg(not(windows))]
impl FirewallEngine for WfpFirewallEngine {
    fn engine_name(&self) -> &'static str {
        BACKEND_UNSUPPORTED
    }

    fn profile_status(&self) -> PlatformResult<FirewallProfileStatus> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    fn ensure_profiles_enabled(&self) -> PlatformResult<bool> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    fn enumerate_rules(&self, _prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    fn dedupe_rules(&self, _prefix: &str) -> PlatformResult<usize> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    fn ensure_rules(&self, _desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    fn remove_rules_by_name(&self, _names: &[String]) -> PlatformResult<RemoveReport> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    fn remove_rules_with_prefix(&self, _prefix: &str) -> PlatformResult<RemoveReport> {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }

    fn wfp_status(&self) -> WfpStatus {
        self.status()
    }
}

/// Free function to idempotently purge all persistent / boot-time ClaudeGuard WFP filters
/// (safe to call during emergency `--restore` even without an active dynamic session).
pub fn clear_persistent_filters() -> PlatformResult<RemoveReport> {
    #[cfg(windows)]
    {
        win_impl::clear_persistent_filters_native()
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::unsupported(
            "wfp",
            "Windows Filtering Platform is only supported on Windows",
        ))
    }
}

/// Detect the verified default-routed TUN adapter name and 64-bit `NET_LUID` for WFP.
pub fn detect_active_tun_luid() -> Option<(String, u64)> {
    #[cfg(windows)]
    {
        win_impl::detect_active_tun_luid_native()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

// ==================== HybridFirewallEngine ====================

struct HybridInner {
    pref: FirewallBackendPref,
    com: ComFirewallEngine,
    wfp: Option<WfpFirewallEngine>,
    active_backend: &'static str,
    last_error: String,
    fallback_events: WfpEventStore,
}

/// Dual-backend firewall engine orchestrating `WfpFirewallEngine` (dynamic kernel sublayer)
/// and `ComFirewallEngine` (`INetFwPolicy2`) according to [`FirewallBackendPref`].
///
/// - `AutoWfpFirst`: Uses WFP dynamic filters when elevated & BFE is available; otherwise falls
///   back seamlessly to `ComFirewallEngine` with clean status diagnostics and zero panics.
/// - `ComLegacy`: Always delegates directly to `ComFirewallEngine`.
/// - `WfpOnly`: Strictly requires WFP (never falls back to COM registry rules).
pub struct HybridFirewallEngine {
    inner: RwLock<HybridInner>,
}

impl std::fmt::Debug for HybridFirewallEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (pref, active) = self
            .inner
            .read()
            .map(|g| (g.pref, g.active_backend))
            .unwrap_or((FirewallBackendPref::AutoWfpFirst, BACKEND_COM_LEGACY));
        f.debug_struct("HybridFirewallEngine")
            .field("pref", &pref)
            .field("active_backend", &active)
            .finish()
    }
}

impl Default for HybridFirewallEngine {
    fn default() -> Self {
        Self::new(FirewallBackendPref::default())
    }
}

impl HybridFirewallEngine {
    /// Construct a `HybridFirewallEngine` for `pref`, opening a dynamic WFP session when
    /// permitted and falling back gracefully under `AutoWfpFirst` if non-elevated or unavailable.
    pub fn new(pref: FirewallBackendPref) -> Self {
        let elevated = crate::access_win::is_elevated().unwrap_or(false);
        Self::init_with_elevation(pref, elevated)
    }

    fn init_with_elevation(pref: FirewallBackendPref, elevated: bool) -> Self {
        let (wfp, active_backend, last_error) = Self::resolve_backend(pref, elevated);
        Self {
            inner: RwLock::new(HybridInner {
                pref,
                com: ComFirewallEngine::new(),
                wfp,
                active_backend,
                last_error,
                fallback_events: WfpEventStore::new(),
            }),
        }
    }

    fn resolve_backend(
        pref: FirewallBackendPref,
        elevated: bool,
    ) -> (Option<WfpFirewallEngine>, &'static str, String) {
        match pref {
            FirewallBackendPref::ComLegacy => {
                let backend = if cfg!(windows) {
                    BACKEND_COM_LEGACY
                } else {
                    BACKEND_UNSUPPORTED
                };
                (None, backend, String::new())
            }
            FirewallBackendPref::AutoWfpFirst => {
                if !cfg!(windows) {
                    return (
                        None,
                        BACKEND_UNSUPPORTED,
                        "WFP is only supported on Windows".to_string(),
                    );
                }
                if !elevated {
                    return (
                        None,
                        BACKEND_COM_LEGACY,
                        "当前进程未提权（非管理员），WFP 动态子层已平滑降级为 COM 防火墙引擎"
                            .to_string(),
                    );
                }
                match WfpFirewallEngine::open() {
                    Ok(engine) => (Some(engine), BACKEND_WFP_DYNAMIC, String::new()),
                    Err(err) => (
                        None,
                        BACKEND_COM_LEGACY,
                        format!("WFP 初始化失败，已自动降级至 COM 防火墙引擎：{err}"),
                    ),
                }
            }
            FirewallBackendPref::WfpOnly => {
                if !cfg!(windows) {
                    return (
                        None,
                        BACKEND_WFP_UNAVAILABLE,
                        "WFP is only supported on Windows".to_string(),
                    );
                }
                if !elevated {
                    return (
                        None,
                        BACKEND_WFP_UNAVAILABLE,
                        "已启用仅 WFP 模式，但当前进程未提权（需要管理员或 LocalSystem 服务权限）"
                            .to_string(),
                    );
                }
                match WfpFirewallEngine::open() {
                    Ok(engine) => (Some(engine), BACKEND_WFP_DYNAMIC, String::new()),
                    Err(err) => (
                        None,
                        BACKEND_WFP_UNAVAILABLE,
                        format!("仅 WFP 模式初始化失败：{err}"),
                    ),
                }
            }
        }
    }

    /// Return the currently configured [`FirewallBackendPref`].
    pub fn preference(&self) -> FirewallBackendPref {
        self.inner
            .read()
            .map(|g| g.pref)
            .unwrap_or(FirewallBackendPref::AutoWfpFirst)
    }

    /// Update the backend preference at runtime, cleanly opening or dropping the dynamic WFP
    /// session as needed, and return the updated [`WfpStatus`].
    pub fn set_preference(&self, pref: FirewallBackendPref) -> WfpStatus {
        let elevated = crate::access_win::is_elevated().unwrap_or(false);
        self.set_preference_with_elevation(pref, elevated)
    }

    fn set_preference_with_elevation(
        &self,
        pref: FirewallBackendPref,
        elevated: bool,
    ) -> WfpStatus {
        if let Ok(mut guard) = self.inner.write() {
            if guard.pref == pref && (pref == FirewallBackendPref::ComLegacy || guard.wfp.is_some())
            {
                drop(guard);
                return self.wfp_status();
            }

            let was_wfp = guard.wfp.is_some();
            let migrated_from_wfp: Vec<FirewallRuleSpec> = guard
                .wfp
                .as_ref()
                .map(|w| w.active_rule_specs())
                .unwrap_or_default();
            let migrated_from_com: Vec<FirewallRuleSpec> = if !was_wfp && elevated {
                guard
                    .com
                    .enumerate_rules(crate::firewall_com::CG_RULE_PREFIX)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| {
                        !r.name.to_ascii_lowercase().starts_with(
                            &crate::leak_shield_win::SHIELD_RULE_PREFIX.to_ascii_lowercase(),
                        )
                    })
                    .map(|r| FirewallRuleSpec {
                        name: r.name,
                        program: (!r.program.trim().is_empty()).then(|| PathBuf::from(r.program)),
                        direction: r.direction,
                        action: r.action,
                        enabled: r.enabled,
                        description: None,
                        profiles: r.profiles,
                    })
                    .collect()
            } else {
                Vec::new()
            };

            // When switching WFP -> COM, apply active Quarantine/Lockdown rules to COM BEFORE
            // closing the dynamic WFP session so there is zero fail-open window.
            if was_wfp
                && pref == FirewallBackendPref::ComLegacy
                && elevated
                && !migrated_from_wfp.is_empty()
            {
                let _ = guard.com.ensure_rules(&migrated_from_wfp);
            }

            guard.wfp = None;
            let (new_wfp, active_backend, last_error) = Self::resolve_backend(pref, elevated);

            if let Some(ref wfp_eng) = new_wfp {
                // When switching COM -> WFP, migrate active COM Quarantine/Lockdown specs into WFP
                // first and then purge persistent COM rules so MpsSvc never retains orphaned blocks.
                if !migrated_from_com.is_empty() {
                    let _ = wfp_eng.ensure_rules(&migrated_from_com);
                }
                if !was_wfp && elevated {
                    let _ = guard
                        .com
                        .remove_rules_with_prefix(crate::firewall_com::CG_RULE_PREFIX);
                    let _ = crate::leak_shield_win::clear_leak_shield();
                }
            } else if was_wfp
                && pref != FirewallBackendPref::WfpOnly
                && elevated
                && !migrated_from_wfp.is_empty()
            {
                // Fallback case (`AutoWfpFirst` failed to reopen WFP): preserve quarantine on COM.
                let _ = guard.com.ensure_rules(&migrated_from_wfp);
            }

            guard.pref = pref;
            guard.wfp = new_wfp;
            guard.active_backend = active_backend;
            guard.last_error = last_error;
        }
        self.wfp_status()
    }

    /// Return a live [`WfpStatus`] snapshot reflecting the active backend, sublayer status,
    /// blocked-packet ring buffer, and any graceful fallback diagnostics.
    pub fn wfp_status(&self) -> WfpStatus {
        let Ok(guard) = self.inner.read() else {
            return WfpStatus {
                active_backend: BACKEND_COM_LEGACY.to_string(),
                last_error: "HybridFirewallEngine lock poisoned".to_string(),
                ..WfpStatus::default()
            };
        };

        if let Some(ref wfp) = guard.wfp {
            let mut st = wfp.status();
            if st.last_error.is_empty() && !guard.last_error.is_empty() {
                st.last_error = guard.last_error.clone();
            }
            st
        } else {
            let (total_blocked_packets, recent_blocked) = guard.fallback_events.snapshot_events();
            WfpStatus {
                active_backend: guard.active_backend.to_string(),
                sublayer_registered: false,
                dynamic_session_open: false,
                boot_time_filters_armed: false,
                active_filter_count: 0,
                net_event_subscribed: false,
                total_blocked_packets,
                recent_blocked,
                last_error: guard.last_error.clone(),
            }
        }
    }

    /// Clear the in-memory WFP blocked-packet event ring buffer.
    pub fn clear_wfp_events(&self) {
        if let Ok(guard) = self.inner.read() {
            if let Some(ref wfp) = guard.wfp {
                wfp.clear_blocked_events();
            } else {
                guard.fallback_events.clear_events();
            }
        }
    }

    /// Synchronize the 4-Vector Leak Shield via WFP when active, or via COM under
    /// `ComLegacy` / `AutoWfpFirst` fallback.
    pub fn sync_leak_shield_wfp(
        &self,
        app_paths: &[PathBuf],
        block_quic: bool,
        block_dns_doh: bool,
        block_ipv6: bool,
    ) -> PlatformResult<LeakShieldStatus> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;

        if let Some(ref wfp) = guard.wfp {
            wfp.sync_leak_shield_wfp(app_paths, block_quic, block_dns_doh, block_ipv6)
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            crate::leak_shield_win::sync_leak_shield(
                app_paths,
                block_quic,
                block_dns_doh,
                block_ipv6,
            )
        }
    }

    /// Synchronize the Per-App Split-Permit Sandwich and dynamic WFP posture.
    ///
    /// Under `AutoWfpFirst` fallback or `ComLegacy`, returns the current [`WfpStatus`] cleanly
    /// without failing when WFP is inactive; under `WfpOnly`, returns an explicit error.
    pub fn sync_tunnel_only_split_permit(
        &self,
        spec: &WfpRuntimePostureSpec,
    ) -> PlatformResult<WfpStatus> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;

        if let Some(ref wfp) = guard.wfp {
            wfp.sync_tunnel_only_filters(spec)
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            drop(guard);
            Ok(self.wfp_status())
        }
    }

    /// Synchronize the opt-in persistent `FWPM_FILTER_FLAG_BOOTTIME` guard (`wfp_boot_guard`).
    pub fn sync_boot_guard(&self, enable: bool, app_exes: &[PathBuf]) -> PlatformResult<usize> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;

        if let Some(ref wfp) = guard.wfp {
            wfp.sync_boot_time_guard(enable, app_exes)
        } else if !enable {
            // Disabling boot guard when inactive is a clean no-op if non-elevated.
            match clear_persistent_filters() {
                Ok(_) => Ok(0),
                Err(PlatformError::AccessDenied(_))
                    if guard.pref != FirewallBackendPref::WfpOnly =>
                {
                    Ok(0)
                }
                Err(err) => Err(err),
            }
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            Err(PlatformError::AccessDenied(
                "启用 WFP 开机早启动保护（Boot-Time Guard）需要 WFP 内核会话及管理员权限"
                    .to_string(),
            ))
        }
    }

    /// Idempotently clear any persistent / boot-time WFP filters.
    pub fn clear_persistent_boot_guard(&self) -> PlatformResult<RemoveReport> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.clear_persistent_filters()
        } else {
            clear_persistent_filters()
        }
    }

    /// Read-only inspection of the active 4-Vector Leak Shield:
    /// queries tracked dynamic WFP shield/posture filters when WFP is active, or falls back to
    /// `leak_shield_win::inspect_leak_shield()` under `ComLegacy` / non-elevated `AutoWfpFirst`.
    pub fn inspect_leak_shield(&self) -> LeakShieldStatus {
        let Ok(guard) = self.inner.read() else {
            return LeakShieldStatus {
                summary: "HybridFirewallEngine lock poisoned".into(),
                ..LeakShieldStatus::default()
            };
        };
        if let Some(ref wfp) = guard.wfp {
            wfp.inspect_leak_shield()
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            LeakShieldStatus {
                summary: "仅 WFP 模式下内核会话不可用，防泄露护盾未生效".into(),
                ..LeakShieldStatus::default()
            }
        } else {
            crate::leak_shield_win::inspect_leak_shield()
        }
    }

    /// Purges ALL ClaudeGuard firewall state across both WFP and COM backends:
    /// 1. Dynamic WFP `rule_entries`, `shield_filter_ids`, and `posture_filter_ids`
    /// 2. Persistent / Boot-Time WFP sublayer (`0xFF10`) filters
    /// 3. Windows Firewall COM `ClaudeGuard*` and `ClaudeGuard-Shield-*` rules
    pub fn clear_all_claudeguard_state(&self) -> Result<usize, String> {
        let guard = self
            .inner
            .read()
            .map_err(|_| "HybridFirewallEngine lock poisoned".to_string())?;

        let mut total_removed = 0usize;

        if let Some(ref wfp) = guard.wfp {
            let dyn_removed = wfp.clear_all_dynamic_filters().map_err(|e| e.to_string())?;
            total_removed = total_removed.saturating_add(dyn_removed);
            match wfp.clear_persistent_filters() {
                Ok(rep) => total_removed = total_removed.saturating_add(rep.removed),
                Err(PlatformError::AccessDenied(_))
                    if guard.pref != FirewallBackendPref::WfpOnly => {}
                Err(err) => return Err(err.to_string()),
            }
        } else {
            match clear_persistent_filters() {
                Ok(rep) => total_removed = total_removed.saturating_add(rep.removed),
                Err(PlatformError::Unsupported { .. }) => {}
                Err(PlatformError::AccessDenied(_))
                    if guard.pref != FirewallBackendPref::WfpOnly => {}
                Err(err) => return Err(err.to_string()),
            }
        }

        // Also sweep any residual COM firewall / shield rules (e.g. after backend switch or upgrade).
        match guard.com.remove_rules_with_prefix("ClaudeGuard") {
            Ok(rep) => total_removed = total_removed.saturating_add(rep.removed),
            Err(PlatformError::Unsupported { .. }) => {}
            Err(PlatformError::AccessDenied(_))
                if guard.wfp.is_none() && guard.pref != FirewallBackendPref::ComLegacy => {}
            Err(err) if guard.wfp.is_some() => {
                // WFP primary clear already succeeded; do not fail if MpsSvc COM is stopped.
                let _ = err;
            }
            Err(err) => return Err(err.to_string()),
        }
        if let Ok(shield_removed) = crate::leak_shield_win::clear_leak_shield() {
            total_removed = total_removed.saturating_add(shield_removed);
        }

        Ok(total_removed)
    }

    fn wfp_only_err(last_error: &str) -> PlatformError {
        let detail = if last_error.trim().is_empty() {
            "WFP-only backend is unavailable".to_string()
        } else {
            last_error.to_string()
        };
        if cfg!(windows) {
            PlatformError::AccessDenied(detail)
        } else {
            PlatformError::unsupported("wfp", detail)
        }
    }
}

impl FirewallEngine for HybridFirewallEngine {
    fn engine_name(&self) -> &'static str {
        self.inner
            .read()
            .map(|g| g.active_backend)
            .unwrap_or(BACKEND_COM_LEGACY)
    }

    fn profile_status(&self) -> PlatformResult<FirewallProfileStatus> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.profile_status()
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            guard.com.profile_status()
        }
    }

    fn ensure_profiles_enabled(&self) -> PlatformResult<bool> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.ensure_profiles_enabled()
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            guard.com.ensure_profiles_enabled()
        }
    }

    fn enumerate_rules(&self, prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.enumerate_rules(prefix)
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            guard.com.enumerate_rules(prefix)
        }
    }

    fn dedupe_rules(&self, prefix: &str) -> PlatformResult<usize> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.dedupe_rules(prefix)
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            guard.com.dedupe_rules(prefix)
        }
    }

    fn ensure_rules(&self, desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.ensure_rules(desired)
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            guard.com.ensure_rules(desired)
        }
    }

    fn remove_rules_by_name(&self, names: &[String]) -> PlatformResult<RemoveReport> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.remove_rules_by_name(names)
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            guard.com.remove_rules_by_name(names)
        }
    }

    fn remove_rules_with_prefix(&self, prefix: &str) -> PlatformResult<RemoveReport> {
        let guard = self
            .inner
            .read()
            .map_err(|_| PlatformError::Io("HybridFirewallEngine lock poisoned".into()))?;
        if let Some(ref wfp) = guard.wfp {
            wfp.remove_rules_with_prefix(prefix)
        } else if guard.pref == FirewallBackendPref::WfpOnly {
            Err(Self::wfp_only_err(&guard.last_error))
        } else {
            guard.com.remove_rules_with_prefix(prefix)
        }
    }

    fn wfp_status(&self) -> WfpStatus {
        self.wfp_status()
    }

    fn clear_wfp_events(&self) {
        self.clear_wfp_events();
    }
}

// ==================== Unit Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wfp_guid_constants_are_stable_and_distinct() {
        let all = [
            CLAUDEGUARD_WFP_PROVIDER_GUID_U128,
            CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID_U128,
            CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID_U128,
            CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID_U128,
        ];
        assert_eq!(all[0], 0x9c4e_7a21_5b38_4f19_a8d2_61e0_c3f9_4b01);
        assert_eq!(all[1], 0x9c4e_7a22_5b38_4f19_a8d2_61e0_c3f9_4b02);
        assert_eq!(all[2], 0x9c4e_7a23_5b38_4f19_a8d2_61e0_c3f9_4b03);
        assert_eq!(all[3], 0x9c4e_7a24_5b38_4f19_a8d2_61e0_c3f9_4b04);

        let unique: HashSet<u128> = all.into_iter().collect();
        assert_eq!(unique.len(), 4);

        #[cfg(windows)]
        {
            assert_eq!(
                CLAUDEGUARD_WFP_PROVIDER_GUID.to_u128(),
                CLAUDEGUARD_WFP_PROVIDER_GUID_U128
            );
            assert_eq!(
                CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID.to_u128(),
                CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID_U128
            );
            assert_ne!(
                CLAUDEGUARD_WFP_PROVIDER_GUID,
                CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID
            );
            assert_eq!(
                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID.to_u128(),
                CLAUDEGUARD_WFP_SUBLAYER_DYNAMIC_GUID_U128
            );
            assert_eq!(
                CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID.to_u128(),
                CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID_U128
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn wfp_provider_guid_separation_and_error_code_mapping() {
        use windows::Win32::Foundation::{
            ERROR_ACCESS_DENIED, E_ACCESSDENIED, FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND,
            FWP_E_IN_USE, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND,
        };

        // Dynamic and persistent provider GUIDs must never collide (prevents FWP_E_LIFETIME_MISMATCH).
        assert_ne!(
            CLAUDEGUARD_WFP_PROVIDER_GUID,
            CLAUDEGUARD_WFP_PROVIDER_PERSISTENT_GUID
        );

        // Official Win32 Foundation FWP_E_* codes must match BFE kernel values.
        assert_eq!(FWP_E_FILTER_NOT_FOUND.0 as u32, 0x8032_0003);
        assert_eq!(FWP_E_PROVIDER_NOT_FOUND.0 as u32, 0x8032_0005);
        assert_eq!(FWP_E_SUBLAYER_NOT_FOUND.0 as u32, 0x8032_0007);
        assert_eq!(FWP_E_ALREADY_EXISTS.0 as u32, 0x8032_0009);
        assert_eq!(FWP_E_IN_USE.0 as u32, 0x8032_000A);

        // ERROR_ACCESS_DENIED (5) and E_ACCESSDENIED (0x80070005) map to AccessDenied.
        assert!(matches!(
            win_impl::wfp_err(ERROR_ACCESS_DENIED.0, "open"),
            PlatformError::AccessDenied(_)
        ));
        assert!(matches!(
            win_impl::wfp_err(E_ACCESSDENIED.0 as u32, "open"),
            PlatformError::AccessDenied(_)
        ));
        // 0x8032_000E is FWP_E_TXN_IN_PROGRESS and must NOT be misclassified as AccessDenied.
        assert!(matches!(
            win_impl::wfp_err(0x8032_000E, "txn"),
            PlatformError::Com { .. }
        ));
    }

    #[test]
    fn wfp_weight_hierarchy_is_strictly_ordered() {
        // Persistent / Boot-Time sublayer must strictly outrank Dynamic sublayer.
        const {
            assert!(WFP_SUBLAYER_WEIGHT_PERSISTENT == 0xFF10);
            assert!(WFP_SUBLAYER_WEIGHT_DYNAMIC == 0xFF00);
            assert!(WFP_SUBLAYER_WEIGHT_PERSISTENT > WFP_SUBLAYER_WEIGHT_DYNAMIC);
        }

        // Intra-sublayer FWP_UINT8 weights must be in 1..=15 and strictly decreasing.
        let ordered = [
            WFP_WEIGHT_GLOBAL_CUT,
            WFP_WEIGHT_QUARANTINE_OR_LOCKDOWN,
            WFP_WEIGHT_LEAK_SHIELD,
            WFP_WEIGHT_LOOPBACK_PERMIT,
            WFP_WEIGHT_ACTIVE_TUN_PERMIT,
            WFP_WEIGHT_LAN_EXEMPT_PERMIT,
            WFP_WEIGHT_DIRECT_NIC_BLOCK,
        ];
        assert!(ordered.iter().all(|&w| (1..=15).contains(&w)));
        for pair in ordered.windows(2) {
            assert!(
                pair[0] > pair[1],
                "expected weight {} > {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn wfp_ipv4_host_byte_order_and_mask_conversion() {
        // 127.0.0.1 in WFP host byte order MUST be 0x7F00_0001 (NOT 0x0100_007F).
        assert_eq!(
            ipv4_to_wfp_host_u32(Ipv4Addr::new(127, 0, 0, 1)),
            0x7F00_0001
        );
        assert_eq!(
            ipv4_from_wfp_host_u32(0x7F00_0001),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert_eq!(
            ipv4_from_wfp_host_u32(ipv4_to_wfp_host_u32(Ipv4Addr::new(223, 5, 5, 5))),
            Ipv4Addr::new(223, 5, 5, 5)
        );

        // 127.12.34.56/8 -> masked addr 0x7F00_0000, mask 0xFF00_0000.
        assert_eq!(
            ipv4_and_mask_host_u32(Ipv4Addr::new(127, 12, 34, 56), 8),
            (0x7F00_0000, 0xFF00_0000)
        );
        // 172.31.255.1/12 -> masked addr 172.16.0.0 (0xAC10_0000), mask 0xFFF0_0000.
        assert_eq!(
            ipv4_and_mask_host_u32(Ipv4Addr::new(172, 31, 255, 1), 12),
            (0xAC10_0000, 0xFFF0_0000)
        );
        // /32 exact host match & /0 wildcard match edge cases.
        assert_eq!(
            ipv4_and_mask_host_u32(Ipv4Addr::new(1, 1, 1, 1), 32),
            (0x0101_0101, 0xFFFF_FFFF)
        );
        assert_eq!(
            ipv4_and_mask_host_u32(Ipv4Addr::new(1, 1, 1, 1), 0),
            (0x0000_0000, 0x0000_0000)
        );

        #[cfg(windows)]
        {
            let m = v4_addr_mask(Ipv4Addr::new(192, 168, 1, 55), 16);
            assert_eq!(m.addr, 0xC0A8_0000);
            assert_eq!(m.mask, 0xFFFF_0000);
        }
    }

    #[test]
    fn wfp_ipv6_prefix_masking_zeroes_host_bits() {
        let ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0x1234, 0, 0, 0, 0x1111);
        let (octets, plen) = ipv6_and_prefix(ip, 3);
        assert_eq!(plen, 3);
        assert_eq!(
            Ipv6Addr::from(octets),
            Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)
        );

        let (octets96, plen96) = ipv6_and_prefix(
            Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0102, 0x0304),
            96,
        );
        assert_eq!(plen96, 96);
        assert_eq!(
            Ipv6Addr::from(octets96),
            Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn wfp_event_ring_enforces_256_cap_eviction_and_monotonic_seq() {
        let store = WfpEventStore::new();
        store.insert_filter_meta(
            42,
            WfpFilterAttribution {
                agent_id: "claude".into(),
                filter_reason: "direct_nic_bypass".into(),
                layer: "ale_auth_connect_v4".into(),
            },
        );

        // Unknown OS filter IDs must be discarded in O(1) without touching counters or ring.
        assert!(!store.record_blocked_drop(
            9999,
            1_700_000_000_000,
            None,
            r"\device\harddiskvolume3\windows\system32\svchost.exe".into(),
            "8.8.8.8".into(),
            53,
            "udp",
            "ale_auth_connect_v4",
        ));
        assert_eq!(store.snapshot_events().0, 0);
        assert!(store.snapshot_events().1.is_empty());

        // Push 300 owned events -> cap stays at 256, oldest 44 evicted, seq is 45..=300.
        for i in 1..=300u64 {
            assert!(store.record_blocked_drop(
                42,
                1_700_000_000_000 + i,
                Some(1234),
                r"\device\harddiskvolume3\apps\claude.exe".into(),
                format!("203.0.113.{}", i % 250),
                443,
                "tcp",
                "ale_auth_connect_v4",
            ));
        }

        let (total, events) = store.snapshot_events();
        assert_eq!(total, 300);
        assert_eq!(events.len(), WFP_EVENT_RING_CAPACITY);
        assert_eq!(events.first().unwrap().seq, 45);
        assert_eq!(events.last().unwrap().seq, 300);
        assert_eq!(events.first().unwrap().agent_id, "claude");
        assert_eq!(events.first().unwrap().filter_reason, "direct_nic_bypass");
        assert_eq!(events.first().unwrap().layer, "ale_auth_connect_v4");

        // Clearing resets buffered events and displayed drop count, while seq stays monotonic.
        store.clear_events();
        let (cleared_total, cleared_events) = store.snapshot_events();
        assert_eq!(cleared_total, 0);
        assert!(cleared_events.is_empty());

        assert!(store.record_blocked_drop(
            42,
            1_700_000_009_999,
            None,
            r"\device\harddiskvolume3\apps\claude.exe".into(),
            "1.1.1.1".into(),
            443,
            "udp",
            "ale_auth_connect_v4",
        ));
        let (after_total, after_events) = store.snapshot_events();
        assert_eq!(after_total, 1);
        assert_eq!(after_events.len(), 1);
        assert_eq!(after_events[0].seq, 301);
    }

    #[test]
    fn hybrid_engine_com_legacy_and_non_elevated_auto_fallback_project_clean_status() {
        // ComLegacy never opens WFP and leaves last_error empty.
        let com_eng = HybridFirewallEngine::new(FirewallBackendPref::ComLegacy);
        assert_eq!(com_eng.preference(), FirewallBackendPref::ComLegacy);
        let st_com = com_eng.wfp_status();
        let expected_com = if cfg!(windows) {
            BACKEND_COM_LEGACY
        } else {
            BACKEND_UNSUPPORTED
        };
        assert_eq!(com_eng.engine_name(), expected_com);
        assert_eq!(st_com.active_backend, expected_com);
        assert!(!st_com.dynamic_session_open);
        assert!(!st_com.sublayer_registered);
        assert!(!st_com.boot_time_filters_armed);
        assert!(st_com.last_error.is_empty());

        // Simulated non-elevated AutoWfpFirst gracefully falls back to COM without crashing.
        let auto_fallback =
            HybridFirewallEngine::init_with_elevation(FirewallBackendPref::AutoWfpFirst, false);
        assert_eq!(auto_fallback.engine_name(), expected_com);
        let st_auto = auto_fallback.wfp_status();
        assert_eq!(st_auto.active_backend, expected_com);
        assert!(!st_auto.dynamic_session_open);
        assert!(!st_auto.sublayer_registered);
        assert!(!st_auto.last_error.is_empty());

        // Switching non-elevated AutoWfpFirst -> WfpOnly strictly refuses COM fallback.
        let st_only =
            auto_fallback.set_preference_with_elevation(FirewallBackendPref::WfpOnly, false);
        assert_eq!(auto_fallback.engine_name(), BACKEND_WFP_UNAVAILABLE);
        assert_eq!(st_only.active_backend, BACKEND_WFP_UNAVAILABLE);
        assert!(!st_only.dynamic_session_open);
        assert!(!st_only.last_error.is_empty());
        assert!(auto_fallback.enumerate_rules("ClaudeGuard").is_err());
        assert!(auto_fallback
            .sync_tunnel_only_split_permit(&WfpRuntimePostureSpec::default())
            .is_err());

        // Switching back to ComLegacy clears the WFP error cleanly.
        let st_back =
            auto_fallback.set_preference_with_elevation(FirewallBackendPref::ComLegacy, false);
        assert_eq!(st_back.active_backend, expected_com);
        assert!(st_back.last_error.is_empty());
    }

    #[test]
    fn hybrid_engine_auto_constructor_and_status_projection_never_panic() {
        let engine = HybridFirewallEngine::new(FirewallBackendPref::AutoWfpFirst);
        let status = engine.wfp_status();
        assert!(!status.active_backend.is_empty());
        assert_eq!(engine.wfp_status(), FirewallEngine::wfp_status(&engine));
        // Disabling boot guard with empty app list is safe even when non-elevated.
        let res = engine.sync_boot_guard(false, &[]);
        assert!(res.is_ok() || cfg!(not(windows)));
        engine.clear_wfp_events();
        assert!(engine.wfp_status().recent_blocked.is_empty());
    }

    #[test]
    fn wfp_rule_name_attribution_inference_matches_protocol_reasons() {
        assert_eq!(
            infer_reason_from_rule_name("ClaudeGuard Cut All", &None),
            "panic_lockdown"
        );
        assert_eq!(
            infer_reason_from_rule_name(
                "ClaudeGuard Block Out (claude)",
                &Some(PathBuf::from(r"C:\Apps\Claude.exe"))
            ),
            "app_quarantine"
        );
        assert_eq!(
            infer_reason_from_rule_name(
                "ClaudeGuard-Shield-QUIC-0",
                &Some(PathBuf::from(r"C:\Apps\Claude.exe"))
            ),
            "quic_shield"
        );
        assert_eq!(
            infer_agent_id_from_rule_name("ClaudeGuard Block Out (Antigravity)"),
            "antigravity"
        );
        assert_eq!(infer_agent_id_from_rule_name("ClaudeGuard Cut All"), "");
    }

    #[cfg(windows)]
    #[test]
    fn wfp_net_event_callback_attributes_v4_v6_and_discards_unknown() {
        use std::ffi::c_void;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        let store = Arc::new(WfpEventStore::new());
        store.insert_filter_meta(
            701,
            WfpFilterAttribution {
                agent_id: "claude".into(),
                filter_reason: "doh_shield".into(),
                layer: "ale_auth_connect_v4".into(),
            },
        );
        store.insert_filter_meta(
            702,
            WfpFilterAttribution {
                agent_id: "antigravity".into(),
                filter_reason: "ipv6_shield".into(),
                layer: "ale_auth_connect_v6".into(),
            },
        );

        let ctx_ptr = Arc::as_ptr(&store) as *mut c_void;

        // Null pointer inputs must return safely without panicking.
        unsafe {
            win_impl::wfp_net_event_callback_v4(core::ptr::null_mut(), core::ptr::null());
            win_impl::wfp_net_event_callback_v4(ctx_ptr, core::ptr::null());
        }

        // Prepare UTF-16LE appId bytes (`\device\harddiskvolume3\claude.exe\0`).
        let mut app_bytes: Vec<u8> = r"\device\harddiskvolume3\claude.exe"
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect();

        // (1) Owned IPv4 drop: 223.5.5.5:53 UDP -> recorded with host-order IP decoding.
        let mut drop_v4 = FWPM_NET_EVENT_CLASSIFY_DROP2 {
            filterId: 701,
            ..Default::default()
        };
        let mut ev_v4 = FWPM_NET_EVENT5 {
            r#type: FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            ..Default::default()
        };
        ev_v4.Anonymous.classifyDrop = &mut drop_v4;
        ev_v4.header.flags = FWPM_NET_EVENT_FLAG_IP_VERSION_SET
            | FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET
            | FWPM_NET_EVENT_FLAG_APP_ID_SET;
        ev_v4.header.ipVersion = FWP_IP_VERSION_V4;
        ev_v4.header.ipProtocol = 17;
        ev_v4.header.remotePort = 53;
        ev_v4.header.Anonymous2.remoteAddrV4 = ipv4_to_wfp_host_u32(Ipv4Addr::new(223, 5, 5, 5));
        ev_v4.header.appId = FWP_BYTE_BLOB {
            size: app_bytes.len() as u32,
            data: app_bytes.as_mut_ptr(),
        };

        // (2) Owned IPv6 drop: 2606:4700:4700::1111:443 TCP -> recorded cleanly.
        let mut drop_v6 = FWPM_NET_EVENT_CLASSIFY_DROP2 {
            filterId: 702,
            ..Default::default()
        };
        let mut ev_v6 = FWPM_NET_EVENT5 {
            r#type: FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            ..Default::default()
        };
        ev_v6.Anonymous.classifyDrop = &mut drop_v6;
        ev_v6.header.flags = FWPM_NET_EVENT_FLAG_IP_VERSION_SET
            | FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET;
        ev_v6.header.ipVersion = FWP_IP_VERSION_V6;
        ev_v6.header.ipProtocol = 6;
        ev_v6.header.remotePort = 443;
        ev_v6.header.Anonymous2.remoteAddrV6 = FWP_BYTE_ARRAY16 {
            byteArray16: Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets(),
        };

        // (3) Unrelated system filterId 8888 -> discarded in O(1).
        let mut drop_other = FWPM_NET_EVENT_CLASSIFY_DROP2 {
            filterId: 8888,
            ..Default::default()
        };
        let mut ev_other = FWPM_NET_EVENT5 {
            r#type: FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            ..Default::default()
        };
        ev_other.Anonymous.classifyDrop = &mut drop_other;
        ev_other.header.ipVersion = FWP_IP_VERSION_V4;
        ev_other.header.Anonymous2.remoteAddrV4 = ipv4_to_wfp_host_u32(Ipv4Addr::new(8, 8, 8, 8));

        // (4) Owned drop with `flags = 0` and bogus dangling `appId.data` -> must NOT dereference `appId`!
        let mut drop_unflagged = FWPM_NET_EVENT_CLASSIFY_DROP2 {
            filterId: 701,
            ..Default::default()
        };
        let mut ev_unflagged = FWPM_NET_EVENT5 {
            r#type: FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            ..Default::default()
        };
        ev_unflagged.Anonymous.classifyDrop = &mut drop_unflagged;
        ev_unflagged.header.flags = 0;
        ev_unflagged.header.appId = FWP_BYTE_BLOB {
            size: 64,
            data: core::ptr::dangling_mut::<u8>(),
        };

        unsafe {
            win_impl::wfp_net_event_callback_v4(ctx_ptr, &ev_v4);
            win_impl::wfp_net_event_callback_v4(ctx_ptr, &ev_v6);
            win_impl::wfp_net_event_callback_v4(ctx_ptr, &ev_other);
            win_impl::wfp_net_event_callback_v4(ctx_ptr, &ev_unflagged);
        }

        assert!(is_wsl_virtual_adapter_name(
            "Hyper-V Virtual Ethernet Adapter",
            "vEthernet (WSL (Hyper-V firewall))"
        ));
        assert!(!is_wsl_virtual_adapter_name(
            "Realtek PCIe GbE Family Controller",
            "Ethernet"
        ));

        let (total, events) = store.snapshot_events();
        assert_eq!(total, 3);
        assert_eq!(events.len(), 3);
        assert!(events[2].app_path.is_empty());
        assert_eq!(events[2].remote_port, 0);

        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].agent_id, "claude");
        assert_eq!(events[0].filter_reason, "doh_shield");
        assert_eq!(events[0].protocol, "udp");
        assert_eq!(events[0].remote_ip, "223.5.5.5");
        assert_eq!(events[0].remote_port, 53);
        assert_eq!(events[0].layer, "ale_auth_connect_v4");
        assert_eq!(events[0].app_path, r"\device\harddiskvolume3\claude.exe");

        assert_eq!(events[1].seq, 2);
        assert_eq!(events[1].agent_id, "antigravity");
        assert_eq!(events[1].filter_reason, "ipv6_shield");
        assert_eq!(events[1].protocol, "tcp");
        assert_eq!(events[1].remote_ip, "2606:4700:4700::1111");
        assert_eq!(events[1].remote_port, 443);
        assert_eq!(events[1].layer, "ale_auth_connect_v6");
    }

    #[cfg(windows)]
    #[test]
    fn synthesized_nt_app_id_and_script_shim_filter_work() {
        use std::path::Path;
        assert!(is_non_pe_script_shim(Path::new(
            r"C:\Users\mjq\AppData\Roaming\npm\claude.cmd"
        )));
        assert!(is_non_pe_script_shim(Path::new(
            r"C:\Users\mjq\AppData\Roaming\npm\codex.ps1"
        )));
        assert!(!is_non_pe_script_shim(Path::new(
            r"C:\Windows\System32\notepad.exe"
        )));
        assert!(WfpRuntimePostureSpec::default()
            .active_proxy_endpoint
            .is_none());

        let notepad = Path::new(r"C:\Windows\System32\notepad.exe");
        let synth = win_impl::synthesize_nt_device_app_id_bytes(notepad)
            .expect("QueryDosDeviceW NT path synthesis");
        assert!(synth.len() > 4 && synth.len().is_multiple_of(2));
        assert_eq!(&synth[synth.len() - 2..], &[0, 0]);
        let words: Vec<u16> = synth[..synth.len() - 2]
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes)
            .collect();
        let decoded = String::from_utf16(&words).expect("valid UTF-16LE NT path");
        assert!(
            decoded.starts_with(r"\device\") && decoded.ends_with(r"\windows\system32\notepad.exe"),
            "unexpected synthesized NT appId: {decoded}"
        );
    }
}
