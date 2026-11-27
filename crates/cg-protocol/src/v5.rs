//! ClaudeGuard v5 shared contract models:
//! - M1: Dynamic/Boot-Time WFP telemetry (`FirewallBackendPref`, `WfpBlockedEvent`, `WfpStatus`)
//! - M2: 10-Dimension Ban-Risk & IP Purity (`AsnClassification`, `IpPurityReport`, `RiskAssessment`, `GeoVelocityAlert`)
//! - M3: WebRTC STUN, DNS coherence & Electron hygiene (`StunLeakReport`, `DnsCoherenceReport`, `ElectronHygieneReport`)
//! - M4: Sovereign Multi-Account Vaults (`AccountVault`, `VaultAppTarget`, `VaultRuntimeStatus`)
//! - M5: Clean-Room Residue Scanner & Encrypted Backups (`CleanRoomScope`, `CleanRoomReport`, `CleanRoomBackupMeta`)
//! - M6: Sub-2ms CLI Hook Gate, WSL2 Bridge & BurstGuard (`HookDecision`, `HookFailMode`, `BurstGuardMode`, `HookIntegrationStatus`, `WslBridgeStatus`, `BurstGuardStatus`)
//! - M7: Global Hotkeys & Desensitized Health Card (`HotkeyStatus`, `SanitizedHealthCard`)

use crate::model::{default_true, normalize_ip_or_cidr, normalize_region};
use serde::{Deserialize, Serialize};

fn default_min_safety_score() -> u8 {
    75
}

fn default_vault_cooldown_secs() -> u64 {
    900
}

/// Validates a Sovereign Vault identifier (`^[a-z0-9][a-z0-9_-]{1,31}$`).
/// Rejects path traversal, Windows reserved names, uppercase, and control characters.
pub fn is_valid_vault_id(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.len() < 2 || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_')
    {
        return false;
    }
    !matches!(
        raw,
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    )
}

// ==================== M1: Kernel WFP Engine ====================

/// Firewall isolation backend engine preference (M1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackendPref {
    /// Default: prefer Windows Filtering Platform (WFP) dynamic sublayer with seamless COM fallback.
    #[default]
    AutoWfpFirst,
    /// Strictly require WFP dynamic/persistent sublayers.
    WfpOnly,
    /// Legacy compatibility mode: Windows Firewall COM (`INetFwPolicy2`) only.
    ComLegacy,
}

impl FirewallBackendPref {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::AutoWfpFirst => "WFP 内核动态子层优先（自动回退 COM）",
            Self::WfpOnly => "仅 WFP 内核过滤引擎",
            Self::ComLegacy => "传统 COM 防火墙兼容模式",
        }
    }
}

/// Real-time kernel blocked packet event attributed via `FwpmNetEventSubscribe4` (256-entry ring buffer).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WfpBlockedEvent {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub app_path: String,
    /// Masked at presentation time when `privacy_mask_ip` is enabled.
    #[serde(default)]
    pub remote_ip: String,
    #[serde(default)]
    pub remote_port: u16,
    /// `"tcp"` | `"udp"` | `"icmpv6"` | `"other"`
    #[serde(default)]
    pub protocol: String,
    /// `"ale_auth_connect_v4"` | `"ale_auth_connect_v6"`
    #[serde(default)]
    pub layer: String,
    /// `"direct_nic_bypass"` | `"boot_time_guard"` | `"app_quarantine"` | `"quic_shield"` | `"doh_shield"` | `"ipv6_shield"` | `"panic_lockdown"`
    #[serde(default)]
    pub filter_reason: String,
}

/// Live WFP sublayer and net-event engine status summary (`GuardSnapshot.wfp`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WfpStatus {
    #[serde(default)]
    pub active_backend: String,
    #[serde(default)]
    pub sublayer_registered: bool,
    #[serde(default)]
    pub dynamic_session_open: bool,
    #[serde(default)]
    pub boot_time_filters_armed: bool,
    #[serde(default)]
    pub active_filter_count: usize,
    #[serde(default)]
    pub net_event_subscribed: bool,
    #[serde(default)]
    pub total_blocked_packets: u64,
    #[serde(default)]
    pub recent_blocked: Vec<WfpBlockedEvent>,
    #[serde(default)]
    pub last_error: String,
}

// ==================== M2 & M3: 10D Risk Scoring, IP Purity & Hygiene ====================

/// Commercial/network classification of an egress ASN (M2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsnClassification {
    /// Native residential ISP broadband (lowest risk).
    IspResidential,
    /// Commercial enterprise ISP line (low risk).
    BusinessIsp,
    /// Cellular CGNAT carrier network.
    MobileCellular,
    /// University / research / government network.
    EducationGov,
    /// Cloud / VPS datacenter hosting (AWS, GCP, Vultr, Hetzner, DMIT, Bandwagon, etc.).
    DatacenterHosting,
    /// Public VPN pool, Tor exit node, or shared high-abuse proxy relay.
    PublicProxyVpnTor,
    #[default]
    Unknown,
}

impl AsnClassification {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::IspResidential => "原生住宅 ISP",
            Self::BusinessIsp => "商业专线 ISP",
            Self::MobileCellular => "移动蜂窝网络",
            Self::EducationGov => "教育/科研网",
            Self::DatacenterHosting => "云机房/VPS 段",
            Self::PublicProxyVpnTor => "公共 VPN / Tor / 共享代理",
            Self::Unknown => "待识别",
        }
    }
}

/// Multi-source egress IP purity and threat intelligence report (M2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPurityReport {
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    /// Fixed-point latitude (`degrees * 10`, e.g. `378` = `37.8°N`) preserving `Eq`.
    #[serde(default)]
    pub lat_tenths: Option<i16>,
    /// Fixed-point longitude (`degrees * 10`, e.g. `-1224` = `122.4°W`) preserving `Eq`.
    #[serde(default)]
    pub lon_tenths: Option<i16>,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub asn_org: String,
    #[serde(default)]
    pub classification: AsnClassification,
    /// Composite abuse/fraud risk index `0..=100` (lower is cleaner; `0..=15` is pristine).
    #[serde(default)]
    pub abuse_risk_score: u8,
    /// Fine-grained `/24` noisy-neighbor abuse rate in basis points (`0..=10000`, e.g. `125` = `1.25%`).
    #[serde(default)]
    pub abuser_score_bps: u32,
    #[serde(default)]
    pub is_datacenter: bool,
    #[serde(default)]
    pub is_proxy_or_vpn: bool,
    #[serde(default)]
    pub is_tor: bool,
    #[serde(default)]
    pub is_bogon_or_relay: bool,
    /// True when IPv4 routes overseas while IPv6 leaks directly via domestic ISP.
    #[serde(default)]
    pub dual_stack_split_detected: bool,
    #[serde(default)]
    pub ipv6_egress_country: Option<String>,
    #[serde(default)]
    pub source_tag: String,
    #[serde(default)]
    pub checked_at: u64,
}

/// Native RFC 5389 UDP STUN WebRTC exposure probe report (M3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StunLeakReport {
    #[serde(default)]
    pub checked_at: u64,
    #[serde(default)]
    pub stun_reachable_direct: bool,
    /// True when direct UDP exposes a public server-reflexive IP mismatching proxy egress.
    #[serde(default)]
    pub leaked: bool,
    #[serde(default)]
    pub reflexive_ip: Option<String>,
    #[serde(default)]
    pub reflexive_country: Option<String>,
    #[serde(default)]
    pub summary: String,
}

/// DNS resolver geographic coherence & pollution audit report (M3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsCoherenceReport {
    #[serde(default)]
    pub checked_at: u64,
    #[serde(default)]
    pub coherent: bool,
    #[serde(default)]
    pub domestic_resolver_detected: bool,
    #[serde(default)]
    pub fake_ip_active: bool,
    #[serde(default)]
    pub resolver_countries: Vec<String>,
    #[serde(default)]
    pub summary: String,
}

/// Live Chromium/Electron command-line hygiene audit report (M3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElectronHygieneReport {
    #[serde(default)]
    pub checked_at: u64,
    #[serde(default)]
    pub webrtc_flag_enforced: bool,
    #[serde(default)]
    pub quic_disabled_flag: bool,
    #[serde(default)]
    pub host_resolver_enforced: bool,
    #[serde(default)]
    pub unguarded_running_agents: Vec<String>,
    #[serde(default)]
    pub summary: String,
}

/// Overall 0-100 positive safety grade (`S` = best, `F` = critical ban risk).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyGrade {
    /// 90..=100: Native residential fortress.
    S,
    /// 75..=89: Clean compliant egress.
    A,
    /// 60..=74: Acceptable with minor caveats (e.g., static clean VPS).
    B,
    /// 40..=59: Elevated ban risk.
    #[default]
    C,
    /// 0..=39: Critical ban hazard (direct leak, impossible travel, Tor, STUN leak).
    F,
}

impl SafetyGrade {
    pub fn from_score(score: u8) -> Self {
        match score {
            90..=100 => Self::S,
            75..=89 => Self::A,
            60..=74 => Self::B,
            40..=59 => Self::C,
            _ => Self::F,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::S => "S",
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::F => "F",
        }
    }
}

/// Individual dimension score item in the 10-Dimension Ban-Risk Radar.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskDimensionItem {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub max_score: u8,
    #[serde(default)]
    pub score: u8,
    #[serde(default)]
    pub healthy: bool,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub remediation_action: Option<String>,
}

/// Impossible-travel geo-velocity alert record (shared by M2 global ledger and M4 per-vault ledger).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoVelocityAlert {
    #[serde(default)]
    pub vault_id: Option<String>,
    #[serde(default)]
    pub from_country: String,
    #[serde(default)]
    pub from_city: String,
    #[serde(default)]
    pub to_country: String,
    #[serde(default)]
    pub to_city: String,
    #[serde(default)]
    pub distance_km: u32,
    #[serde(default)]
    pub elapsed_secs: u64,
    #[serde(default)]
    pub implied_speed_kmh: u32,
    #[serde(default)]
    pub cooldown_until: Option<u64>,
}

/// Complete 10-Dimension Ban-Risk & Egress Safety assessment (`GuardSnapshot.risk_assessment`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    /// Positive safety score `0..=100` (100 = zero ban risk).
    #[serde(default)]
    pub score: u8,
    #[serde(default)]
    pub grade: SafetyGrade,
    #[serde(default)]
    pub headline: String,
    #[serde(default)]
    pub dimensions: Vec<RiskDimensionItem>,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default)]
    pub geo_velocity_alert: Option<GeoVelocityAlert>,
    #[serde(default)]
    pub distinct_subnets_1h: u32,
    #[serde(default)]
    pub distinct_countries_24h: u32,
    #[serde(default)]
    pub ip_purity: IpPurityReport,
    #[serde(default)]
    pub stun_leak: StunLeakReport,
    #[serde(default)]
    pub dns_coherence: DnsCoherenceReport,
    #[serde(default)]
    pub electron_hygiene: ElectronHygieneReport,
    #[serde(default)]
    pub evaluated_at: u64,
}

// ==================== M4: Sovereign Multi-Account Vaults ====================

/// Target AI application launchable inside an isolated Sovereign Account Vault (M4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultAppTarget {
    ClaudeDesktop,
    ChatgptDesktop,
    AntigravityIde,
    ClaudeCodeCli,
    CodexCli,
}

impl VaultAppTarget {
    pub fn agent_id(self) -> &'static str {
        match self {
            Self::ClaudeDesktop => "claude",
            Self::ChatgptDesktop => "chatgpt",
            Self::AntigravityIde => "antigravity",
            Self::ClaudeCodeCli => "claude-code",
            Self::CodexCli => "codex",
        }
    }

    pub fn is_cli(self) -> bool {
        matches!(self, Self::ClaudeCodeCli | Self::CodexCli)
    }
}

/// Isolation execution strategy for MSIX-packaged Windows Store apps (M4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MsixIsolationMode {
    /// Prefer direct unpacked EXE + `--user-data-dir` with lockfile verification; fall back to exclusive swap lock.
    #[default]
    AutoVerifyLock,
    /// Enforce strict single-instance exclusive profile swap lock (zero risk of cross-account mixing).
    ExclusiveSwapLock,
}

/// Persisted configuration for one Sovereign Account Vault (`Config.vaults`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountVault {
    /// Unique identifier (`^[a-z0-9][a-z0-9_-]{1,31}$`, e.g. `"work-claude-max"`).
    pub id: String,
    /// Human-readable display title (e.g. `"主力 Max (US 静态住宅)"`).
    pub name: String,
    /// Card accent hex color (e.g. `"#5B69D0"`).
    #[serde(default)]
    pub accent_hex: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Pinned allowed country codes (ISO 3166-1 alpha-2, e.g. `["US"]`).
    #[serde(default)]
    pub pinned_regions: Vec<String>,
    /// Pinned allowed static IPs or CIDRs.
    #[serde(default)]
    pub pinned_ips: Vec<String>,
    /// Optional pinned ASN (e.g. `Some(7922)`).
    #[serde(default)]
    pub pinned_asn: Option<u32>,
    /// Optional dedicated local proxy mixed port (e.g. `Some(7892)` for concurrent multi-region vaults).
    #[serde(default)]
    pub dedicated_proxy_port: Option<u16>,
    /// Optional linked Mihomo selector group and preferred node name.
    #[serde(default)]
    pub preferred_mihomo_group: Option<String>,
    #[serde(default)]
    pub preferred_mihomo_node: Option<String>,
    /// Opt-in: automatically ask local Mihomo API to switch to `preferred_mihomo_node` on vault launch (default `false`).
    #[serde(default)]
    pub auto_align_mihomo_on_vault_launch: bool,
    /// Minimum 10D safety score required to launch this vault (default `75`).
    #[serde(default = "default_min_safety_score")]
    pub min_safety_score: u8,
    /// Anti-teleportation cooldown in seconds after an IP change (default `900` = 15 min).
    #[serde(default = "default_vault_cooldown_secs")]
    pub cooldown_after_ip_change_secs: u64,
    /// Share host IDE extensions directory across VS Code-family vaults (default `true`).
    #[serde(default = "default_true")]
    pub share_ide_extensions: bool,
    #[serde(default)]
    pub msix_isolation_mode: MsixIsolationMode,
}

impl AccountVault {
    /// Normalizes fields and clamps numeric ranges in-place.
    pub fn normalize(&mut self) {
        self.id = self.id.trim().to_ascii_lowercase();
        self.name = self.name.trim().to_string();
        if self.name.is_empty() {
            self.name = self.id.clone();
        }
        self.accent_hex = self.accent_hex.trim().to_string();
        if self.accent_hex.is_empty() {
            self.accent_hex = "#3B82F6".into();
        }
        let mut regions = Vec::new();
        for r in &self.pinned_regions {
            if let Some(norm) = normalize_region(r)
                && !regions.contains(&norm)
            {
                regions.push(norm);
            }
        }
        self.pinned_regions = regions;

        let mut ips = Vec::new();
        for ip in &self.pinned_ips {
            if let Some(norm) = normalize_ip_or_cidr(ip)
                && !ips.contains(&norm)
            {
                ips.push(norm);
            }
        }
        self.pinned_ips = ips;

        if self.dedicated_proxy_port == Some(0) {
            self.dedicated_proxy_port = None;
        }
        self.min_safety_score = self.min_safety_score.min(100);
        self.cooldown_after_ip_change_secs = self.cooldown_after_ip_change_secs.min(86_400);
    }
}

/// Live runtime state of a Sovereign Account Vault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRuntimeState {
    #[default]
    Ready,
    ActiveRunning,
    CoolingDown,
    EgressMismatch,
    Disabled,
}

/// UI-facing runtime snapshot of a Sovereign Account Vault (`GuardSnapshot.vaults`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRuntimeStatus {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub accent_hex: String,
    #[serde(default)]
    pub state: VaultRuntimeState,
    #[serde(default)]
    pub running_pids: Vec<u32>,
    #[serde(default)]
    pub running_apps: Vec<String>,
    #[serde(default)]
    pub egress_matches_contract: bool,
    #[serde(default)]
    pub cooldown_remaining_secs: u64,
    #[serde(default)]
    pub last_active_at: Option<u64>,
    #[serde(default)]
    pub last_ip_masked: Option<String>,
    #[serde(default)]
    pub last_country: Option<String>,
    #[serde(default)]
    pub vault_dir: String,
    #[serde(default)]
    pub summary: String,
}

// ==================== M5: Clean-Room Residue Scanner & Sanitizer ====================

/// 4 correlation vectors audited by the Clean-Room Residue Scanner (M5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanRoomVector {
    #[default]
    ClaudeCodeState,
    DesktopChromiumAndCrashpad,
    WindowsCredentialManager,
    OrphanMemoryProcess,
}

/// Clean-room contamination severity tier (M5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanRoomRiskLevel {
    #[default]
    Clean,
    Low,
    Elevated,
    CriticalChainBanRisk,
}

/// Single sanitized contamination finding (never exposes raw secrets/cookies).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanRoomFinding {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub vector: CleanRoomVector,
    #[serde(default)]
    pub risk_weight: u8,
    #[serde(default)]
    pub location_display: String,
    #[serde(default)]
    pub correlation_keys: Vec<String>,
    #[serde(default)]
    pub masked_preview: String,
    #[serde(default)]
    pub bytes_size: u64,
    #[serde(default)]
    pub preservation_note: String,
}

/// Client scope selection for Clean-Room scanning and sanitization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanRoomScope {
    #[serde(default = "default_true")]
    pub claude: bool,
    #[serde(default)]
    pub chatgpt_codex: bool,
    #[serde(default)]
    pub antigravity: bool,
}

impl Default for CleanRoomScope {
    fn default() -> Self {
        Self {
            claude: true,
            chatgpt_codex: false,
            antigravity: false,
        }
    }
}

/// Full read-only local residue contamination report (M5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanRoomReport {
    #[serde(default)]
    pub scanned_at: u64,
    #[serde(default)]
    pub scope: CleanRoomScope,
    /// Composite chain-ban contamination score `0..=100` (`0` = sterile clean room, `>=60` = high risk).
    #[serde(default)]
    pub pollution_score: u8,
    #[serde(default)]
    pub risk_level: CleanRoomRiskLevel,
    #[serde(default)]
    pub findings: Vec<CleanRoomFinding>,
    #[serde(default)]
    pub preserved_assets_summary: Vec<String>,
    #[serde(default)]
    pub summary: String,
}

/// Metadata summary for a DPAPI+AES-256-GCM encrypted clean-room backup (`.cgbak`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanRoomBackupMeta {
    #[serde(default)]
    pub backup_id: String,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub archive_bytes: u64,
    #[serde(default)]
    pub item_count: usize,
    #[serde(default)]
    pub sha256_hex: String,
    #[serde(default)]
    pub clients_included: Vec<String>,
}

// ==================== M6: Fast CLI Hook Gate, WSL2 Bridge & BurstGuard ====================

/// Pre-prompt CLI Hook verdict (M6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookDecision {
    #[default]
    Allow,
    Block,
}

/// Hook behavior when `ClaudeGuardService` is unreachable (M6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookFailMode {
    /// Anti-ban default: block prompt transmission when service is unexpectedly offline.
    #[default]
    FailClosed,
    /// Emit warning banner but allow prompt through.
    FailOpenWithWarn,
}

/// Automated rate-burst & robotic cadence protection mode (M6 BurstGuard).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurstGuardMode {
    Off,
    /// Default: alert user without hard-blocking prompts.
    #[default]
    WarnOnly,
    /// Hard-throttle in `FastHookGate` once `burst_throttle_rpm` is exceeded.
    ThrottleGate,
}

/// CLI Hook and PowerShell `$PROFILE` wiring status (`GuardSnapshot.hooks`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookIntegrationStatus {
    #[serde(default)]
    pub claude_code_hook_installed: bool,
    #[serde(default)]
    pub pwsh_profile_wrapped: bool,
    #[serde(default)]
    pub vault_hooks_synced_count: usize,
    #[serde(default)]
    pub total_gate_checks: u64,
    #[serde(default)]
    pub total_gate_blocks: u64,
    #[serde(default)]
    pub last_gate_latency_us: u64,
    #[serde(default)]
    pub summary: String,
}

/// WSL2 loopback HMAC gate bridge status (`GuardSnapshot.wsl_bridge`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WslBridgeStatus {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listening: bool,
    #[serde(default)]
    pub bound_port: Option<u16>,
    #[serde(default)]
    pub token_ready: bool,
    #[serde(default)]
    pub synced_distros: Vec<String>,
    #[serde(default)]
    pub proxy_desync_detected: bool,
    #[serde(default)]
    pub summary: String,
}

/// BurstGuard prompt velocity & OAuth hijack audit status (`GuardSnapshot.burst_guard`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurstGuardStatus {
    #[serde(default)]
    pub mode: BurstGuardMode,
    #[serde(default)]
    pub prompts_last_1m: u32,
    #[serde(default)]
    pub prompts_last_15m: u32,
    #[serde(default)]
    pub robotic_cadence_detected: bool,
    #[serde(default)]
    pub unauthorized_oauth_client_detected: bool,
    #[serde(default)]
    pub suspicious_processes: Vec<String>,
    #[serde(default)]
    pub summary: String,
}

// ==================== M7: Global Hotkeys & Shareable Health Card ====================

/// Global emergency hotkey registration status (`GuardSnapshot.hotkeys`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HotkeyStatus {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub panic_lockdown_chord: String,
    #[serde(default)]
    pub quick_hud_chord: String,
    #[serde(default)]
    pub panic_registered_ok: bool,
    #[serde(default)]
    pub hud_registered_ok: bool,
    #[serde(default)]
    pub conflict_note: String,
}

/// Desensitized shareable Pre-Flight Health Card payload (M7).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedHealthCard {
    #[serde(default)]
    pub generated_at: u64,
    #[serde(default)]
    pub cg_version: String,
    #[serde(default)]
    pub safety_score: u8,
    #[serde(default)]
    pub grade: SafetyGrade,
    #[serde(default)]
    pub region_badge: String,
    #[serde(default)]
    pub asn_purity_badge: String,
    #[serde(default)]
    pub wfp_shield_badge: String,
    #[serde(default)]
    pub leak_hygiene_badge: String,
    #[serde(default)]
    pub geo_stability_badge: String,
    #[serde(default)]
    pub vault_isolation_badge: String,
    #[serde(default)]
    pub markdown_snippet: String,
    #[serde(default)]
    pub saved_png_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_id_validation_blocks_traversal_and_reserved_names() {
        assert!(is_valid_vault_id("work-claude-max"));
        assert!(is_valid_vault_id("a1"));
        assert!(is_valid_vault_id("jp_personal_01"));
        assert!(!is_valid_vault_id("a"));
        assert!(!is_valid_vault_id("-bad"));
        assert!(!is_valid_vault_id("../escape"));
        assert!(!is_valid_vault_id("WorkUpper"));
        assert!(!is_valid_vault_id("con"));
        assert!(!is_valid_vault_id("nul"));
        assert!(!is_valid_vault_id("com1"));
        assert!(!is_valid_vault_id(&"a".repeat(33)));
    }

    #[test]
    fn safety_grade_maps_score_bands_accurately() {
        assert_eq!(SafetyGrade::from_score(100), SafetyGrade::S);
        assert_eq!(SafetyGrade::from_score(90), SafetyGrade::S);
        assert_eq!(SafetyGrade::from_score(89), SafetyGrade::A);
        assert_eq!(SafetyGrade::from_score(75), SafetyGrade::A);
        assert_eq!(SafetyGrade::from_score(74), SafetyGrade::B);
        assert_eq!(SafetyGrade::from_score(60), SafetyGrade::B);
        assert_eq!(SafetyGrade::from_score(59), SafetyGrade::C);
        assert_eq!(SafetyGrade::from_score(40), SafetyGrade::C);
        assert_eq!(SafetyGrade::from_score(39), SafetyGrade::F);
        assert_eq!(SafetyGrade::from_score(0), SafetyGrade::F);
    }

    #[test]
    fn vault_app_target_covers_core_five_suite() {
        let cases = [
            (VaultAppTarget::ClaudeDesktop, "claude", false),
            (VaultAppTarget::ChatgptDesktop, "chatgpt", false),
            (VaultAppTarget::AntigravityIde, "antigravity", false),
            (VaultAppTarget::ClaudeCodeCli, "claude-code", true),
            (VaultAppTarget::CodexCli, "codex", true),
        ];
        for (target, expected_id, expected_cli) in cases {
            assert_eq!(target.agent_id(), expected_id);
            assert_eq!(target.is_cli(), expected_cli);
            let json = serde_json::to_string(&target).expect("serialize target");
            let back: VaultAppTarget = serde_json::from_str(&json).expect("deserialize target");
            assert_eq!(back, target);
        }

        let scope: CleanRoomScope =
            serde_json::from_str(r#"{"claude":true,"antigravity":true,"extraClient":true}"#)
                .expect("deserialize scope ignoring unknown legacy fields");
        assert!(scope.claude);
        assert!(!scope.chatgpt_codex);
        assert!(scope.antigravity);
    }
}
