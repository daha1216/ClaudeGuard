//! Shared domain models, presets, targets, telemetry, and normalization utilities.

use crate::state::OperationReceipt;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

pub fn default_true() -> bool {
    true
}

pub fn default_timeout_secs() -> u64 {
    12
}

/// UI color theme preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeMode {
    Light,
    Dark,
    #[default]
    Auto,
}

/// Egress verification strictness preset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreset {
    /// Allows any known non-direct exit country (rejects mainland/direct `CN`, requires configured allowlist).
    LooseAntiDirect,
    /// Standard v3/v4 evaluation: passes when probed IP/CIDR or country matches target allowlist.
    #[default]
    StandardRegion,
    /// Strict static IP lock: requires probed IP to match `expect_ips` (exact IP or IPv4 CIDR).
    StrictStaticIp,
}

impl PolicyPreset {
    pub fn label(self) -> &'static str {
        match self {
            Self::LooseAntiDirect => "宽松防直连",
            Self::StandardRegion => "标准地区白名单",
            Self::StrictStaticIp => "严格锁定静态 IP",
        }
    }
}

/// Network cut level executed on trip (`CONTRACT-v3.10.md` D1/D2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutMode {
    /// App-level quarantine only (kill guarded GUI processes + per-exe firewall block rules).
    #[default]
    Off,
    /// App quarantine plus global outbound firewall block.
    Firewall,
    /// App quarantine plus disabling physical network adapters recorded in WAL.
    Nics,
}

impl CutMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "不断网",
            Self::Firewall => "防火墙全局阻断",
            Self::Nics => "禁用物理网卡",
        }
    }
}

/// Anchor probe parser kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    #[default]
    Auto,
    Trace,
    JsonIp,
    GeminiRegion,
    Reachability,
}

impl AnchorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "自动识别",
            Self::Trace => "trace 文本",
            Self::JsonIp => "JSON 出口",
            Self::GeminiRegion => "页面地区标记",
            Self::Reachability => "仅可达性",
        }
    }
}

/// Monitored egress target definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub anchor_url: String,
    #[serde(default)]
    pub anchor_kind: AnchorKind,
    /// Allowed exact IPs (IPv4/IPv6) or IPv4 CIDR subnets (e.g. `198.51.100.0/24`).
    #[serde(default)]
    pub expect_ips: Vec<String>,
    /// Allowed ISO 3166-1 country/region codes (e.g. `US`, `JP`).
    #[serde(default)]
    pub expect_regions: Vec<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub bind_agent: Option<String>,
}

impl Target {
    /// Extracts the authority/host portion from `anchor_url`.
    pub fn host(&self) -> String {
        self.anchor_url
            .split("://")
            .nth(1)
            .unwrap_or(&self.anchor_url)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .to_string()
    }

    /// Returns true if at least one IP/CIDR or region expectation is configured.
    pub fn has_expect(&self) -> bool {
        !self.expect_ips.is_empty() || !self.expect_regions.is_empty()
    }

    /// Returns true when the target only checks HTTP reachability.
    pub fn is_reachability(&self) -> bool {
        self.anchor_kind == AnchorKind::Reachability
    }
}

/// Raw probe response parsed from an anchor endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub reachable: bool,
    pub status: Option<u16>,
    pub ip: Option<String>,
    /// Normalized ISO 3166-1 alpha-2 code (e.g. `US`).
    pub country: Option<String>,
    /// Raw region string reported by the anchor (e.g. `USA`).
    pub raw_region: Option<String>,
    pub colo: Option<String>,
    pub city: Option<String>,
    pub latency_ms: u64,
    /// Parser tag: `trace` | `json_ip` | `gemini_region` | `reachability` | `error`.
    pub parsed_as: String,
    pub detail: String,
}

impl ProbeResult {
    /// Returns true when at least one geo/IP datum was extracted.
    pub fn has_info(&self) -> bool {
        self.ip.is_some() || self.country.is_some() || self.raw_region.is_some()
    }

    /// Constructs a transport/network failure probe result.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            parsed_as: "error".into(),
            detail: detail.into(),
            ..Self::default()
        }
    }
}

/// Policy evaluation verdict for a single target probe (`CONTRACT-v3.10.md` §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Pass,
    Fail,
    Unverified,
}

/// Target evaluation output combining verdict, reason, and matched rule summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub verdict: PolicyVerdict,
    pub reason: String,
    #[serde(default)]
    pub matched_rule: Option<String>,
}

/// Current target UI state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    Pending,
    Checking,
    Pass,
    Fail,
    Unverified,
    Disabled,
}

/// Per-target status snapshot exposed to UI and IPC clients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetStatus {
    pub id: String,
    pub name: String,
    pub builtin: bool,
    pub state: TargetState,
    pub anchor_url: String,
    pub anchor_kind: AnchorKind,
    pub expect_ips: Vec<String>,
    pub expect_regions: Vec<String>,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub raw_region: Option<String>,
    pub colo: Option<String>,
    pub city: Option<String>,
    pub latency_ms: u64,
    pub checked_at: Option<u64>,
    pub reason: String,
    pub fail_streak: u32,
    #[serde(default)]
    pub matched_rule: Option<String>,
}

impl TargetStatus {
    /// Creates an initial target status from a [`Target`] configuration entry.
    pub fn from_target(t: &Target, state: TargetState) -> Self {
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            builtin: t.builtin,
            state,
            anchor_url: t.anchor_url.clone(),
            anchor_kind: t.anchor_kind,
            expect_ips: t.expect_ips.clone(),
            expect_regions: t.expect_regions.clone(),
            ip: None,
            country: None,
            raw_region: None,
            colo: None,
            city: None,
            latency_ms: 0,
            checked_at: None,
            reason: String::new(),
            fail_streak: 0,
            matched_rule: None,
        }
    }

    /// Applies probe + evaluation results with explicit timestamp and fail streak.
    pub fn apply_at(
        &mut self,
        probe: &ProbeResult,
        eval: &Evaluation,
        streak: u32,
        checked_at: u64,
    ) {
        self.state = match eval.verdict {
            PolicyVerdict::Pass => TargetState::Pass,
            PolicyVerdict::Fail => TargetState::Fail,
            PolicyVerdict::Unverified => TargetState::Unverified,
        };
        self.ip = probe.ip.clone();
        self.country = probe.country.clone();
        self.raw_region = probe.raw_region.clone();
        self.colo = probe.colo.clone();
        self.city = probe.city.clone();
        self.latency_ms = probe.latency_ms;
        self.checked_at = Some(checked_at);
        self.reason = eval.reason.clone();
        self.fail_streak = streak;
        self.matched_rule = eval.matched_rule.clone();
    }

    /// Returns localized region display text if available.
    pub fn region_text(&self) -> String {
        match (&self.country, &self.raw_region) {
            (Some(c), _) => region_name(c).to_string(),
            (None, Some(raw)) => raw.clone(),
            _ => String::new(),
        }
    }

    /// Secondary summary line for target Bento cards.
    pub fn geo_text(&self) -> String {
        if self.state == TargetState::Disabled {
            return "未启用".into();
        }
        if self.anchor_kind == AnchorKind::Reachability {
            return match self.state {
                TargetState::Pass => format!("可达 · {}ms", self.latency_ms),
                TargetState::Fail => "不可达".into(),
                _ => "待检测".into(),
            };
        }
        if self.country.is_some() {
            let mut parts = vec![self.region_text()];
            if let Some(city) = self.city.as_deref().filter(|s| !s.is_empty()) {
                parts.push(city.to_string());
            }
            if let Some(colo) = self.colo.as_deref().filter(|s| !s.is_empty()) {
                parts.push(colo.to_string());
            }
            return parts.join(" · ");
        }
        self.reason.clone()
    }
}

/// Detected client network access level (`CONTRACT-v3.10.md` §4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    SystemProxy,
    Tun,
    Uncovered,
    #[default]
    Unknown,
}

/// Observed access path evidence captured during a check round.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessEvidence {
    pub level: AccessLevel,
    #[serde(default)]
    pub proxy_addr: Option<String>,
    #[serde(default)]
    pub tun_iface: Option<String>,
    #[serde(default)]
    pub route_hint: bool,
    pub observed_at: u64,
    pub revision: u64,
    #[serde(default)]
    pub note: String,
}

impl AccessEvidence {
    /// Returns true when traffic is demonstrably uncovered (proxy disabled and no TUN).
    pub fn is_uncovered(&self) -> bool {
        self.level == AccessLevel::Uncovered
    }

    /// Returns true when the access path cannot be verified (PAC, SOCKS, bypass risk, etc.).
    pub fn is_unknown(&self) -> bool {
        self.level == AccessLevel::Unknown
    }

    /// Returns true when access is confirmed through a known system proxy or active TUN adapter.
    pub fn is_known(&self) -> bool {
        matches!(self.level, AccessLevel::SystemProxy | AccessLevel::Tun)
    }

    /// Legacy v3 string path tag for compatibility.
    pub fn path_tag(&self) -> &'static str {
        match self.level {
            AccessLevel::SystemProxy => "system_proxy",
            AccessLevel::Tun => "tun",
            AccessLevel::Uncovered => "uncovered",
            AccessLevel::Unknown => "unknown",
        }
    }
}

/// Details of an active circuit-breaker trip for diagnostics and recovery cards.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TripInfo {
    pub since: u64,
    pub reason: String,
    #[serde(default)]
    pub failing_ids: Vec<String>,
    pub killed: u32,
    pub firewall_rules: u32,
    #[serde(default)]
    pub quarantined_agents: Vec<String>,
    #[serde(default)]
    pub agents: Vec<String>,
    pub network_cut: CutMode,
    #[serde(default)]
    pub network_note: String,
    #[serde(default)]
    pub expected_summary: String,
    #[serde(default)]
    pub observed_summary: String,
    #[serde(default)]
    pub receipt: Option<OperationReceipt>,
}

/// Single observed direct public TCP connection bypassing the local proxy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakConn {
    pub pid: u32,
    pub agent: String,
    pub remote: String,
    pub port: u16,
}

/// Direct-connection leak observation summary.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakReport {
    pub applicable: bool,
    pub mode: String,
    pub checked_at: u64,
    pub agent_conns: usize,
    pub proxied: usize,
    pub local: usize,
    #[serde(default)]
    pub direct: Vec<LeakConn>,
    pub direct_total: usize,
    pub note: String,
}

impl LeakReport {
    pub fn not_applicable(mode: &str, note: &str, checked_at: u64) -> Self {
        Self {
            applicable: false,
            mode: mode.to_string(),
            checked_at,
            agent_conns: 0,
            proxied: 0,
            local: 0,
            direct: Vec::new(),
            direct_total: 0,
            note: note.to_string(),
        }
    }

    pub fn leaked(&self) -> bool {
        self.direct_total > 0
    }
}

/// Host timezone and locale profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvInfo {
    pub tz_key: String,
    pub tz_label: String,
    pub utc_offset_min: i32,
    pub locale: String,
    pub lang: String,
    pub region: String,
}

/// Environment consistency check comparing system timezone/locale with verified egress.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvCheck {
    pub info: EnvInfo,
    #[serde(default)]
    pub egress_country: Option<String>,
    #[serde(default)]
    pub egress_colo: Option<String>,
    #[serde(default)]
    pub expect_city: Option<String>,
    #[serde(default)]
    pub expect_tz: Option<String>,
    #[serde(default)]
    pub tz_match: Option<bool>,
    #[serde(default)]
    pub locale_match: Option<bool>,
    #[serde(default)]
    pub note: String,
}

impl EnvCheck {
    pub fn mismatched(&self) -> bool {
        self.tz_match == Some(false) || self.locale_match == Some(false)
    }
}

/// Applied system environment alignment WAL record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppliedEnv {
    pub at: u64,
    pub city: String,
    pub tz_from: String,
    pub tz_to: String,
    pub lat_from: Option<String>,
    pub lon_from: Option<String>,
    pub lat_to: String,
    pub lon_to: String,
}

impl AppliedEnv {
    pub fn touched_tz(&self) -> bool {
        !self.tz_to.is_empty()
    }

    pub fn touched_location(&self) -> bool {
        !self.lat_to.is_empty()
    }
}

/// Health classification for a 24h timeline bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineStatus {
    #[default]
    Empty,
    Pass,
    Warn,
    Fail,
}

/// Single bucket in the 24h rolling timeline (48 x 30m or 96 x 15m buckets).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineBucket {
    pub bucket_start: u64,
    pub bucket_secs: u32,
    pub total_checks: u32,
    pub pass_count: u32,
    pub warn_count: u32,
    pub fail_count: u32,
    pub status: TimelineStatus,
    pub max_latency_ms: u64,
    pub avg_latency_ms: u64,
}

impl TimelineBucket {
    pub fn empty(bucket_start: u64, bucket_secs: u32) -> Self {
        Self {
            bucket_start,
            bucket_secs,
            total_checks: 0,
            pass_count: 0,
            warn_count: 0,
            fail_count: 0,
            status: TimelineStatus::Empty,
            max_latency_ms: 0,
            avg_latency_ms: 0,
        }
    }
}

/// Health state for an individual defense subsystem check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfCheckStatus {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Disabled,
    Unsupported,
}

/// Single defense self-check row displayed on the overview Bento card.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefenseCheckItem {
    pub id: String,
    pub name: String,
    pub status: SelfCheckStatus,
    pub detail: String,
}

/// Live self-check status across daemon, firewall COM, leak radar, and WAL journal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefenseSelfCheck {
    pub daemon_running: bool,
    pub daemon_elevated: bool,
    pub firewall_com_ready: bool,
    pub firewall_query_ok: bool,
    pub global_cut_ready: bool,
    pub leak_radar_active: bool,
    pub wal_clean: bool,
    #[serde(default)]
    pub wal_pending_tx: Option<String>,
    #[serde(default)]
    pub items: Vec<DefenseCheckItem>,
    pub checked_at: u64,
}

/// Distinguishes GUI agents (quarantined & terminated on fail) from CLI agents (warned/orphan-swept).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    #[default]
    Gui,
    Cli,
}

/// Cached runtime status for one guarded or observed AI client.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeStatus {
    pub id: String,
    pub name: String,
    pub kind: AgentKind,
    pub installed: bool,
    pub guarded: bool,
    pub running_count: usize,
    pub orphan_count: usize,
    pub quarantined: bool,
    pub firewall_rules: usize,
    #[serde(default)]
    pub install_paths: Vec<String>,
}

/// Health state of `yuaotian/antigravity-proxy` (`version.dll` + `config.json` + runtime memory hook).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityProxyState {
    #[default]
    NotInstalled,
    Healthy,
    MissingDll,
    MissingOrInvalidConfig,
    PortMismatch,
    RuntimeUnhooked,
}

impl AntigravityProxyState {
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub fn is_degraded(self) -> bool {
        matches!(
            self,
            Self::MissingDll
                | Self::MissingOrInvalidConfig
                | Self::PortMismatch
                | Self::RuntimeUnhooked
        )
    }

    pub fn label_zh(self) -> &'static str {
        match self {
            Self::NotInstalled => "未安装反重力",
            Self::Healthy => "注入生效",
            Self::MissingDll => "注入丢失 (version.dll)",
            Self::MissingOrInvalidConfig => "注入配置异常",
            Self::PortMismatch => "代理端口不一致",
            Self::RuntimeUnhooked => "运行态未挂载",
        }
    }
}

/// Snapshot of `yuaotian/antigravity-proxy` disk artifacts and live memory module verification.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AntigravityProxyStatus {
    #[serde(default)]
    pub state: AntigravityProxyState,
    #[serde(default)]
    pub installed: bool,
    #[serde(default)]
    pub antigravity_dir: Option<String>,
    #[serde(default)]
    pub antigravity_version: Option<String>,
    #[serde(default)]
    pub dll_present: bool,
    #[serde(default)]
    pub dll_valid: bool,
    #[serde(default)]
    pub dll_size: u64,
    #[serde(default)]
    pub config_present: bool,
    #[serde(default)]
    pub injector_version: Option<String>,
    #[serde(default)]
    pub proxy_type: Option<String>,
    #[serde(default)]
    pub proxy_host: Option<String>,
    #[serde(default)]
    pub proxy_port: Option<u16>,
    #[serde(default)]
    pub port_matches_guard: bool,
    #[serde(default)]
    pub child_injection: Option<bool>,
    #[serde(default)]
    pub runtime_running: bool,
    #[serde(default)]
    pub runtime_dll_loaded_main: bool,
    #[serde(default)]
    pub runtime_dll_loaded_ls: bool,
    #[serde(default)]
    pub version_changed_from: Option<String>,
    #[serde(default)]
    pub checked_at: u64,
    #[serde(default)]
    pub summary: String,
}

impl AntigravityProxyStatus {
    pub fn is_ready_for_launch(&self) -> bool {
        !self.installed || self.state == AntigravityProxyState::Healthy
    }
}

/// Asynchronous release check phase for ClaudeGuard and external components.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCheckPhase {
    #[default]
    Idle,
    Checking,
    UpToDate,
    UpdateAvailable,
    NotInstalled,
    Failed,
}

impl UpdateCheckPhase {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::Idle => "待检查",
            Self::Checking => "检查中",
            Self::UpToDate => "已是最新版",
            Self::UpdateAvailable => "发现新版本",
            Self::NotInstalled => "未安装",
            Self::Failed => "检查失败",
        }
    }
}

/// Update check status for a single tracked component (ClaudeGuard or antigravity-proxy).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentUpdateStatus {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub phase: UpdateCheckPhase,
    #[serde(default)]
    pub installed_version: Option<String>,
    #[serde(default)]
    pub latest_version: Option<String>,
    #[serde(default)]
    pub release_url: Option<String>,
    #[serde(default)]
    pub asset_url: Option<String>,
    #[serde(default)]
    pub checked_at: Option<u64>,
    #[serde(default)]
    pub note: String,
}

fn default_claudeguard_update_status() -> ComponentUpdateStatus {
    ComponentUpdateStatus {
        id: "claudeguard".into(),
        name: "ClaudeGuard 主程序".into(),
        repo: "daha1216/ClaudeGuard".into(),
        installed_version: Some(env!("CARGO_PKG_VERSION").into()),
        ..ComponentUpdateStatus::default()
    }
}

fn default_antigravity_proxy_update_status() -> ComponentUpdateStatus {
    ComponentUpdateStatus {
        id: "antigravity_proxy".into(),
        name: "antigravity-proxy 注入器".into(),
        repo: "yuaotian/antigravity-proxy".into(),
        ..ComponentUpdateStatus::default()
    }
}

fn default_claude_desktop_update_status() -> ComponentUpdateStatus {
    ComponentUpdateStatus {
        id: "claude_desktop".into(),
        name: "Claude 桌面端".into(),
        repo: "Anthropic MSIX 官方渠道".into(),
        ..ComponentUpdateStatus::default()
    }
}

fn default_claude_code_update_status() -> ComponentUpdateStatus {
    ComponentUpdateStatus {
        id: "claude_code".into(),
        name: "Claude Code CLI".into(),
        repo: "@anthropic-ai/claude-code".into(),
        ..ComponentUpdateStatus::default()
    }
}

fn default_codex_desktop_update_status() -> ComponentUpdateStatus {
    ComponentUpdateStatus {
        id: "codex_desktop".into(),
        name: "ChatGPT / Codex 桌面端".into(),
        repo: "OpenAI MSIX 官方渠道".into(),
        ..ComponentUpdateStatus::default()
    }
}

fn default_codex_cli_update_status() -> ComponentUpdateStatus {
    ComponentUpdateStatus {
        id: "codex_cli".into(),
        name: "Codex CLI".into(),
        repo: "@openai/codex".into(),
        ..ComponentUpdateStatus::default()
    }
}

fn default_antigravity_ide_update_status() -> ComponentUpdateStatus {
    ComponentUpdateStatus {
        id: "antigravity_ide".into(),
        name: "Antigravity 客户端".into(),
        repo: "Google 官方更新源".into(),
        ..ComponentUpdateStatus::default()
    }
}

/// Aggregated software update and local MSIX / CLI / IDE package version summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSummary {
    #[serde(default = "default_claudeguard_update_status")]
    pub claudeguard: ComponentUpdateStatus,
    #[serde(default = "default_antigravity_proxy_update_status")]
    pub antigravity_proxy: ComponentUpdateStatus,
    #[serde(default = "default_claude_desktop_update_status")]
    pub claude_desktop: ComponentUpdateStatus,
    #[serde(default = "default_claude_code_update_status")]
    pub claude_code: ComponentUpdateStatus,
    #[serde(default = "default_codex_desktop_update_status")]
    pub codex_desktop: ComponentUpdateStatus,
    #[serde(default = "default_codex_cli_update_status")]
    pub codex_cli: ComponentUpdateStatus,
    #[serde(default = "default_antigravity_ide_update_status")]
    pub antigravity_ide: ComponentUpdateStatus,
    #[serde(default)]
    pub claude_msix_version: Option<String>,
    #[serde(default)]
    pub codex_msix_version: Option<String>,
}

impl Default for UpdateSummary {
    fn default() -> Self {
        Self {
            claudeguard: default_claudeguard_update_status(),
            antigravity_proxy: default_antigravity_proxy_update_status(),
            claude_desktop: default_claude_desktop_update_status(),
            claude_code: default_claude_code_update_status(),
            codex_desktop: default_codex_desktop_update_status(),
            codex_cli: default_codex_cli_update_status(),
            antigravity_ide: default_antigravity_ide_update_status(),
            claude_msix_version: None,
            codex_msix_version: None,
        }
    }
}

/// Audit/operational log severity level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    #[default]
    Info,
    Warn,
    Error,
    Audit,
}

/// Structured log entry returned by `GuardSnapshot` and `QueryLogs`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: u64,
    pub level: LogLevel,
    pub category: String,
    pub message: String,
}

/// Onboarding strategy suggested from zero-input environment probing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStrategy {
    RecommendRegion,
    StrictStaticIp,
    CustomCidrOrRegions,
}

/// Selectable onboarding option card with pre-populated rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingOption {
    pub strategy: OnboardingStrategy,
    pub recommended: bool,
    pub title: String,
    pub subtitle: String,
    pub preset: PolicyPreset,
    #[serde(default)]
    pub expect_ips: Vec<String>,
    #[serde(default)]
    pub expect_regions: Vec<String>,
}

/// Zero-input onboarding probe output returned by `PipeRequest::ProbeOnboarding`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingProbeResult {
    pub access: AccessEvidence,
    #[serde(default)]
    pub detected_proxy_port: Option<u16>,
    #[serde(default)]
    pub probe: Option<ProbeResult>,
    #[serde(default)]
    pub installed_agents: Vec<String>,
    #[serde(default)]
    pub recommended_strategy: Option<OnboardingStrategy>,
    #[serde(default)]
    pub standby_notice: Option<String>,
    #[serde(default)]
    pub options: Vec<OnboardingOption>,
}

// ---------- IPv4 CIDR & IP / Region Normalization ----------

/// Parsed IPv4 CIDR subnet (e.g. `198.51.100.0/24`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Cidr {
    pub network: u32,
    pub prefix_len: u8,
}

impl Ipv4Cidr {
    /// Parses a CIDR string like `198.51.100.0/24`, normalizing host bits to the network address.
    pub fn parse(raw: &str) -> Option<Self> {
        let (ip_part, prefix_part) = raw.trim().split_once('/')?;
        let addr: Ipv4Addr = ip_part.trim().parse().ok()?;
        let prefix_len: u8 = prefix_part.trim().parse().ok()?;
        if prefix_len > 32 {
            return None;
        }
        let mask = Self::mask_for(prefix_len);
        Some(Self {
            network: u32::from(addr) & mask,
            prefix_len,
        })
    }

    pub const fn mask_for(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        }
    }

    /// Returns true if `ip` belongs to this CIDR subnet.
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & Self::mask_for(self.prefix_len)) == self.network
    }

    /// Formats canonical `a.b.c.d/prefix` representation.
    pub fn canonical(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix_len)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.network), self.prefix_len)
    }
}

/// Parsed IP allowlist rule supporting both exact IPv4/IPv6 and IPv4 CIDR subnets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpRule {
    Exact(IpAddr),
    CidrV4(Ipv4Cidr),
}

impl IpRule {
    pub fn parse(raw: &str) -> Option<Self> {
        let text = raw.trim();
        if text.is_empty() {
            return None;
        }
        if text.contains('/') {
            Ipv4Cidr::parse(text).map(Self::CidrV4)
        } else {
            text.parse::<IpAddr>().ok().map(Self::Exact)
        }
    }

    pub fn matches(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::Exact(expected), actual) => expected == actual,
            (Self::CidrV4(cidr), IpAddr::V4(v4)) => cidr.contains(v4),
            (Self::CidrV4(_), IpAddr::V6(_)) => false,
        }
    }

    pub fn canonical(self) -> String {
        match self {
            Self::Exact(ip) => ip.to_string(),
            Self::CidrV4(cidr) => cidr.canonical(),
        }
    }
}

/// Normalizes a single exact IP string (rejecting CIDRs or invalid syntax).
pub fn normalize_ip(raw: &str) -> Option<String> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    text.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Normalizes an exact IP or IPv4 CIDR allowlist entry.
pub fn normalize_ip_or_cidr(raw: &str) -> Option<String> {
    IpRule::parse(raw).map(IpRule::canonical)
}

/// Returns the canonical rule string that matched `ip`, if any.
pub fn matched_ip_rule(expect: &[String], ip: &str) -> Option<String> {
    let parsed_ip: IpAddr = ip.trim().parse().ok()?;
    for entry in expect {
        if let Some(rule) = IpRule::parse(entry)
            && rule.matches(parsed_ip)
        {
            return Some(rule.canonical());
        }
    }
    None
}

/// Returns true if `ip` matches any exact IP or IPv4 CIDR entry in `expect`.
pub fn ip_hit(expect: &[String], ip: &str) -> bool {
    matched_ip_rule(expect, ip).is_some()
}

const ALPHA3_TO_ALPHA2: &[(&str, &str)] = &[
    ("USA", "US"),
    ("CAN", "CA"),
    ("MEX", "MX"),
    ("BRA", "BR"),
    ("ARG", "AR"),
    ("CHL", "CL"),
    ("COL", "CO"),
    ("PER", "PE"),
    ("GBR", "GB"),
    ("IRL", "IE"),
    ("FRA", "FR"),
    ("DEU", "DE"),
    ("NLD", "NL"),
    ("BEL", "BE"),
    ("LUX", "LU"),
    ("CHE", "CH"),
    ("AUT", "AT"),
    ("ESP", "ES"),
    ("PRT", "PT"),
    ("ITA", "IT"),
    ("GRC", "GR"),
    ("POL", "PL"),
    ("CZE", "CZ"),
    ("SVK", "SK"),
    ("HUN", "HU"),
    ("ROU", "RO"),
    ("BGR", "BG"),
    ("SWE", "SE"),
    ("NOR", "NO"),
    ("DNK", "DK"),
    ("FIN", "FI"),
    ("EST", "EE"),
    ("LVA", "LV"),
    ("LTU", "LT"),
    ("UKR", "UA"),
    ("RUS", "RU"),
    ("TUR", "TR"),
    ("ISR", "IL"),
    ("ARE", "AE"),
    ("SAU", "SA"),
    ("EGY", "EG"),
    ("ZAF", "ZA"),
    ("NGA", "NG"),
    ("IND", "IN"),
    ("PAK", "PK"),
    ("BGD", "BD"),
    ("THA", "TH"),
    ("VNM", "VN"),
    ("MYS", "MY"),
    ("SGP", "SG"),
    ("IDN", "ID"),
    ("PHL", "PH"),
    ("CHN", "CN"),
    ("HKG", "HK"),
    ("MAC", "MO"),
    ("TWN", "TW"),
    ("JPN", "JP"),
    ("KOR", "KR"),
    ("PRK", "KP"),
    ("MNG", "MN"),
    ("KAZ", "KZ"),
    ("AUS", "AU"),
    ("NZL", "NZ"),
    ("CUB", "CU"),
    ("IRN", "IR"),
    ("SYR", "SY"),
    ("BLR", "BY"),
];

const ISO_REGION_CODES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";

/// Normalizes alpha-2 or common alpha-3 region codes to uppercase ISO alpha-2.
pub fn normalize_region(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    match up.len() {
        2 if up.chars().all(|c| c.is_ascii_alphabetic()) => Some(up),
        3 => ALPHA3_TO_ALPHA2
            .iter()
            .find(|(a3, _)| *a3 == up)
            .map(|(_, a2)| (*a2).to_string()),
        _ => None,
    }
}

/// Checks whether a string is a valid ISO 3166-1 alpha-2 country/region code.
pub fn is_known_region(code: &str) -> bool {
    let up = code.trim().to_ascii_uppercase();
    up.len() == 2 && ISO_REGION_CODES.split(' ').any(|item| item == up)
}

/// Localized Chinese display name for common ISO alpha-2 region codes.
pub fn region_name(code: &str) -> &str {
    match code.to_ascii_uppercase().as_str() {
        "US" => "美国",
        "JP" => "日本",
        "SG" => "新加坡",
        "HK" => "香港",
        "TW" => "台湾",
        "KR" => "韩国",
        "GB" => "英国",
        "DE" => "德国",
        "FR" => "法国",
        "CA" => "加拿大",
        "AU" => "澳大利亚",
        "NL" => "荷兰",
        "RU" => "俄罗斯",
        "IN" => "印度",
        "BR" => "巴西",
        "TR" => "土耳其",
        "AE" => "阿联酋",
        "CH" => "瑞士",
        "SE" => "瑞典",
        "IT" => "意大利",
        "ES" => "西班牙",
        "CN" => "中国",
        "MO" => "澳门",
        _ => code,
    }
}

/// Matches an observed country code against expected region entries.
pub fn region_hit(expect: &[String], country: &str) -> bool {
    let Some(country) = normalize_region(country) else {
        return false;
    };
    expect.iter().any(|e| {
        normalize_region(e)
            .map(|n| n == country)
            .unwrap_or_else(|| e.trim().eq_ignore_ascii_case(country.as_str()))
    })
}

/// Built-in target IDs in canonical display order.
pub const BUILTIN_TARGET_IDS: [&str; 4] = ["local", "claude", "codex", "antigravity"];

pub fn is_builtin_target(id: &str) -> bool {
    BUILTIN_TARGET_IDS.contains(&id)
}

fn clean_ips_lossy(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in raw.iter().filter_map(|s| normalize_ip_or_cidr(s)) {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn clean_regions_lossy(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
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

/// Constructs the four default built-in targets (`local` disabled by default per `AGENTS.md` #19).
pub fn default_builtin_targets(expect_ips: &[String], expect_regions: &[String]) -> Vec<Target> {
    let ips = clean_ips_lossy(expect_ips);
    let regions = clean_regions_lossy(expect_regions);
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

/// Ensures all built-in targets exist and sit in canonical order before custom targets.
pub fn ensure_builtin_targets(
    mut targets: Vec<Target>,
    fallback_ips: &[String],
    fallback_regions: &[String],
) -> Vec<Target> {
    let mut ips = clean_ips_lossy(fallback_ips);
    let mut regions = clean_regions_lossy(fallback_regions);
    if ips.is_empty()
        && regions.is_empty()
        && let Some(src) = targets.iter().find(|t| t.has_expect())
    {
        ips = src.expect_ips.clone();
        regions = src.expect_regions.clone();
    }
    for builtin in default_builtin_targets(&ips, &regions) {
        if !targets.iter().any(|t| t.id == builtin.id) {
            targets.push(builtin);
        }
    }
    targets.sort_by_key(|t| {
        BUILTIN_TARGET_IDS
            .iter()
            .position(|id| *id == t.id)
            .unwrap_or(BUILTIN_TARGET_IDS.len())
    });
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parses_normalizes_and_matches_subnets() {
        let cidr = Ipv4Cidr::parse("198.51.100.98/24").expect("valid CIDR");
        assert_eq!(cidr.canonical(), "198.51.100.0/24");
        assert!(cidr.contains(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(cidr.contains(Ipv4Addr::new(198, 51, 100, 254)));
        assert!(!cidr.contains(Ipv4Addr::new(198, 51, 101, 1)));

        let zero = Ipv4Cidr::parse("0.0.0.0/0").expect("/0 should not overflow");
        assert!(zero.contains(Ipv4Addr::new(203, 0, 113, 45)));

        assert!(Ipv4Cidr::parse("198.51.100.0/33").is_none());
        assert!(Ipv4Cidr::parse("198.51.100.0").is_none());
    }

    #[test]
    fn ip_hit_handles_exact_and_cidr_rules() {
        let rules = vec!["198.51.100.0/24".to_string(), "203.0.113.45".to_string()];
        assert_eq!(
            matched_ip_rule(&rules, "198.51.100.98").as_deref(),
            Some("198.51.100.0/24")
        );
        assert_eq!(
            matched_ip_rule(&rules, "203.0.113.45").as_deref(),
            Some("203.0.113.45")
        );
        assert!(!ip_hit(&rules, "203.0.113.46"));
        assert!(!ip_hit(&rules, "not-an-ip"));
    }

    #[test]
    fn region_normalization_works() {
        assert_eq!(normalize_region("USA").as_deref(), Some("US"));
        assert_eq!(normalize_region("jpn").as_deref(), Some("JP"));
        assert!(is_known_region("US"));
        assert!(!is_known_region("ZZ"));
    }

    #[test]
    fn ipv6_and_cidr_edge_cases() {
        let rules = vec!["2001:db8::1".into(), "198.51.100.42/32".into()];
        assert!(ip_hit(&rules, "2001:0db8:0000:0000:0000:0000:0000:0001"));
        assert!(ip_hit(&rules, "198.51.100.42"));
        assert!(!ip_hit(&rules, "198.51.100.43"));
        assert!(IpRule::parse("2001:db8::/32").is_none());
    }

    #[test]
    fn target_status_and_access_evidence_helpers() {
        let t = &default_builtin_targets(&[], &["US".into()])[1];
        let mut st = TargetStatus::from_target(t, TargetState::Pending);
        let probe = ProbeResult {
            reachable: true,
            status: Some(200),
            ip: Some("198.51.100.98".into()),
            country: Some("US".into()),
            raw_region: Some("US".into()),
            colo: Some("LAX".into()),
            city: Some("洛杉矶".into()),
            latency_ms: 42,
            parsed_as: "trace".into(),
            detail: String::new(),
        };
        let eval = Evaluation {
            verdict: PolicyVerdict::Pass,
            reason: "ok".into(),
            matched_rule: Some("US".into()),
        };
        st.apply_at(&probe, &eval, 0, 1_700_000_000);
        assert_eq!(st.geo_text(), "美国 · 洛杉矶 · LAX");
        assert_eq!(st.matched_rule.as_deref(), Some("US"));

        let ev = AccessEvidence {
            level: AccessLevel::Tun,
            tun_iface: Some("Mihomo".into()),
            route_hint: true,
            observed_at: 100,
            revision: 2,
            note: "TUN".into(),
            ..AccessEvidence::default()
        };
        assert!(ev.is_known());
        assert!(!ev.is_uncovered());
        assert_eq!(ev.path_tag(), "tun");
    }

    #[test]
    fn antigravity_proxy_status_helpers_and_serde_roundtrip() {
        assert!(!AntigravityProxyState::NotInstalled.is_healthy());
        assert!(!AntigravityProxyState::NotInstalled.is_degraded());
        assert_eq!(
            AntigravityProxyState::NotInstalled.label_zh(),
            "未安装反重力"
        );
        assert!(AntigravityProxyState::Healthy.is_healthy());
        assert!(!AntigravityProxyState::Healthy.is_degraded());
        assert_eq!(AntigravityProxyState::Healthy.label_zh(), "注入生效");
        for degraded in [
            AntigravityProxyState::MissingDll,
            AntigravityProxyState::MissingOrInvalidConfig,
            AntigravityProxyState::PortMismatch,
            AntigravityProxyState::RuntimeUnhooked,
        ] {
            assert!(degraded.is_degraded());
            assert!(!degraded.is_healthy());
            assert!(!degraded.label_zh().is_empty());
        }

        let not_installed = AntigravityProxyStatus::default();
        assert!(not_installed.is_ready_for_launch());

        let missing = AntigravityProxyStatus {
            state: AntigravityProxyState::MissingDll,
            installed: true,
            antigravity_dir: Some(r"C:\Users\demo\AppData\Local\Programs\antigravity".into()),
            antigravity_version: Some("45.0.0".into()),
            dll_present: false,
            dll_valid: false,
            dll_size: 0,
            config_present: true,
            injector_version: Some("2.6.3".into()),
            proxy_type: Some("socks5".into()),
            proxy_host: Some("127.0.0.1".into()),
            proxy_port: Some(7890),
            port_matches_guard: true,
            child_injection: Some(true),
            runtime_running: false,
            runtime_dll_loaded_main: false,
            runtime_dll_loaded_ls: false,
            version_changed_from: Some("44.9.1".into()),
            checked_at: 1_700_000_123,
            summary: "version.dll 缺失".into(),
        };
        assert!(!missing.is_ready_for_launch());

        let json = serde_json::to_string(&missing).expect("serialize AntigravityProxyStatus");
        assert!(json.contains("\"missing_dll\""));
        assert!(json.contains("\"antigravityVersion\""));
        let back: AntigravityProxyStatus =
            serde_json::from_str(&json).expect("deserialize AntigravityProxyStatus");
        assert_eq!(back, missing);

        let mut healthy = missing;
        healthy.state = AntigravityProxyState::Healthy;
        healthy.dll_present = true;
        healthy.dll_valid = true;
        healthy.dll_size = 730_112;
        assert!(healthy.is_ready_for_launch());
    }

    #[test]
    fn update_summary_and_phase_serde_roundtrip() {
        assert_eq!(UpdateCheckPhase::Idle.label_zh(), "待检查");
        assert_eq!(UpdateCheckPhase::Checking.label_zh(), "检查中");
        assert_eq!(UpdateCheckPhase::UpToDate.label_zh(), "已是最新版");
        assert_eq!(UpdateCheckPhase::UpdateAvailable.label_zh(), "发现新版本");
        assert_eq!(UpdateCheckPhase::NotInstalled.label_zh(), "未安装");
        assert_eq!(UpdateCheckPhase::Failed.label_zh(), "检查失败");

        let mut summary = UpdateSummary::default();
        assert_eq!(summary.claudeguard.id, "claudeguard");
        assert_eq!(summary.claudeguard.repo, "daha1216/ClaudeGuard");
        assert_eq!(
            summary.claudeguard.installed_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(summary.antigravity_proxy.id, "antigravity_proxy");
        assert_eq!(summary.antigravity_proxy.repo, "yuaotian/antigravity-proxy");

        summary.antigravity_proxy.phase = UpdateCheckPhase::UpdateAvailable;
        summary.antigravity_proxy.installed_version = Some("2.6.0".into());
        summary.antigravity_proxy.latest_version = Some("2.6.3".into());
        summary.antigravity_proxy.release_url =
            Some("https://github.com/yuaotian/antigravity-proxy/releases/tag/v2.6.3".into());
        summary.antigravity_proxy.asset_url = Some(
            "https://github.com/yuaotian/antigravity-proxy/releases/download/v2.6.3/version.dll"
                .into(),
        );
        summary.antigravity_proxy.checked_at = Some(1_700_000_200);
        summary.antigravity_proxy.note = "发现新版本 v2.6.3".into();
        summary.claude_msix_version = Some("1.2.3.0".into());
        summary.codex_msix_version = Some("26.501.0.0".into());

        let json = serde_json::to_string(&summary).expect("serialize UpdateSummary");
        assert!(json.contains("\"update_available\""));
        assert!(json.contains("\"antigravityProxy\""));
        assert!(json.contains("\"claudeMsixVersion\""));
        let back: UpdateSummary = serde_json::from_str(&json).expect("deserialize UpdateSummary");
        assert_eq!(back, summary);

        let empty_back: UpdateSummary =
            serde_json::from_str("{}").expect("deserialize empty UpdateSummary");
        assert_eq!(empty_back, UpdateSummary::default());
    }
}
