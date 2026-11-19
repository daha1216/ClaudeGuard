//! View-model projections, draft input isolation, and privacy-masked display formatters.
//!
//! Pure deterministic Rust module (zero GPUI or Win32 dependencies) so all state
//! projections, draft isolation guarantees, and IP masking are exhaustively unit-tested.

use crate::demo::now_unix_secs;
use crate::protocol::{
    AccessLevel, AgentKind, AnchorKind, AntigravityProxyState, AntigravityProxyStatus, Config,
    DefenseCheckItem, GuardSnapshot, Lifecycle, LogEntry, LogLevel, OnboardingProbeResult,
    OnboardingStrategy, OperationReceipt, PolicyPreset, ProtectionState, SelfCheckStatus, Target,
    TargetState, TargetStatus, TimelineBucket, TimelineStatus, UiLabelExt, UpdateSummary,
    mask_ip_str, mask_ips_in_text, region_name,
};
use crate::theme::{BadgeTone, HeroTone};

/// Sidebar navigation destinations in Mode B Main Console.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum NavSection {
    #[default]
    Overview,
    Targets,
    Breaker,
    Environment,
    Audit,
    Updates,
    Notify,
}

impl NavSection {
    pub const ALL: [NavSection; 7] = [
        NavSection::Overview,
        NavSection::Targets,
        NavSection::Breaker,
        NavSection::Environment,
        NavSection::Audit,
        NavSection::Updates,
        NavSection::Notify,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "守护总览磁贴",
            Self::Targets => "目标与白名单",
            Self::Breaker => "熔断与防火墙",
            Self::Environment => "环境与防泄露",
            Self::Audit => "时间线与审计",
            Self::Updates => "客户端更新",
            Self::Notify => "通知与飞书",
        }
    }

    pub fn short_tag(self) -> &'static str {
        match self {
            Self::Overview => "总览",
            Self::Targets => "白名单",
            Self::Breaker => "熔断",
            Self::Environment => "环境",
            Self::Audit => "审计",
            Self::Updates => "更新",
            Self::Notify => "通知",
        }
    }
}

/// Editable row draft for a single egress target, isolated from background polling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetDraft {
    pub id: String,
    pub name: String,
    pub builtin: bool,
    pub enabled: bool,
    pub anchor_url: String,
    pub anchor_kind: AnchorKind,
    pub expect_ips_text: String,
    pub expect_regions_text: String,
    pub timeout_secs: u64,
    pub bind_agent: Option<String>,
}

impl TargetDraft {
    pub fn from_target(t: &Target) -> Self {
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            builtin: t.builtin,
            enabled: t.enabled,
            anchor_url: t.anchor_url.clone(),
            anchor_kind: t.anchor_kind,
            expect_ips_text: t.expect_ips.join(", "),
            expect_regions_text: t.expect_regions.join(", "),
            timeout_secs: t.timeout_secs,
            bind_agent: t.bind_agent.clone(),
        }
    }

    pub fn to_target(&self) -> Target {
        Target {
            id: self.id.clone(),
            name: self.name.trim().to_string(),
            builtin: self.builtin,
            enabled: self.enabled,
            anchor_url: self.anchor_url.trim().to_string(),
            anchor_kind: self.anchor_kind,
            expect_ips: split_tokens(&self.expect_ips_text),
            expect_regions: split_tokens(&self.expect_regions_text)
                .into_iter()
                .map(|s| s.to_ascii_uppercase())
                .collect(),
            timeout_secs: self.timeout_secs.clamp(3, 60),
            bind_agent: self.bind_agent.clone(),
        }
    }
}

/// Isolated form drafts so background snapshot refreshes NEVER overwrite in-progress typing.
#[derive(Clone, Debug)]
pub struct DraftStore {
    pub dirty: bool,
    pub loaded_cfg_rev: Option<u64>,
    pub proxy_port: String,
    pub interval_secs: String,
    pub trip_threshold: String,
    pub targets: Vec<TargetDraft>,
    pub new_target_name: String,
    pub new_target_url: String,
    pub new_target_ips: String,
    pub new_target_regions: String,
    pub feishu_enabled: bool,
    pub feishu_webhook: String,
    pub feishu_secret: String,
    pub feishu_clear_secret: bool,
    pub search_query: String,
    pub onboarding_strategy: OnboardingStrategy,
    pub onboarding_custom_cidr: String,
    pub onboarding_custom_regions: String,
    pub validation_error: Option<String>,
}

impl Default for DraftStore {
    fn default() -> Self {
        Self {
            dirty: false,
            loaded_cfg_rev: None,
            proxy_port: "7890".into(),
            interval_secs: "15".into(),
            trip_threshold: "2".into(),
            targets: Vec::new(),
            new_target_name: String::new(),
            new_target_url: String::new(),
            new_target_ips: String::new(),
            new_target_regions: String::new(),
            feishu_enabled: false,
            feishu_webhook: String::new(),
            feishu_secret: String::new(),
            feishu_clear_secret: false,
            search_query: String::new(),
            onboarding_strategy: OnboardingStrategy::RecommendRegion,
            onboarding_custom_cidr: "198.51.100.0/24".into(),
            onboarding_custom_regions: "US, JP".into(),
            validation_error: None,
        }
    }
}

impl DraftStore {
    /// Synchronizes drafts from a daemon config ONLY when `!self.dirty` and `cfg_rev` advanced.
    pub fn sync_from_snapshot(&mut self, cfg: &Config, cfg_rev: u64) -> bool {
        if self.dirty {
            return false;
        }
        if self.loaded_cfg_rev == Some(cfg_rev) {
            return false;
        }
        self.force_load(cfg, cfg_rev);
        true
    }

    /// Force-reloads drafts after an explicit save or reset.
    pub fn force_load(&mut self, cfg: &Config, cfg_rev: u64) {
        self.dirty = false;
        self.loaded_cfg_rev = Some(cfg_rev);
        self.proxy_port = cfg.proxy_port.to_string();
        self.interval_secs = cfg.interval_secs.to_string();
        self.trip_threshold = cfg.trip_threshold.to_string();
        self.targets = cfg.targets.iter().map(TargetDraft::from_target).collect();
        self.validation_error = None;
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        self.validation_error = None;
    }

    /// Validates and applies drafts onto a base [`Config`] before sending `SaveConfig`.
    pub fn build_updated_config(&mut self, base: &Config) -> Result<Config, String> {
        let port: u16 = self
            .proxy_port
            .trim()
            .parse()
            .ok()
            .filter(|&p| p >= 1)
            .ok_or_else(|| "代理端口必须是 1–65535 之间的整数".to_string())?;
        let interval: u64 = self
            .interval_secs
            .trim()
            .parse()
            .ok()
            .filter(|&s| (5..=3600).contains(&s))
            .ok_or_else(|| "检查间隔必须在 5–3600 秒之间".to_string())?;
        let threshold: u32 = self
            .trip_threshold
            .trim()
            .parse()
            .ok()
            .filter(|&t| (1..=10).contains(&t))
            .ok_or_else(|| "连续失败阈值必须在 1–10 次之间".to_string())?;

        let mut next = base.clone();
        next.proxy_port = port;
        next.interval_secs = interval;
        next.trip_threshold = threshold;
        next.targets = self.targets.iter().map(TargetDraft::to_target).collect();
        for t in &next.targets {
            if t.name.is_empty() {
                return Err("存在名称为空的监控目标".into());
            }
            if !t.anchor_url.starts_with("https://") && !t.anchor_url.starts_with("http://") {
                return Err(format!(
                    "目标「{}」的探测 URL 必须以 https:// 或 http:// 开头",
                    t.name
                ));
            }
            if t.enabled
                && t.anchor_kind != AnchorKind::Reachability
                && t.expect_ips.is_empty()
                && t.expect_regions.is_empty()
            {
                return Err(format!(
                    "目标「{}」已启用，请至少填写 1 个允许地区或 IP/CIDR",
                    t.name
                ));
            }
        }
        Ok(next)
    }
}

pub fn split_tokens(raw: &str) -> Vec<String> {
    raw.split(|c: char| c.is_whitespace() || matches!(c, ',' | '，' | ';' | '；'))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Projected Hero Bento card state shared by Mode A HUD and Mode B Console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeroViewModel {
    pub tone: HeroTone,
    pub pill_label: String,
    pub title: String,
    pub subtitle: String,
    pub access_badge: String,
    pub pass_count: usize,
    pub fail_count: usize,
    pub unverified_count: usize,
    pub is_paused: bool,
    pub paused_remaining_text: Option<String>,
    pub checked_age_text: String,
    pub can_launch: bool,
}

/// Projected target card in Bento grid & Mode A 2x2 HUD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetCardViewModel {
    pub id: String,
    pub name: String,
    pub cc_badge: String,
    pub state_label: String,
    pub badge_tone: BadgeTone,
    pub ip_display: String,
    pub location_display: String,
    pub latency_label: String,
    pub matched_rule: String,
    pub anchor_url: String,
}

/// Projected Safe Launch Dock application button.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeLaunchAppViewModel {
    pub agent_id: String,
    pub label: String,
    pub badge: String,
    pub installed: bool,
    pub quarantined: bool,
    pub ag_proxy_blocked: bool,
    pub running_count: usize,
    pub orphan_count: usize,
    pub install_paths: Vec<String>,
}

/// Projected Tripped Diagnostic Dual-Path Card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrippedDiagnosticViewModel {
    pub reason: String,
    pub expected_summary: String,
    pub observed_summary: String,
    pub killed_count: u32,
    pub firewall_rules: u32,
    pub network_note: String,
    pub receipt: Option<OperationReceipt>,
}

/// Projected Mode A Tray Quick HUD (`376 x 486`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HudProjection {
    pub connected: bool,
    pub connection_err: Option<String>,
    pub hero: HeroViewModel,
    pub ag_proxy_warning: Option<String>,
    pub target_tiles: Vec<TargetCardViewModel>,
    pub process_tile_title: String,
    pub process_tile_value: String,
    pub process_tile_sub: String,
    pub total_orphans: usize,
    pub launch_apps: Vec<SafeLaunchAppViewModel>,
    pub pause_button_label: String,
}

/// Projected runtime status row for one AI client on the Breaker page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentStatusRowViewModel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub installed: bool,
    pub quarantined: bool,
    pub running_count: usize,
    pub orphan_count: usize,
    pub firewall_rules: usize,
}

/// Complete projected view model for Mode B Main Console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleProjection {
    pub connected: bool,
    pub connection_banner: Option<String>,
    pub hero: HeroViewModel,
    pub tripped_card: Option<TrippedDiagnosticViewModel>,
    pub target_cards: Vec<TargetCardViewModel>,
    pub launch_apps: Vec<SafeLaunchAppViewModel>,
    pub timeline_bars: Vec<TimelineBarViewModel>,
    pub selected_bucket_summary: String,
    pub selected_bucket_window: Option<(u64, u64)>,
    pub self_checks: Vec<DefenseCheckItem>,
    pub filtered_logs: Vec<LogEntry>,
    pub agent_statuses: Vec<AgentStatusRowViewModel>,
    pub updates: UpdateSummary,
}

/// Projected diagnostic Bento card for `yuaotian/antigravity-proxy` on the Environment page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AntigravityProxyCardViewModel {
    pub pill_label: String,
    pub pill_tone: BadgeTone,
    pub checked_age_label: Option<String>,
    pub version_primary: String,
    pub version_sub: String,
    pub version_warn: bool,
    pub dll_primary: String,
    pub dll_sub: String,
    pub dll_tone: BadgeTone,
    pub config_primary: String,
    pub config_sub: String,
    pub config_tone: BadgeTone,
    pub runtime_primary: String,
    pub runtime_sub: String,
    pub runtime_tone: BadgeTone,
    pub summary_text: String,
    pub dir_text: String,
    pub is_degraded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelineBarViewModel {
    pub index: usize,
    pub bucket_start: u64,
    pub bucket_secs: u32,
    pub status: TimelineStatus,
    pub total_checks: u32,
    pub pass_count: u32,
    pub warn_count: u32,
    pub fail_count: u32,
    pub avg_latency_ms: u64,
    pub selected: bool,
    pub label: String,
}

pub fn format_relative_secs(ts: Option<u64>, now: u64) -> String {
    let Some(t) = ts else {
        return "尚未检测".into();
    };
    let diff = now.saturating_sub(t);
    if diff < 5 {
        "刚刚".into()
    } else if diff < 60 {
        format!("{diff} 秒前")
    } else if diff < 3600 {
        format!("{} 分钟前", diff / 60)
    } else {
        format!("{} 小时前", diff / 3600)
    }
}

pub fn format_remaining_secs(until: Option<u64>, now: u64) -> Option<String> {
    let until = until?;
    if until <= now {
        return None;
    }
    let rem = until - now;
    let mins = rem / 60;
    let secs = rem % 60;
    if mins > 0 {
        Some(format!("剩余 {mins} 分 {secs} 秒"))
    } else {
        Some(format!("剩余 {secs} 秒"))
    }
}

pub fn format_unix_hm(ts: u64) -> String {
    if ts == 0 {
        return "--:--".into();
    }
    // Local UTC+8 fallback formatting without heavy chrono dependency in view model;
    // displays clean HH:MM:SS relative/day-clock from epoch seconds.
    let day_secs = (ts + 8 * 3600) % 86_400;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

pub fn project_hero(
    snap: Option<&GuardSnapshot>,
    connected: bool,
    privacy_mask: bool,
    now_secs: u64,
) -> HeroViewModel {
    let Some(snap) = snap else {
        return HeroViewModel {
            tone: HeroTone::DisarmedOrPaused,
            pill_label: "等待守护服务".into(),
            title: "尚未连接 Guardian 服务".into(),
            subtitle: "正在尝试连接 \\\\.\\pipe\\ClaudeGuardV4，或使用 --demo 预览状态".into(),
            access_badge: "未连接".into(),
            pass_count: 0,
            fail_count: 0,
            unverified_count: 0,
            is_paused: false,
            paused_remaining_text: None,
            checked_age_text: "等待快照".into(),
            can_launch: false,
        };
    };

    let mut pass_count = 0;
    let mut fail_count = 0;
    let mut unverified_count = 0;
    for t in &snap.targets {
        match t.state {
            TargetState::Pass => pass_count += 1,
            TargetState::Fail => fail_count += 1,
            TargetState::Pending | TargetState::Checking | TargetState::Unverified => {
                unverified_count += 1
            }
            TargetState::Disabled => {}
        }
    }

    let is_paused = snap.is_paused_at(now_secs);
    let paused_remaining_text = format_remaining_secs(snap.paused_until, now_secs);
    let access_badge = match snap.access.level {
        AccessLevel::SystemProxy => snap
            .access
            .proxy_addr
            .as_deref()
            .and_then(|addr| addr.rsplit_once(':').map(|(_, p)| format!(":{p} 代理")))
            .unwrap_or_else(|| format!(":{} 代理", snap.config.proxy_port)),
        AccessLevel::Tun => snap
            .access
            .tun_iface
            .as_deref()
            .map(|ifn| format!("TUN · {ifn}"))
            .unwrap_or_else(|| "TUN 接管".into()),
        AccessLevel::Uncovered => "未接入代理".into(),
        AccessLevel::Unknown => "接入未知".into(),
    };

    let (tone, pill_label, title, subtitle) = if !connected {
        (
            HeroTone::DisarmedOrPaused,
            "连接中断 · 安全闭锁".into(),
            "守护服务未连接（安全闭锁中）".into(),
            "命名管道不可用，无法验证出口合规；严格禁止假报通过或启动 AI 应用".into(),
        )
    } else if snap.lifecycle == Lifecycle::Unconfigured {
        (
            HeroTone::DisarmedOrPaused,
            "等待首次配置".into(),
            "尚未完成首启向导".into(),
            "当前为只读预探态，不会终止进程或修改防火墙；请完成向导开始守护".into(),
        )
    } else if snap.lifecycle == Lifecycle::Disarmed {
        (
            HeroTone::DisarmedOrPaused,
            "已撤防".into(),
            "保护已停止并解除隔离".into(),
            if snap.disarmed_reason.is_empty() {
                "AI 应用可正常直连或按系统配置运行；点「重新布防」恢复出口守护".into()
            } else {
                maybe_mask(&snap.disarmed_reason, privacy_mask)
            },
        )
    } else if snap.is_tripped() {
        let reason = snap
            .tripped
            .as_ref()
            .map(|t| t.reason.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("出口校验触发熔断隔离");
        (
            HeroTone::Tripped,
            snap.protection.label().to_string(),
            "已熔断并隔离受管 AI 应用".into(),
            maybe_mask(reason, privacy_mask),
        )
    } else if is_paused {
        (
            HeroTone::DisarmedOrPaused,
            "守护暂停中".into(),
            "已暂停自动拦截与熔断".into(),
            format!(
                "继续执行只读出口检测，不新增隔离操作（{}）",
                paused_remaining_text.as_deref().unwrap_or("即将恢复")
            ),
        )
    } else if fail_count > 0 {
        (
            HeroTone::Tripped,
            "出口异常告警".into(),
            "检测到出口不合规".into(),
            format!(
                "有 {fail_count} 个目标未通过白名单校验，即将达到熔断阈值 ({} 次)",
                snap.config.trip_threshold
            ),
        )
    } else if snap.all_enabled_pass() && snap.protection == ProtectionState::Monitoring {
        let primary_loc = snap
            .targets
            .iter()
            .find(|t| t.id == "claude" && t.state == TargetState::Pass)
            .or_else(|| snap.targets.iter().find(|t| t.state == TargetState::Pass))
            .map(|t| {
                let loc = match (t.country.as_deref(), t.city.as_deref()) {
                    (Some(cc), Some(city)) if !city.is_empty() => {
                        format!("{} · {city}", region_name(cc))
                    }
                    (Some(cc), _) => region_name(cc).to_string(),
                    _ => "合规节点".to_string(),
                };
                let ip =
                    t.ip.as_deref()
                        .map(|ip| maybe_mask_ip(ip, privacy_mask))
                        .unwrap_or_else(|| "可达".into());
                format!("{loc} ({ip}) · {}ms", t.latency_ms)
            })
            .unwrap_or_else(|| "全部目标合规".into());
        (
            HeroTone::Healthy,
            "实时守护正常".into(),
            "出口安全合规".into(),
            format!("{primary_loc} · COM 防火墙与进程防线正常"),
        )
    } else {
        (
            HeroTone::DisarmedOrPaused,
            snap.protection.label().to_string(),
            "正在核验出口与防线".into(),
            "在所有启用目标确认通过前，Safe Launch 门禁将保持拦截保护".into(),
        )
    };

    let can_launch = connected
        && snap.lifecycle == Lifecycle::Armed
        && !is_paused
        && snap.protection == ProtectionState::Monitoring
        && snap.all_enabled_pass();

    HeroViewModel {
        tone,
        pill_label,
        title,
        subtitle,
        access_badge,
        pass_count,
        fail_count,
        unverified_count,
        is_paused,
        paused_remaining_text,
        checked_age_text: format_relative_secs(snap.checked_at, now_secs),
        can_launch,
    }
}

fn maybe_mask_ip(ip: &str, mask: bool) -> String {
    if mask {
        mask_ip_str(ip)
    } else {
        ip.to_string()
    }
}

fn maybe_mask(text: &str, mask: bool) -> String {
    if mask {
        mask_ips_in_text(text)
    } else {
        text.to_string()
    }
}

pub fn project_target_card(target: &TargetStatus, privacy_mask: bool) -> TargetCardViewModel {
    let badge_tone = match target.state {
        TargetState::Pass => BadgeTone::Pass,
        TargetState::Fail => BadgeTone::Fail,
        TargetState::Pending | TargetState::Checking | TargetState::Unverified => BadgeTone::Warn,
        TargetState::Disabled => BadgeTone::Muted,
    };

    let cc_badge = target
        .country
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_else(|| {
            if target.anchor_kind == AnchorKind::Reachability {
                "TLS".into()
            } else {
                "--".into()
            }
        });

    let ip_display = if target.state == TargetState::Disabled {
        "未启用".into()
    } else if let Some(ip) = target.ip.as_deref() {
        maybe_mask_ip(ip, privacy_mask)
    } else if target.anchor_kind == AnchorKind::Reachability {
        if target.state == TargetState::Pass {
            "Google 后端直通".into()
        } else {
            "仅可达性探测".into()
        }
    } else {
        "等待出口 IP".into()
    };

    let location_display = if target.state == TargetState::Disabled {
        "请在「目标与白名单」启用".into()
    } else if let Some(cc) = target.country.as_deref() {
        let mut parts = vec![region_name(cc).to_string()];
        if let Some(city) = target.city.as_deref().filter(|s| !s.is_empty()) {
            parts.push(city.to_string());
        }
        if let Some(colo) = target.colo.as_deref().filter(|s| !s.is_empty()) {
            parts.push(colo.to_string());
        }
        parts.join(" · ")
    } else {
        maybe_mask(&target.reason, privacy_mask)
    };

    let latency_label = if target.latency_ms > 0 {
        format!("{}ms", target.latency_ms)
    } else {
        "--".into()
    };

    let matched_rule = target
        .matched_rule
        .as_deref()
        .map(|r| maybe_mask(r, privacy_mask))
        .unwrap_or_else(|| {
            if target.state == TargetState::Fail {
                maybe_mask(&target.reason, privacy_mask)
            } else if !target.expect_regions.is_empty() || !target.expect_ips.is_empty() {
                let mut rules = Vec::new();
                if !target.expect_regions.is_empty() {
                    rules.push(format!("地区 {}", target.expect_regions.join("/")));
                }
                if !target.expect_ips.is_empty() {
                    let ips: Vec<String> = target
                        .expect_ips
                        .iter()
                        .map(|ip| maybe_mask_ip(ip, privacy_mask))
                        .collect();
                    rules.push(ips.join(", "));
                }
                rules.join(" · ")
            } else {
                maybe_mask(&target.reason, privacy_mask)
            }
        });

    TargetCardViewModel {
        id: target.id.clone(),
        name: target.name.clone(),
        cc_badge,
        state_label: target.state.label().to_string(),
        badge_tone,
        ip_display,
        location_display,
        latency_label,
        matched_rule,
        anchor_url: target.anchor_url.clone(),
    }
}

pub fn project_launch_apps(snap: Option<&GuardSnapshot>) -> Vec<SafeLaunchAppViewModel> {
    let canonical = [
        ("claude", "Claude Desktop", "桌面端"),
        ("claude-code", "Claude Code", "CLI"),
        ("chatgpt", "ChatGPT", "Codex"),
        ("antigravity", "反重力", "IDE"),
    ];

    canonical
        .into_iter()
        .map(|(id, label, badge)| {
            let ag_proxy_blocked = id == "antigravity"
                && snap.is_some_and(|s| {
                    s.config.require_antigravity_proxy
                        && s.antigravity_proxy.installed
                        && !s.antigravity_proxy.is_ready_for_launch()
                });
            let found = snap.and_then(|s| s.agents.iter().find(|a| a.id == id));
            match found {
                Some(agent) => SafeLaunchAppViewModel {
                    agent_id: id.into(),
                    label: label.into(),
                    badge: badge.into(),
                    installed: agent.installed,
                    quarantined: agent.quarantined,
                    ag_proxy_blocked,
                    running_count: agent.running_count,
                    orphan_count: agent.orphan_count,
                    install_paths: agent.install_paths.clone(),
                },
                None => SafeLaunchAppViewModel {
                    agent_id: id.into(),
                    label: label.into(),
                    badge: badge.into(),
                    installed: true,
                    quarantined: snap.is_some_and(GuardSnapshot::is_tripped),
                    ag_proxy_blocked,
                    running_count: 0,
                    orphan_count: 0,
                    install_paths: Vec::new(),
                },
            }
        })
        .collect()
}

pub fn project_hud(
    snap: Option<&GuardSnapshot>,
    connected: bool,
    connection_err: Option<&str>,
    privacy_mask: bool,
) -> HudProjection {
    let now = now_unix_secs();
    let hero = project_hero(snap, connected, privacy_mask, now);

    let mut target_tiles = Vec::new();
    if let Some(s) = snap {
        for id in ["claude", "codex", "antigravity"] {
            if let Some(t) = s.targets.iter().find(|t| t.id == id) {
                target_tiles.push(project_target_card(t, privacy_mask));
            }
        }
        if target_tiles.len() < 3 {
            for t in &s.targets {
                if t.state != TargetState::Disabled
                    && !target_tiles.iter().any(|x| x.id == t.id)
                    && target_tiles.len() < 3
                {
                    target_tiles.push(project_target_card(t, privacy_mask));
                }
            }
        }
    }

    let total_orphans: usize = snap
        .map(|s| s.agents.iter().map(|a| a.orphan_count).sum())
        .unwrap_or(0);
    let total_running: usize = snap
        .map(|s| s.agents.iter().map(|a| a.running_count).sum())
        .unwrap_or(0);
    let quarantined_rules: usize = snap
        .map(|s| s.agents.iter().map(|a| a.firewall_rules).sum())
        .unwrap_or(0);

    let (process_tile_value, process_tile_sub) = if !connected && snap.is_none() {
        ("未连接守护服务".into(), "无法读取进程或防火墙防线".into())
    } else if snap.is_some_and(GuardSnapshot::is_tripped) {
        (
            format!("已隔离 {quarantined_rules} 规则"),
            "点击「打开主控制台」一键复检解封".into(),
        )
    } else if total_orphans > 0 {
        (
            format!("发现 {total_orphans} 个孤儿进程"),
            "点击右侧「清孤儿」立即清理".into(),
        )
    } else {
        (
            format!("{total_running} 个守护进程正常"),
            "无孤儿残留 · 守护链路干净".into(),
        )
    };

    let pause_button_label = if hero.is_paused {
        "▶ 恢复守护".into()
    } else {
        "II 暂停 30m".into()
    };

    let ag_proxy_warning = snap.and_then(|s| {
        if s.antigravity_proxy.state.is_degraded() {
            let detail = if s.antigravity_proxy.summary.trim().is_empty() {
                s.antigravity_proxy.state.label().to_string()
            } else {
                maybe_mask(s.antigravity_proxy.summary.trim(), privacy_mask)
            };
            Some(format!("! 反重力代理注入异常：{detail}"))
        } else {
            None
        }
    });

    HudProjection {
        connected,
        connection_err: connection_err.map(ToString::to_string),
        hero,
        ag_proxy_warning,
        target_tiles,
        process_tile_title: "进程守护".into(),
        process_tile_value,
        process_tile_sub,
        total_orphans,
        launch_apps: project_launch_apps(snap),
        pause_button_label,
    }
}

pub fn project_console(
    snap: Option<&GuardSnapshot>,
    connected: bool,
    connection_err: Option<&str>,
    privacy_mask: bool,
    selected_bucket: Option<usize>,
    search_query: &str,
    queried_logs: Option<&[LogEntry]>,
) -> ConsoleProjection {
    let now = now_unix_secs();
    let hero = project_hero(snap, connected, privacy_mask, now);

    let connection_banner = if !connected {
        Some(
            connection_err
                .map(|e| format!("守护服务未连接：{e}"))
                .unwrap_or_else(|| "正在连接守护服务 \\\\.\\pipe\\ClaudeGuardV4…".into()),
        )
    } else {
        None
    };

    let tripped_card = snap.and_then(|s| {
        if !s.is_tripped() {
            return None;
        }
        let info = s.tripped.as_ref();
        let reason = info
            .map(|t| maybe_mask(&t.reason, privacy_mask))
            .unwrap_or_else(|| "检测到出口违规或保护隔离状态".into());
        let expected_summary = info
            .map(|t| maybe_mask(&t.expected_summary, privacy_mask))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                s.targets
                    .iter()
                    .find(|t| t.state == TargetState::Fail)
                    .map(|t| {
                        let reg = if t.expect_regions.is_empty() {
                            "未设地区".into()
                        } else {
                            t.expect_regions.join("/")
                        };
                        let ips = if t.expect_ips.is_empty() {
                            "未设静态 IP".into()
                        } else {
                            t.expect_ips
                                .iter()
                                .map(|ip| maybe_mask_ip(ip, privacy_mask))
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        format!("地区 {reg} · {ips}")
                    })
                    .unwrap_or_else(|| "已配置白名单".into())
            });
        let observed_summary = info
            .map(|t| maybe_mask(&t.observed_summary, privacy_mask))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                s.targets
                    .iter()
                    .find(|t| t.state == TargetState::Fail)
                    .map(|t| {
                        let cc = t.country.as_deref().unwrap_or("--");
                        let ip =
                            t.ip.as_deref()
                                .map(|ip| maybe_mask_ip(ip, privacy_mask))
                                .unwrap_or_else(|| "未知 IP".into());
                        format!("{cc} · {ip}")
                    })
                    .unwrap_or_else(|| "实测违规出口".into())
            });

        Some(TrippedDiagnosticViewModel {
            reason,
            expected_summary,
            observed_summary,
            killed_count: info.map(|t| t.killed).unwrap_or(0),
            firewall_rules: info.map(|t| t.firewall_rules).unwrap_or(0),
            network_note: info
                .map(|t| t.network_note.clone())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "应用级隔离已核验".into()),
            receipt: info.and_then(|t| t.receipt.clone()),
        })
    });

    let target_cards = snap
        .map(|s| {
            s.targets
                .iter()
                .filter(|t| t.state != TargetState::Disabled)
                .take(3)
                .map(|t| project_target_card(t, privacy_mask))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let timeline_bars = project_timeline_bars(snap, selected_bucket);
    let selected_bar = selected_bucket.and_then(|idx| timeline_bars.get(idx));
    let selected_bucket_window =
        selected_bar.map(|b| (b.bucket_start, b.bucket_start + u64::from(b.bucket_secs)));
    let selected_bucket_summary = match selected_bar {
        Some(b) => format!(
            "已选时段 {} · {} · 通过 {} / 告警 {} / 失败 {} · 均值 {}ms",
            format_unix_hm(b.bucket_start),
            b.status.label(),
            b.pass_count,
            b.warn_count,
            b.fail_count,
            b.avg_latency_ms
        ),
        None => "24h 每格 30 分钟 · 点击柱条筛选对应时段审计日志".into(),
    };

    let self_checks = project_self_checks(snap);

    let needle = search_query.trim().to_ascii_lowercase();
    let log_source: &[LogEntry] = if let Some(live_logs) = queried_logs {
        live_logs
    } else if let Some(s) = snap {
        &s.recent_logs
    } else {
        &[]
    };
    let filtered_logs = log_source
        .iter()
        .filter(|entry| {
            if let Some((start, end)) = selected_bucket_window
                && (entry.timestamp < start || entry.timestamp >= end)
            {
                return false;
            }
            if !needle.is_empty() {
                let msg_l = entry.message.to_ascii_lowercase();
                let cat_l = entry.category.to_ascii_lowercase();
                if !msg_l.contains(&needle) && !cat_l.contains(&needle) {
                    return false;
                }
            }
            true
        })
        .map(|entry| LogEntry {
            id: entry.id,
            timestamp: entry.timestamp,
            level: entry.level,
            category: entry.category.clone(),
            message: maybe_mask(&entry.message, privacy_mask),
        })
        .collect::<Vec<_>>();

    let agent_statuses = snap
        .map(|s| {
            s.agents
                .iter()
                .map(|a| {
                    let kind = match a.kind {
                        AgentKind::Gui => "GUI".to_string(),
                        AgentKind::Cli => {
                            if s.config.kill_cli_on_fail {
                                "CLI (支持熔断同步终止)".to_string()
                            } else {
                                "CLI (仅告警/清孤儿)".to_string()
                            }
                        }
                    };
                    AgentStatusRowViewModel {
                        id: a.id.clone(),
                        name: a.name.clone(),
                        kind,
                        installed: a.installed,
                        quarantined: a.quarantined,
                        running_count: a.running_count,
                        orphan_count: a.orphan_count,
                        firewall_rules: a.firewall_rules,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let updates = snap.map(|s| s.updates.clone()).unwrap_or_default();

    ConsoleProjection {
        connected,
        connection_banner,
        hero,
        tripped_card,
        target_cards,
        launch_apps: project_launch_apps(snap),
        timeline_bars,
        selected_bucket_summary,
        selected_bucket_window,
        self_checks,
        filtered_logs,
        agent_statuses,
        updates,
    }
}

fn project_timeline_bars(
    snap: Option<&GuardSnapshot>,
    selected_bucket: Option<usize>,
) -> Vec<TimelineBarViewModel> {
    let raw: Vec<TimelineBucket> = snap
        .map(|s| s.timeline.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![TimelineBucket::default(); 48]);

    // Collapse 96 buckets into 48 bars if needed, or display 48 directly.
    let buckets: Vec<TimelineBucket> = if raw.len() == 96 {
        raw.chunks(2)
            .map(|pair| {
                let a = &pair[0];
                let b = pair.get(1).unwrap_or(a);
                let status = match (a.status, b.status) {
                    (TimelineStatus::Fail, _) | (_, TimelineStatus::Fail) => TimelineStatus::Fail,
                    (TimelineStatus::Warn, _) | (_, TimelineStatus::Warn) => TimelineStatus::Warn,
                    (TimelineStatus::Pass, _) | (_, TimelineStatus::Pass) => TimelineStatus::Pass,
                    _ => TimelineStatus::Empty,
                };
                TimelineBucket {
                    bucket_start: a.bucket_start,
                    bucket_secs: a.bucket_secs + b.bucket_secs,
                    total_checks: a.total_checks + b.total_checks,
                    pass_count: a.pass_count + b.pass_count,
                    warn_count: a.warn_count + b.warn_count,
                    fail_count: a.fail_count + b.fail_count,
                    status,
                    max_latency_ms: a.max_latency_ms.max(b.max_latency_ms),
                    avg_latency_ms: match (a.avg_latency_ms, b.avg_latency_ms) {
                        (0, x) | (x, 0) => x,
                        (x, y) => (x + y) / 2,
                    },
                }
            })
            .collect()
    } else {
        raw
    };

    buckets
        .into_iter()
        .enumerate()
        .map(|(index, b)| TimelineBarViewModel {
            index,
            bucket_start: b.bucket_start,
            bucket_secs: b.bucket_secs,
            status: b.status,
            total_checks: b.total_checks,
            pass_count: b.pass_count,
            warn_count: b.warn_count,
            fail_count: b.fail_count,
            avg_latency_ms: b.avg_latency_ms,
            selected: selected_bucket == Some(index),
            label: format!("{} · {}", format_unix_hm(b.bucket_start), b.status.label()),
        })
        .collect()
}

fn project_self_checks(snap: Option<&GuardSnapshot>) -> Vec<DefenseCheckItem> {
    let Some(snap) = snap else {
        return vec![
            DefenseCheckItem {
                id: "daemon".into(),
                name: "Guardian 服务".into(),
                status: SelfCheckStatus::Unknown,
                detail: "等待命名管道连接".into(),
            },
            DefenseCheckItem {
                id: "firewall".into(),
                name: "Win32 COM 防火墙".into(),
                status: SelfCheckStatus::Unknown,
                detail: "未读取".into(),
            },
            DefenseCheckItem {
                id: "leak".into(),
                name: "直连防泄露雷达".into(),
                status: SelfCheckStatus::Unknown,
                detail: "未读取".into(),
            },
            DefenseCheckItem {
                id: "wal".into(),
                name: "WAL 崩溃恢复账本".into(),
                status: SelfCheckStatus::Unknown,
                detail: "未读取".into(),
            },
        ];
    };

    if !snap.self_check.items.is_empty() {
        return snap.self_check.items.clone();
    }

    let sc = &snap.self_check;
    let mut items = vec![
        DefenseCheckItem {
            id: "daemon".into(),
            name: "Guardian 服务".into(),
            status: if sc.daemon_running {
                SelfCheckStatus::Healthy
            } else {
                SelfCheckStatus::Degraded
            },
            detail: if sc.daemon_elevated {
                "服务运行中 · 高权限执行器已就绪".into()
            } else {
                "运行中".into()
            },
        },
        DefenseCheckItem {
            id: "firewall".into(),
            name: "Win32 COM 防火墙".into(),
            status: if sc.firewall_com_ready && sc.firewall_query_ok {
                SelfCheckStatus::Healthy
            } else {
                SelfCheckStatus::Degraded
            },
            detail: if sc.firewall_query_ok {
                "INetFwPolicy2 规则读写与回读核验正常".into()
            } else {
                "防火墙规则查询异常".into()
            },
        },
        DefenseCheckItem {
            id: "leak".into(),
            name: "直连防泄露雷达".into(),
            status: if sc.leak_radar_active {
                SelfCheckStatus::Healthy
            } else {
                SelfCheckStatus::Disabled
            },
            detail: if sc.leak_radar_active {
                "TCP 套接字直连监测运行中".into()
            } else {
                "已关闭".into()
            },
        },
        DefenseCheckItem {
            id: "wal".into(),
            name: "WAL 崩溃恢复账本".into(),
            status: if sc.wal_clean {
                SelfCheckStatus::Healthy
            } else {
                SelfCheckStatus::Degraded
            },
            detail: sc
                .wal_pending_tx
                .as_ref()
                .map(|tx| format!("待提交恢复事务：{tx}"))
                .unwrap_or_else(|| "账本干净 · 无崩溃残留".into()),
        },
    ];

    if snap.antigravity_proxy.installed {
        let ag = &snap.antigravity_proxy;
        let status = if ag.state.is_healthy() {
            SelfCheckStatus::Healthy
        } else {
            SelfCheckStatus::Degraded
        };
        let detail = if ag.summary.trim().is_empty() {
            ag.state.label().to_string()
        } else {
            ag.summary.clone()
        };
        items.push(DefenseCheckItem {
            id: "antigravity_proxy".into(),
            name: "反重力代理注入".into(),
            status,
            detail,
        });
    }

    items
}

/// Projects `AntigravityProxyStatus` into the 2x2 diagnostic Glass Bento card view-model.
pub fn project_antigravity_proxy_card(
    ag: &AntigravityProxyStatus,
    guard_proxy_port: u16,
    privacy_mask: bool,
    now_secs: u64,
) -> AntigravityProxyCardViewModel {
    let pill_tone = match ag.state {
        AntigravityProxyState::Healthy => BadgeTone::Pass,
        AntigravityProxyState::NotInstalled => BadgeTone::Muted,
        AntigravityProxyState::MissingDll | AntigravityProxyState::RuntimeUnhooked => {
            BadgeTone::Fail
        }
        AntigravityProxyState::MissingOrInvalidConfig | AntigravityProxyState::PortMismatch => {
            BadgeTone::Warn
        }
    };
    let pill_label = ag.state.label().to_string();
    let checked_age_label =
        (ag.checked_at > 0).then(|| format_relative_secs(Some(ag.checked_at), now_secs));

    let (version_primary, version_sub, version_warn) = if !ag.installed {
        (
            "未检测到安装".into(),
            r"默认探测 LocalAppData\Programs\antigravity".into(),
            false,
        )
    } else {
        let ver = ag
            .antigravity_version
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|v| format!("v{}", v.trim_start_matches('v')))
            .unwrap_or_else(|| "版本未知".into());
        if let Some(prev) = ag.version_changed_from.as_deref().filter(|s| !s.is_empty()) {
            (
                format!("{ver}（由 v{} 更新）", prev.trim_start_matches('v')),
                "! 检测到客户端版本更新，请核对劫持模块是否被覆盖".into(),
                true,
            )
        } else {
            (ver, "版本稳定 · 未发生覆盖升级".into(), false)
        }
    };

    let (dll_primary, dll_sub, dll_tone) = if !ag.installed {
        (
            "未安装客户端".into(),
            "无需注入模块".into(),
            BadgeTone::Muted,
        )
    } else if ag.dll_present && ag.dll_valid {
        let sub = if ag.dll_size > 0 {
            format!("PE 签名特征通过 · {} KB", ag.dll_size / 1024)
        } else {
            "antigravity-proxy 模块特征匹配".into()
        };
        ("✓ 已就绪 · 签名有效".into(), sub, BadgeTone::Pass)
    } else if ag.dll_present {
        (
            "! 模块无效（非代理 DLL）".into(),
            format!("大小 {} B · 未命中 antigravity-proxy 特征", ag.dll_size),
            BadgeTone::Fail,
        )
    } else {
        let sub = if ag.version_changed_from.is_some() {
            "反重力升级后 version.dll 被覆盖丢失，请重新注入".into()
        } else {
            "安装目录未发现 version.dll 劫持模块".into()
        };
        ("! 缺失或已被更新覆盖".into(), sub, BadgeTone::Fail)
    };

    let (config_primary, config_sub, config_tone) = if !ag.installed {
        ("--".into(), "未安装反重力".into(), BadgeTone::Muted)
    } else if !ag.config_present {
        (
            "! 缺失 config.json".into(),
            "缺少本地代理地址与子进程注入配置".into(),
            BadgeTone::Warn,
        )
    } else {
        let ver_s = ag
            .injector_version
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|v| format!("v{}", v.trim_start_matches('v')))
            .unwrap_or_else(|| "v?".into());
        let scheme = ag
            .proxy_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("socks5");
        let raw_host = ag
            .proxy_host
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("127.0.0.1");
        let host = if privacy_mask
            && raw_host != "127.0.0.1"
            && !raw_host.eq_ignore_ascii_case("localhost")
        {
            mask_ip_str(raw_host)
        } else {
            raw_host.to_string()
        };
        let endpoint = match ag.proxy_port {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}:--"),
        };
        let child_s = match ag.child_injection {
            Some(true) => "子进程注入开启",
            Some(false) => "! 子进程注入关闭",
            None => "子进程注入未声明",
        };
        let primary = format!("{ver_s} · {endpoint} · {child_s}");
        let (sub, tone) = if ag.child_injection == Some(false) || ag.proxy_port.is_none() {
            (
                "! 需开启 child_injection 并配置有效本地代理端口".into(),
                BadgeTone::Warn,
            )
        } else if !ag.port_matches_guard {
            (
                format!("! 与 ClaudeGuard 守护端口 (:{guard_proxy_port}) 不一致"),
                BadgeTone::Warn,
            )
        } else {
            (
                format!("✓ 与 ClaudeGuard 本地代理端口 (:{guard_proxy_port}) 一致"),
                BadgeTone::Pass,
            )
        };
        (primary, sub, tone)
    };

    let (runtime_primary, runtime_sub, runtime_tone) = if !ag.installed {
        ("未安装".into(), "无运行态进程".into(), BadgeTone::Muted)
    } else if !ag.runtime_running {
        if ag.dll_present
            && ag.dll_valid
            && !matches!(
                ag.state,
                AntigravityProxyState::MissingOrInvalidConfig | AntigravityProxyState::PortMismatch
            )
        {
            (
                "○ 未运行（静态就绪）".into(),
                "启动后将自动核验主进程与 language_server 内存模块表".into(),
                BadgeTone::Muted,
            )
        } else {
            (
                "○ 未运行（待修复静态注入）".into(),
                "修复 version.dll / config.json 后再安全启动".into(),
                BadgeTone::Warn,
            )
        }
    } else if ag.state == AntigravityProxyState::RuntimeUnhooked
        || (!ag.runtime_dll_loaded_ls && !ag.runtime_dll_loaded_main)
    {
        (
            "! 运行中但未挂载".into(),
            format!(
                "主进程：{} · language_server：{}",
                if ag.runtime_dll_loaded_main {
                    "已挂载"
                } else {
                    "未挂载"
                },
                if ag.runtime_dll_loaded_ls {
                    "已挂载"
                } else {
                    "未挂载"
                }
            ),
            BadgeTone::Fail,
        )
    } else {
        (
            "● 内存已挂载 VERSION.dll".into(),
            format!(
                "主进程：{} · language_server：{}",
                if ag.runtime_dll_loaded_main {
                    "已挂载"
                } else {
                    "未检出"
                },
                if ag.runtime_dll_loaded_ls {
                    "已挂载"
                } else {
                    "待拉起"
                }
            ),
            BadgeTone::Pass,
        )
    };

    let raw_summary = if ag.summary.trim().is_empty() {
        ag.state.label().to_string()
    } else {
        ag.summary.clone()
    };
    let summary_text = if privacy_mask {
        let protected = raw_summary.replace("127.0.0.1", "__CG_LOOPBACK__");
        mask_ips_in_text(&protected).replace("__CG_LOOPBACK__", "127.0.0.1")
    } else {
        raw_summary
    };
    let dir_text = ag
        .antigravity_dir
        .clone()
        .unwrap_or_else(|| "未检测到反重力安装目录".into());

    AntigravityProxyCardViewModel {
        pill_label,
        pill_tone,
        checked_age_label,
        version_primary,
        version_sub,
        version_warn,
        dll_primary,
        dll_sub,
        dll_tone,
        config_primary,
        config_sub,
        config_tone,
        runtime_primary,
        runtime_sub,
        runtime_tone,
        summary_text,
        dir_text,
        is_degraded: ag.state.is_degraded(),
    }
}

/// Applies onboarding selection to produce a complete armed v4 [`Config`].
pub fn build_onboarding_config(
    base: &Config,
    probe: &OnboardingProbeResult,
    strategy: OnboardingStrategy,
    custom_cidr: &str,
    custom_regions: &str,
) -> Result<Config, String> {
    let mut cfg = base.clone();
    cfg.first_run = false;
    if let Some(port) = probe.detected_proxy_port {
        cfg.proxy_port = port;
    }

    let (preset, ips, regions) = match strategy {
        OnboardingStrategy::RecommendRegion => {
            let opt = probe
                .options
                .iter()
                .find(|o| o.strategy == OnboardingStrategy::RecommendRegion);
            let mut reg = opt.map(|o| o.expect_regions.clone()).unwrap_or_default();
            if reg.is_empty()
                && let Some(cc) = probe.probe.as_ref().and_then(|p| p.country.clone())
            {
                reg.push(cc);
            }
            if reg.is_empty() {
                reg.push("US".into());
            }
            (PolicyPreset::StandardRegion, Vec::new(), reg)
        }
        OnboardingStrategy::StrictStaticIp => {
            let ip = probe
                .probe
                .as_ref()
                .and_then(|p| p.ip.clone())
                .ok_or_else(|| "未能探测到当前出口静态 IP，无法启用严格锁定".to_string())?;
            let reg = probe
                .probe
                .as_ref()
                .and_then(|p| p.country.clone())
                .into_iter()
                .collect();
            (PolicyPreset::StrictStaticIp, vec![ip], reg)
        }
        OnboardingStrategy::CustomCidrOrRegions => {
            let ips = split_tokens(custom_cidr);
            let regions: Vec<String> = split_tokens(custom_regions)
                .into_iter()
                .map(|r| r.to_ascii_uppercase())
                .collect();
            if ips.is_empty() && regions.is_empty() {
                return Err("请至少填写 1 个国家代码（如 US）或 IP/CIDR 网段".into());
            }
            (PolicyPreset::StandardRegion, ips, regions)
        }
    };

    cfg.preset = preset;
    for target in &mut cfg.targets {
        if matches!(target.id.as_str(), "claude" | "codex") {
            target.enabled = true;
            target.expect_ips = ips.clone();
            target.expect_regions = regions.clone();
        }
    }
    if !probe.installed_agents.is_empty() {
        cfg.guarded_agents = probe
            .installed_agents
            .iter()
            .filter(|id| matches!(id.as_str(), "claude" | "chatgpt" | "antigravity"))
            .cloned()
            .collect();
    }
    Ok(cfg)
}

#[allow(dead_code)]
fn _log_level_order(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 3,
        LogLevel::Audit => 2,
        LogLevel::Warn => 1,
        LogLevel::Info => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::{DemoScenario, build_demo_onboarding_probe, build_demo_snapshot};

    #[test]
    fn draft_store_never_overwrites_dirty_user_edits_on_background_refresh() {
        let mut drafts = DraftStore::default();
        let snap1 = build_demo_snapshot(DemoScenario::Pass);
        assert!(drafts.sync_from_snapshot(&snap1.config, snap1.cfg_rev));
        assert_eq!(drafts.proxy_port, "7890");

        // User starts typing a new port and marks draft dirty.
        drafts.proxy_port = "10808".into();
        drafts.mark_dirty();

        // Background daemon refresh arrives with a newer cfg_rev.
        let mut snap2 = snap1.clone();
        snap2.cfg_rev = snap1.cfg_rev + 1;
        snap2.config.proxy_port = 9999;

        assert!(
            !drafts.sync_from_snapshot(&snap2.config, snap2.cfg_rev),
            "background refresh must not overwrite dirty user draft"
        );
        assert_eq!(drafts.proxy_port, "10808");
    }

    #[test]
    fn projections_cover_pass_trip_disarmed_and_privacy_masking() {
        let pass = build_demo_snapshot(DemoScenario::Pass);
        let pass_view = project_console(Some(&pass), true, None, false, None, "", None);
        assert_eq!(pass_view.hero.tone, HeroTone::Healthy);
        assert!(pass_view.hero.can_launch);
        assert!(pass_view.tripped_card.is_none());
        assert_eq!(pass_view.target_cards[0].ip_display, "198.51.100.98");
        assert_eq!(pass_view.self_checks.len(), 4);

        // Privacy masking hides last two IPv4 octets everywhere.
        let pass_snap = build_demo_snapshot(DemoScenario::Pass);
        let masked_view = project_console(Some(&pass_snap), true, None, true, None, "", None);
        assert_eq!(masked_view.target_cards[0].ip_display, "198.51.*.*");
        assert!(masked_view.hero.subtitle.contains("198.51.*.*"));

        // Tripped state exposes dual-path diagnostic diff + masked observed IP.
        let trip_snap = build_demo_snapshot(DemoScenario::Trip);
        let trip_view = project_console(Some(&trip_snap), true, None, true, None, "", None);
        assert_eq!(trip_view.hero.tone, HeroTone::Tripped);
        assert!(!trip_view.hero.can_launch);
        let diag = trip_view.tripped_card.expect("tripped diagnostic card");
        assert!(diag.observed_summary.contains("203.0.*.*"));
        assert!(diag.expected_summary.contains("198.51.*.*"));
        assert_eq!(diag.firewall_rules, 6);

        // Disarmed state uses DisarmedOrPaused hero tone and disallows Safe Launch.
        let disarmed_snap = build_demo_snapshot(DemoScenario::Disarmed);
        let disarmed_hud = project_hud(Some(&disarmed_snap), true, None, false);
        assert_eq!(disarmed_hud.hero.tone, HeroTone::DisarmedOrPaused);
        assert!(!disarmed_hud.hero.can_launch);

        // Disconnected state must fail closed: cannot launch even if stale Pass snapshot exists.
        let offline_hud = project_hud(Some(&pass_snap), false, Some("pipe down"), false);
        assert!(!offline_hud.connected);
        assert!(!offline_hud.hero.can_launch);
        assert_eq!(offline_hud.hero.tone, HeroTone::DisarmedOrPaused);
    }

    #[test]
    fn timeline_bucket_selection_and_search_filter_logs() {
        let trip = build_demo_snapshot(DemoScenario::Trip);
        let all = project_console(Some(&trip), true, None, false, None, "", None);
        assert!(!all.filtered_logs.is_empty());

        let search = project_console(Some(&trip), true, None, false, None, "INetFwRule", None);
        assert_eq!(search.filtered_logs.len(), 1);
        assert_eq!(search.filtered_logs[0].category, "firewall");

        // Bucket 0 is ~24h ago; logs from the last hour must be filtered out when bucket 0 is selected.
        let bucket_zero = project_console(Some(&trip), true, None, false, Some(0), "", None);
        assert!(bucket_zero.filtered_logs.is_empty());
    }

    #[test]
    fn onboarding_strategy_builds_valid_config() {
        let probe = build_demo_onboarding_probe(true);
        let cfg = build_onboarding_config(
            &Config::default(),
            &probe,
            OnboardingStrategy::StrictStaticIp,
            "",
            "",
        )
        .expect("strict static IP config");
        assert!(!cfg.first_run);
        assert_eq!(cfg.preset, PolicyPreset::StrictStaticIp);
        assert_eq!(cfg.targets[1].expect_ips, vec!["198.51.100.98".to_string()]);
    }

    #[test]
    fn antigravity_proxy_blocks_safe_launch_when_missing_dll_and_unblocks_when_healthy_or_optional()
    {
        use crate::protocol::AntigravityProxyState;

        // Healthy in Pass scenario -> unblocked, no HUD warning.
        let mut snap = build_demo_snapshot(DemoScenario::Pass);
        assert!(snap.config.require_antigravity_proxy);
        let healthy_hud = project_hud(Some(&snap), true, None, false);
        assert!(healthy_hud.ag_proxy_warning.is_none());
        let ag_healthy = healthy_hud
            .launch_apps
            .iter()
            .find(|a| a.agent_id == "antigravity")
            .expect("antigravity launch app");
        assert!(!ag_healthy.ag_proxy_blocked);

        // Fallback self-check synthesis includes "反重力代理注入" as Healthy when items is empty.
        snap.self_check.items.clear();
        let healthy_checks = project_self_checks(Some(&snap));
        let ag_check = healthy_checks
            .iter()
            .find(|c| c.name == "反重力代理注入")
            .expect("antigravity_proxy self-check row");
        assert_eq!(ag_check.status, SelfCheckStatus::Healthy);

        // MissingDll (e.g. after Antigravity auto-upgrade) -> antigravity blocked, others unblocked, HUD warns.
        let trip_snap = build_demo_snapshot(DemoScenario::Trip);
        snap.antigravity_proxy = trip_snap.antigravity_proxy;
        assert_eq!(
            snap.antigravity_proxy.state,
            AntigravityProxyState::MissingDll
        );

        let missing_hud = project_hud(Some(&snap), true, None, false);
        let warn = missing_hud
            .ag_proxy_warning
            .as_deref()
            .expect("HUD warning banner when MissingDll");
        assert!(warn.starts_with("! 反重力代理注入异常："));

        for app in &missing_hud.launch_apps {
            if app.agent_id == "antigravity" {
                assert!(
                    app.ag_proxy_blocked,
                    "antigravity must be marked ag_proxy_blocked"
                );
            } else {
                assert!(
                    !app.ag_proxy_blocked,
                    "{} must not be marked ag_proxy_blocked",
                    app.agent_id
                );
            }
        }

        let degraded_checks = project_self_checks(Some(&snap));
        let ag_deg_check = degraded_checks
            .iter()
            .find(|c| c.name == "反重力代理注入")
            .expect("antigravity_proxy degraded self-check row");
        assert_eq!(ag_deg_check.status, SelfCheckStatus::Degraded);

        // Disabling require_antigravity_proxy unblocks Safe Launch while keeping diagnostic visibility.
        snap.config.require_antigravity_proxy = false;
        let opt_out_apps = project_launch_apps(Some(&snap));
        let ag_opt_out = opt_out_apps
            .iter()
            .find(|a| a.agent_id == "antigravity")
            .expect("antigravity launch app");
        assert!(!ag_opt_out.ag_proxy_blocked);

        // NotInstalled never blocks Safe Launch even when require_antigravity_proxy == true.
        snap.config.require_antigravity_proxy = true;
        snap.antigravity_proxy.installed = false;
        snap.antigravity_proxy.state = AntigravityProxyState::NotInstalled;
        let not_installed_hud = project_hud(Some(&snap), true, None, false);
        assert!(not_installed_hud.ag_proxy_warning.is_none());
        let ag_not_installed = not_installed_hud
            .launch_apps
            .iter()
            .find(|a| a.agent_id == "antigravity")
            .expect("antigravity launch app");
        assert!(!ag_not_installed.ag_proxy_blocked);

        // Verify Environment page 2x2 diagnostic card projection across Pass & Trip scenarios.
        let pass_ag = build_demo_snapshot(DemoScenario::Pass).antigravity_proxy;
        let pass_card = project_antigravity_proxy_card(&pass_ag, 7890, true, now_unix_secs());
        assert_eq!(pass_card.pill_tone, BadgeTone::Pass);
        assert_eq!(pass_card.version_primary, "v44.9.1");
        assert!(pass_card.dll_primary.contains("已就绪 · 签名有效"));
        assert_eq!(
            pass_card.config_primary,
            "v2.6.3 · socks5://127.0.0.1:7890 · 子进程注入开启"
        );
        assert!(pass_card.runtime_primary.contains("内存已挂载 VERSION.dll"));
        assert!(!pass_card.is_degraded);

        let trip_ag = build_demo_snapshot(DemoScenario::Trip).antigravity_proxy;
        let trip_card = project_antigravity_proxy_card(&trip_ag, 7890, false, now_unix_secs());
        assert_eq!(trip_card.pill_tone, BadgeTone::Fail);
        assert!(trip_card.version_primary.contains("v45.0.0"));
        assert!(trip_card.version_primary.contains("由 v44.9.1 更新"));
        assert!(trip_card.dll_primary.contains("缺失或已被更新覆盖"));
        assert!(trip_card.is_degraded);
    }

    #[test]
    fn project_console_propagates_agent_status_ids_and_update_summary() {
        use crate::protocol::UpdateCheckPhase;

        let pass = build_demo_snapshot(DemoScenario::Pass);
        let pass_view = project_console(Some(&pass), true, None, false, None, "", None);
        let ids: Vec<&str> = pass_view
            .agent_statuses
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["claude", "chatgpt", "antigravity", "claude-code", "codex"]
        );
        let claude_row = pass_view
            .agent_statuses
            .iter()
            .find(|r| r.id == "claude")
            .unwrap();
        assert!(claude_row.installed);
        assert_eq!(claude_row.orphan_count, 1);
        assert_eq!(
            pass_view.updates.claudeguard.phase,
            UpdateCheckPhase::UpToDate
        );
        assert_eq!(
            pass_view.updates.antigravity_proxy.phase,
            UpdateCheckPhase::UpToDate
        );
        assert_eq!(
            pass_view.updates.claude_msix_version.as_deref(),
            Some("5.1231.2.0")
        );
        assert_eq!(
            pass_view.updates.codex_msix_version.as_deref(),
            Some("26.1111.2228.0")
        );

        let trip = build_demo_snapshot(DemoScenario::Trip);
        let trip_view = project_console(Some(&trip), true, None, false, None, "", None);
        assert_eq!(
            trip_view.updates.antigravity_proxy.phase,
            UpdateCheckPhase::UpdateAvailable
        );
        assert_eq!(
            trip_view
                .updates
                .antigravity_proxy
                .latest_version
                .as_deref(),
            Some("2.7.0")
        );
        let codex_row = trip_view
            .agent_statuses
            .iter()
            .find(|r| r.id == "codex")
            .unwrap();
        assert!(codex_row.installed);
        assert_eq!(codex_row.orphan_count, 1);
    }
}
