//! Standalone `--demo [pass|trip|disarmed|wizard]` scenario snapshots for visual & smoke testing.
//!
//! Uses ONLY RFC 5737 test-net IPv4 addresses (`198.51.100.98`, `198.51.100.0/24`, `203.0.113.45`).

use crate::protocol::{
    AccessEvidence, AccessLevel, AgentKind, AgentRuntimeStatus, AnchorKind, AntigravityProxyState,
    AntigravityProxyStatus, ComponentUpdateStatus, Config, CutMode, DefenseCheckItem,
    DefenseSelfCheck, EnvCheck, EnvInfo, GuardSnapshot, LeakConn, LeakReport, Lifecycle, LogEntry,
    LogLevel, OnboardingOption, OnboardingProbeResult, OnboardingStrategy, OperationItemReceipt,
    OperationReceipt, OperationStatus, PolicyPreset, ProbeResult, ProtectionState, SelfCheckStatus,
    Target, TargetState, TargetStatus, TimelineBucket, TimelineStatus, TripInfo, UpdateCheckPhase,
    UpdateSummary, default_builtin_targets,
};
use crate::theme::ThemeMode;
use std::time::{SystemTime, UNIX_EPOCH};

/// Built-in interactive demo scenarios selected via `--demo <mode>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DemoScenario {
    Pass,
    Trip,
    Disarmed,
    Wizard,
}

impl DemoScenario {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "pass" | "healthy" => Some(Self::Pass),
            "trip" | "tripped" => Some(Self::Trip),
            "disarmed" | "paused" => Some(Self::Disarmed),
            "wizard" | "onboarding" => Some(Self::Wizard),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "演示模式 · 出口合规",
            Self::Trip => "演示模式 · 熔断隔离",
            Self::Disarmed => "演示模式 · 已撤防",
            Self::Wizard => "演示模式 · 首启向导",
        }
    }
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_760_000_000)
}

fn demo_config(first_run: bool) -> Config {
    let mut targets =
        default_builtin_targets(&["198.51.100.98".into()], &["US".into(), "SG".into()]);
    targets.push(Target {
        id: "custom-gemini".into(),
        name: "Gemini 地区出口".into(),
        builtin: false,
        enabled: false,
        anchor_url: "https://gemini.google.com/".into(),
        anchor_kind: AnchorKind::GeminiRegion,
        expect_ips: vec!["198.51.100.0/24".into()],
        expect_regions: vec!["US".into()],
        timeout_secs: 12,
        bind_agent: None,
    });
    Config {
        first_run,
        targets,
        guarded_agents: vec!["claude".into(), "chatgpt".into(), "antigravity".into()],
        theme_mode: ThemeMode::Auto,
        ..Config::default()
    }
}

fn demo_timeline(now: u64, scenario: DemoScenario) -> Vec<TimelineBucket> {
    let bucket_secs = 1800u32; // 48 buckets x 30m = 24h
    let aligned_now = now - (now % u64::from(bucket_secs));
    let mut out = Vec::with_capacity(48);
    for idx in 0..48u64 {
        let start = aligned_now.saturating_sub((47 - idx) * u64::from(bucket_secs));
        let (status, pass_count, warn_count, fail_count, avg_lat) = match scenario {
            DemoScenario::Wizard if idx < 44 => (TimelineStatus::Empty, 0, 0, 0, 0),
            DemoScenario::Wizard => (TimelineStatus::Warn, 0, 2, 0, 0),
            DemoScenario::Trip if idx >= 45 => (TimelineStatus::Fail, 1, 0, 3, 210),
            DemoScenario::Disarmed if idx >= 44 => (TimelineStatus::Warn, 0, 4, 0, 0),
            _ if idx < 8 => (TimelineStatus::Empty, 0, 0, 0, 0),
            _ if idx == 29 => (TimelineStatus::Warn, 10, 2, 0, 95),
            _ => (TimelineStatus::Pass, 18, 0, 0, 62 + (idx % 5) * 9),
        };
        out.push(TimelineBucket {
            bucket_start: start,
            bucket_secs,
            total_checks: pass_count + warn_count + fail_count,
            pass_count,
            warn_count,
            fail_count,
            status,
            max_latency_ms: if avg_lat > 0 { avg_lat + 24 } else { 0 },
            avg_latency_ms: avg_lat,
        });
    }
    out
}

fn demo_self_check(now: u64, tripped: bool) -> DefenseSelfCheck {
    DefenseSelfCheck {
        daemon_running: true,
        daemon_elevated: true,
        firewall_com_ready: true,
        firewall_query_ok: true,
        global_cut_ready: true,
        leak_radar_active: true,
        wal_clean: !tripped,
        wal_pending_tx: tripped.then(|| "tx-20261118-quarantine".into()),
        items: vec![
            DefenseCheckItem {
                id: "daemon".into(),
                name: "守护服务".into(),
                status: SelfCheckStatus::Healthy,
                detail: "系统守护常驻运行 · 本地状态通道响应 <1ms".into(),
            },
            DefenseCheckItem {
                id: "firewall".into(),
                name: "应用级防火墙".into(),
                status: SelfCheckStatus::Healthy,
                detail: if tripped {
                    "已核验 6 条应用隔离规则生效中".into()
                } else {
                    "防火墙规则引擎就绪 · 零弹窗即时生效".into()
                },
            },
            DefenseCheckItem {
                id: "leak".into(),
                name: "防直连泄露监测".into(),
                status: SelfCheckStatus::Healthy,
                detail: "实时监测外连状态 · 已排除 TUN 虚拟网段干扰".into(),
            },
            DefenseCheckItem {
                id: "wal".into(),
                name: "断电恢复账本".into(),
                status: if tripped {
                    SelfCheckStatus::Degraded
                } else {
                    SelfCheckStatus::Healthy
                },
                detail: if tripped {
                    "存在未结隔离事务 tx-20261118-quarantine（异常重启可自动续接还原）".into()
                } else {
                    "恢复账本状态干净 · 无异常残留".into()
                },
            },
        ],
        checked_at: now,
    }
}

fn demo_agents(tripped: bool) -> Vec<AgentRuntimeStatus> {
    vec![
        AgentRuntimeStatus {
            id: "claude".into(),
            name: "Claude 桌面版".into(),
            kind: AgentKind::Gui,
            installed: true,
            guarded: true,
            running_count: if tripped { 0 } else { 2 },
            orphan_count: if tripped { 0 } else { 1 },
            quarantined: tripped,
            firewall_rules: if tripped { 2 } else { 0 },
            install_paths: vec![r"C:\Program Files\WindowsApps\Claude_1.0.0\app\Claude.exe".into()],
        },
        AgentRuntimeStatus {
            id: "chatgpt".into(),
            name: "ChatGPT 桌面版".into(),
            kind: AgentKind::Gui,
            installed: true,
            guarded: true,
            running_count: if tripped { 0 } else { 1 },
            orphan_count: 0,
            quarantined: tripped,
            firewall_rules: if tripped { 2 } else { 0 },
            install_paths: vec![
                r"C:\Program Files\WindowsApps\OpenAI.Codex\app\ChatGPT.exe".into(),
            ],
        },
        AgentRuntimeStatus {
            id: "antigravity".into(),
            name: "反重力桌面版".into(),
            kind: AgentKind::Gui,
            installed: true,
            guarded: true,
            running_count: if tripped { 0 } else { 1 },
            orphan_count: 0,
            quarantined: tripped,
            firewall_rules: if tripped { 2 } else { 0 },
            install_paths: vec![r"D:\Program Files\Antigravity\Antigravity.exe".into()],
        },
        AgentRuntimeStatus {
            id: "claude-code".into(),
            name: "Claude Code CLI".into(),
            kind: AgentKind::Cli,
            installed: true,
            guarded: true,
            running_count: if tripped { 0 } else { 1 },
            orphan_count: if tripped { 0 } else { 1 },
            quarantined: false,
            firewall_rules: 0,
            install_paths: vec![r"C:\Users\demo\.local\bin\claude.exe".into()],
        },
        AgentRuntimeStatus {
            id: "codex".into(),
            name: "Codex CLI".into(),
            kind: AgentKind::Cli,
            installed: true,
            guarded: true,
            running_count: if tripped { 0 } else { 1 },
            orphan_count: if tripped { 1 } else { 0 },
            quarantined: false,
            firewall_rules: 0,
            install_paths: vec![r"C:\Users\demo\AppData\Roaming\npm\codex.cmd".into()],
        },
    ]
}

fn demo_logs(now: u64, scenario: DemoScenario) -> Vec<LogEntry> {
    let mut entries = vec![
        LogEntry {
            id: 101,
            timestamp: now.saturating_sub(3600),
            level: LogLevel::Info,
            category: "service".into(),
            message: "后台守护服务完成自检：应用防火墙与异常回滚引擎均就绪".into(),
        },
        LogEntry {
            id: 102,
            timestamp: now.saturating_sub(1800),
            level: LogLevel::Info,
            category: "probe".into(),
            message: "Claude 出口核验通过：US · 洛杉矶 198.51.100.98 (58ms)".into(),
        },
        LogEntry {
            id: 103,
            timestamp: now.saturating_sub(900),
            level: LogLevel::Info,
            category: "leak".into(),
            message: "直连防泄露巡检完成：受管进程 4 条代理连接，0 条直连泄露".into(),
        },
    ];
    match scenario {
        DemoScenario::Trip => {
            entries.push(LogEntry {
                id: 104,
                timestamp: now.saturating_sub(120),
                level: LogLevel::Error,
                category: "trip".into(),
                message:
                    "Claude 出口漂移至 HK 203.0.113.45（期望 US / 198.51.100.98），触发应用级熔断"
                        .into(),
            });
            entries.push(LogEntry {
                id: 105,
                timestamp: now.saturating_sub(118),
                level: LogLevel::Audit,
                category: "firewall".into(),
                message: "已终止 3 个受管桌面进程并写入 6 条应用级防火墙隔离规则（回读核验通过）".into(),
            });
            entries.push(LogEntry {
                id: 106,
                timestamp: now.saturating_sub(115),
                level: LogLevel::Warn,
                category: "ag_proxy".into(),
                message: "反重力升级至 v45.0.0 后 version.dll 被覆盖丢失，已拦截反重力安全启动"
                    .into(),
            });
        }
        DemoScenario::Disarmed => {
            entries.push(LogEntry {
                id: 104,
                timestamp: now.saturating_sub(300),
                level: LogLevel::Warn,
                category: "flow_b".into(),
                message: "用户执行流程 B：已清理全部隔离规则并恢复网络，当前处于撤防只读态".into(),
            });
        }
        DemoScenario::Wizard => {
            entries.push(LogEntry {
                id: 104,
                timestamp: now.saturating_sub(10),
                level: LogLevel::Info,
                category: "onboarding".into(),
                message:
                    "首次运行未配置：检测到代理 127.0.0.1:7890 与当前出口 US · 洛杉矶 198.51.100.98"
                        .into(),
            });
        }
        DemoScenario::Pass => {
            entries.push(LogEntry {
                id: 104,
                timestamp: now.saturating_sub(15),
                level: LogLevel::Info,
                category: "probe".into(),
                message: "全部 3 个启用目标通过（Claude / Codex / 反重力）".into(),
            });
        }
    }
    entries
}

fn demo_antigravity_proxy(now: u64, scenario: DemoScenario) -> AntigravityProxyStatus {
    match scenario {
        DemoScenario::Trip => AntigravityProxyStatus {
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
            checked_at: now.saturating_sub(12),
            summary: "反重力升级至 v45.0.0 后 version.dll 被覆盖丢失，已拦截直连风险".into(),
        },
        DemoScenario::Pass | DemoScenario::Disarmed | DemoScenario::Wizard => {
            AntigravityProxyStatus {
                state: AntigravityProxyState::Healthy,
                installed: true,
                antigravity_dir: Some(r"C:\Users\demo\AppData\Local\Programs\antigravity".into()),
                antigravity_version: Some("44.9.1".into()),
                dll_present: true,
                dll_valid: true,
                dll_size: 730_112,
                config_present: true,
                injector_version: Some("2.6.3".into()),
                proxy_type: Some("socks5".into()),
                proxy_host: Some("127.0.0.1".into()),
                proxy_port: Some(7890),
                port_matches_guard: true,
                child_injection: Some(true),
                runtime_running: scenario == DemoScenario::Pass,
                runtime_dll_loaded_main: scenario == DemoScenario::Pass,
                runtime_dll_loaded_ls: scenario == DemoScenario::Pass,
                version_changed_from: None,
                checked_at: now.saturating_sub(4),
                summary: "v2.6.3 注入生效 · socks5://127.0.0.1:7890 · language_server 内存已挂载"
                    .into(),
            }
        }
    }
}

fn demo_updates(now: u64, scenario: DemoScenario) -> UpdateSummary {
    let claudeguard = ComponentUpdateStatus {
        id: "claudeguard".into(),
        name: "ClaudeGuard 主程序".into(),
        repo: "daha1216/ClaudeGuard".into(),
        phase: UpdateCheckPhase::UpToDate,
        installed_version: Some("4.0.0".into()),
        latest_version: Some("4.0.0".into()),
        release_url: Some("https://github.com/daha1216/ClaudeGuard/releases/tag/v4.0.0".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "当前 v4.0.0 已是最新正式版本（官方签名校验已启用）".into(),
    };
    let antigravity_proxy = match scenario {
        DemoScenario::Trip => ComponentUpdateStatus {
            id: "antigravity_proxy".into(),
            name: "antigravity-proxy 注入器".into(),
            repo: "yuaotian/antigravity-proxy".into(),
            phase: UpdateCheckPhase::UpdateAvailable,
            installed_version: Some("2.6.3".into()),
            latest_version: Some("2.7.0".into()),
            release_url: Some(
                "https://github.com/yuaotian/antigravity-proxy/releases/tag/v2.7.0".into(),
            ),
            asset_url: Some(
                "https://github.com/yuaotian/antigravity-proxy/releases/download/v2.7.0/antigravity-proxy-windows-x64.zip"
                    .into(),
            ),
            checked_at: Some(now.saturating_sub(12)),
            note: "发现新版本：当前 v2.6.3 -> 最新 v2.7.0".into(),
        },
        DemoScenario::Pass | DemoScenario::Disarmed | DemoScenario::Wizard => ComponentUpdateStatus {
            id: "antigravity_proxy".into(),
            name: "antigravity-proxy 注入器".into(),
            repo: "yuaotian/antigravity-proxy".into(),
            phase: UpdateCheckPhase::UpToDate,
            installed_version: Some("2.6.3".into()),
            latest_version: Some("2.6.3".into()),
            release_url: Some(
                "https://github.com/yuaotian/antigravity-proxy/releases/tag/v2.6.3".into(),
            ),
            asset_url: None,
            checked_at: Some(now.saturating_sub(18)),
            note: "当前 v2.6.3 已是 yuaotian/antigravity-proxy 最新版".into(),
        },
    };
    let claude_desktop = ComponentUpdateStatus {
        id: "claude_desktop".into(),
        name: "Claude 桌面端".into(),
        repo: "Anthropic MSIX 官方渠道".into(),
        phase: if scenario == DemoScenario::Trip {
            UpdateCheckPhase::UpdateAvailable
        } else {
            UpdateCheckPhase::UpToDate
        },
        installed_version: Some("1.0.200".into()),
        latest_version: Some(if scenario == DemoScenario::Trip {
            "1.0.214".into()
        } else {
            "1.0.200".into()
        }),
        release_url: Some("https://claude.ai/download".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: if scenario == DemoScenario::Trip {
            "发现新版本：当前 v1.0.200 -> 最新 v1.0.214".into()
        } else {
            "当前 v1.0.200 已是最新官方版本".into()
        },
    };
    let claude_code = ComponentUpdateStatus {
        id: "claude_code".into(),
        name: "Claude Code CLI".into(),
        repo: "@anthropic-ai/claude-code".into(),
        phase: if scenario == DemoScenario::Trip {
            UpdateCheckPhase::UpdateAvailable
        } else {
            UpdateCheckPhase::UpToDate
        },
        installed_version: Some("2.1.308".into()),
        latest_version: Some(if scenario == DemoScenario::Trip {
            "2.1.320".into()
        } else {
            "2.1.308".into()
        }),
        release_url: Some("https://www.npmjs.com/package/@anthropic-ai/claude-code".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: if scenario == DemoScenario::Trip {
            "发现新版本：当前 v2.1.308 -> 最新 v2.1.320".into()
        } else {
            "当前 v2.1.308 已是最新官方版本".into()
        },
    };
    let codex_desktop = ComponentUpdateStatus {
        id: "codex_desktop".into(),
        name: "ChatGPT / Codex 桌面端".into(),
        repo: "OpenAI MSIX 官方渠道".into(),
        phase: UpdateCheckPhase::UpToDate,
        installed_version: Some("26.1111.2228.0".into()),
        latest_version: Some("26.1111.2228.0".into()),
        release_url: Some("https://chatgpt.com/download".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "当前 v26.1111.2228.0 已是最新官方版本".into(),
    };
    let codex_cli = ComponentUpdateStatus {
        id: "codex_cli".into(),
        name: "Codex CLI".into(),
        repo: "@openai/codex".into(),
        phase: UpdateCheckPhase::UpToDate,
        installed_version: Some("0.158.0".into()),
        latest_version: Some("0.158.0".into()),
        release_url: Some("https://www.npmjs.com/package/@openai/codex".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "当前 v0.158.0 已是最新官方版本".into(),
    };
    let antigravity_ide = ComponentUpdateStatus {
        id: "antigravity_ide".into(),
        name: "Antigravity 客户端".into(),
        repo: "Google 官方更新源".into(),
        phase: if scenario == DemoScenario::Trip {
            UpdateCheckPhase::UpdateAvailable
        } else {
            UpdateCheckPhase::UpToDate
        },
        installed_version: Some("2.33.0".into()),
        latest_version: Some(if scenario == DemoScenario::Trip {
            "2.34.0".into()
        } else {
            "2.33.0".into()
        }),
        release_url: Some("https://antigravity.google".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: if scenario == DemoScenario::Trip {
            "发现新版本：当前 v2.33.0 -> 最新 v2.34.0".into()
        } else {
            "当前 v2.33.0 已是最新官方版本".into()
        },
    };
    UpdateSummary {
        claudeguard,
        antigravity_proxy,
        claude_desktop,
        claude_code,
        codex_desktop,
        codex_cli,
        antigravity_ide,
        claude_msix_version: Some("5.1231.2.0".into()),
        codex_msix_version: Some("26.1111.2228.0".into()),
    }
}

/// Builds a rich synthetic snapshot for the requested [`DemoScenario`].
pub fn build_demo_snapshot(scenario: DemoScenario) -> GuardSnapshot {
    let now = now_unix_secs();
    let cfg = demo_config(scenario == DemoScenario::Wizard);
    let tripped = scenario == DemoScenario::Trip;

    let targets = match scenario {
        DemoScenario::Trip => vec![
            TargetStatus {
                id: "claude".into(),
                name: "Claude 出口".into(),
                builtin: true,
                state: TargetState::Fail,
                anchor_url: "https://claude.ai/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into()],
                ip: Some("203.0.113.45".into()),
                country: Some("HK".into()),
                raw_region: Some("HK".into()),
                colo: Some("HKG".into()),
                city: Some("香港".into()),
                latency_ms: 194,
                checked_at: Some(now.saturating_sub(12)),
                reason: "出口漂移至 HK 203.0.113.45，不在允许白名单 (US / 198.51.100.98)".into(),
                fail_streak: 2,
                matched_rule: None,
            },
            TargetStatus {
                id: "codex".into(),
                name: "Codex 出口".into(),
                builtin: true,
                state: TargetState::Fail,
                anchor_url: "https://chatgpt.com/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into()],
                ip: Some("203.0.113.45".into()),
                country: Some("HK".into()),
                raw_region: Some("HK".into()),
                colo: Some("HKG".into()),
                city: Some("香港".into()),
                latency_ms: 188,
                checked_at: Some(now.saturating_sub(12)),
                reason: "出口国家 HK 未命中白名单 US".into(),
                fail_streak: 2,
                matched_rule: None,
            },
            TargetStatus {
                id: "antigravity".into(),
                name: "反重力出口".into(),
                builtin: true,
                state: TargetState::Pass,
                anchor_url: "https://cloudcode-pa.googleapis.com/".into(),
                anchor_kind: AnchorKind::Reachability,
                expect_ips: Vec::new(),
                expect_regions: Vec::new(),
                ip: None,
                country: None,
                raw_region: None,
                colo: None,
                city: None,
                latency_ms: 81,
                checked_at: Some(now.saturating_sub(12)),
                reason: "TLS 可达 · HTTP 200".into(),
                fail_streak: 0,
                matched_rule: Some("可达性校验".into()),
            },
            TargetStatus {
                id: "local".into(),
                name: "本机出口".into(),
                builtin: true,
                state: TargetState::Disabled,
                anchor_url: "https://cloudflare.com/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into()],
                ip: None,
                country: None,
                raw_region: None,
                colo: None,
                city: None,
                latency_ms: 0,
                checked_at: None,
                reason: "未启用".into(),
                fail_streak: 0,
                matched_rule: None,
            },
        ],
        DemoScenario::Disarmed | DemoScenario::Wizard => vec![
            TargetStatus {
                id: "claude".into(),
                name: "Claude 出口".into(),
                builtin: true,
                state: TargetState::Unverified,
                anchor_url: "https://claude.ai/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into()],
                ip: Some("198.51.100.98".into()),
                country: Some("US".into()),
                raw_region: Some("US".into()),
                colo: Some("LAX".into()),
                city: Some("洛杉矶".into()),
                latency_ms: 61,
                checked_at: Some(now.saturating_sub(24)),
                reason: if scenario == DemoScenario::Wizard {
                    "首次配置未完成（仅只读预探）".into()
                } else {
                    "已撤防，仅只读展示".into()
                },
                fail_streak: 0,
                matched_rule: None,
            },
            TargetStatus {
                id: "codex".into(),
                name: "Codex 出口".into(),
                builtin: true,
                state: TargetState::Unverified,
                anchor_url: "https://chatgpt.com/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into()],
                ip: Some("198.51.100.98".into()),
                country: Some("US".into()),
                raw_region: Some("US".into()),
                colo: Some("LAX".into()),
                city: Some("洛杉矶".into()),
                latency_ms: 68,
                checked_at: Some(now.saturating_sub(24)),
                reason: "等待布防".into(),
                fail_streak: 0,
                matched_rule: None,
            },
            TargetStatus {
                id: "antigravity".into(),
                name: "反重力出口".into(),
                builtin: true,
                state: TargetState::Unverified,
                anchor_url: "https://cloudcode-pa.googleapis.com/".into(),
                anchor_kind: AnchorKind::Reachability,
                expect_ips: Vec::new(),
                expect_regions: Vec::new(),
                ip: None,
                country: None,
                raw_region: None,
                colo: None,
                city: None,
                latency_ms: 0,
                checked_at: None,
                reason: "等待布防".into(),
                fail_streak: 0,
                matched_rule: None,
            },
        ],
        DemoScenario::Pass => vec![
            TargetStatus {
                id: "claude".into(),
                name: "Claude 出口".into(),
                builtin: true,
                state: TargetState::Pass,
                anchor_url: "https://claude.ai/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into(), "SG".into()],
                ip: Some("198.51.100.98".into()),
                country: Some("US".into()),
                raw_region: Some("US".into()),
                colo: Some("LAX".into()),
                city: Some("洛杉矶".into()),
                latency_ms: 54,
                checked_at: Some(now.saturating_sub(4)),
                reason: "出口 198.51.100.98 (US · 洛杉矶) 命中规则".into(),
                fail_streak: 0,
                matched_rule: Some("地区 US + IP 198.51.100.98".into()),
            },
            TargetStatus {
                id: "codex".into(),
                name: "Codex 出口".into(),
                builtin: true,
                state: TargetState::Pass,
                anchor_url: "https://chatgpt.com/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into(), "SG".into()],
                ip: Some("198.51.100.98".into()),
                country: Some("US".into()),
                raw_region: Some("US".into()),
                colo: Some("LAX".into()),
                city: Some("洛杉矶".into()),
                latency_ms: 63,
                checked_at: Some(now.saturating_sub(4)),
                reason: "出口 198.51.100.98 (US · 洛杉矶) 命中规则".into(),
                fail_streak: 0,
                matched_rule: Some("地区 US".into()),
            },
            TargetStatus {
                id: "antigravity".into(),
                name: "反重力出口".into(),
                builtin: true,
                state: TargetState::Pass,
                anchor_url: "https://cloudcode-pa.googleapis.com/".into(),
                anchor_kind: AnchorKind::Reachability,
                expect_ips: Vec::new(),
                expect_regions: Vec::new(),
                ip: None,
                country: None,
                raw_region: None,
                colo: None,
                city: None,
                latency_ms: 72,
                checked_at: Some(now.saturating_sub(4)),
                reason: "TLS 握手可达 · HTTP 200".into(),
                fail_streak: 0,
                matched_rule: Some("可达性校验".into()),
            },
            TargetStatus {
                id: "local".into(),
                name: "本机出口".into(),
                builtin: true,
                state: TargetState::Disabled,
                anchor_url: "https://cloudflare.com/cdn-cgi/trace".into(),
                anchor_kind: AnchorKind::Auto,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into()],
                ip: None,
                country: None,
                raw_region: None,
                colo: None,
                city: None,
                latency_ms: 0,
                checked_at: None,
                reason: "未启用".into(),
                fail_streak: 0,
                matched_rule: None,
            },
        ],
    };

    let (lifecycle, protection) = match scenario {
        DemoScenario::Pass => (Lifecycle::Armed, ProtectionState::Monitoring),
        DemoScenario::Trip => (Lifecycle::Armed, ProtectionState::Quarantined),
        DemoScenario::Disarmed => (Lifecycle::Disarmed, ProtectionState::Monitoring),
        DemoScenario::Wizard => (Lifecycle::Unconfigured, ProtectionState::Pending),
    };

    let trip_info = tripped.then(|| TripInfo {
        since: now.saturating_sub(120),
        reason: "出口国家与白名单不匹配：Claude/Codex 实测漂移至 HK".into(),
        failing_ids: vec!["claude".into(), "codex".into()],
        killed: 3,
        firewall_rules: 6,
        quarantined_agents: vec!["claude".into(), "chatgpt".into(), "antigravity".into()],
        agents: vec!["Claude".into(), "ChatGPT".into(), "反重力".into()],
        network_cut: CutMode::Off,
        network_note: "应用级精准隔离（业务网络保持可用，方便切换机场节点）".into(),
        expected_summary: "地区 US / SG 或静态 IP 198.51.100.98".into(),
        observed_summary: "HK · 香港 (HKG) · 203.0.113.45".into(),
        receipt: Some(OperationReceipt {
            id: "rcpt-trip-001".into(),
            status: OperationStatus::Verified,
            items: vec![
                OperationItemReceipt {
                    name: "结束受管桌面进程".into(),
                    status: OperationStatus::Verified,
                    detail: "已终止 3 个桌面进程（进程身份二次复核通过）".into(),
                },
                OperationItemReceipt {
                    name: "应用级防火墙出站/入站隔离".into(),
                    status: OperationStatus::Verified,
                    detail: "回读确认 6 条应用隔离规则已生效".into(),
                },
            ],
            error: None,
            verified_scope: "Claude / ChatGPT / 反重力 GUI 应用级网络隔离".into(),
            remaining: Vec::new(),
        }),
    });

    let leak = if scenario == DemoScenario::Trip {
        LeakReport {
            applicable: true,
            mode: "system_proxy".into(),
            checked_at: now.saturating_sub(10),
            agent_conns: 4,
            proxied: 3,
            local: 1,
            direct: vec![LeakConn {
                pid: 48210,
                agent: "github-mcp-server.exe".into(),
                remote: "203.0.113.45".into(),
                port: 443,
                is_mcp: true,
            }],
            direct_total: 1,
            note: "发现 1 条绕过代理的直连外联，已记录诊断样本".into(),
        }
    } else {
        LeakReport {
            applicable: true,
            mode: "system_proxy".into(),
            checked_at: now.saturating_sub(4),
            agent_conns: 5,
            proxied: 5,
            local: 2,
            direct: Vec::new(),
            direct_total: 0,
            note: "全部受管连接均经 127.0.0.1:7890 代理转发，零直连泄露".into(),
        }
    };

    GuardSnapshot {
        schema_version: 4,
        version: "4.0.0".into(),
        platform: "windows".into(),
        network_isolation_supported: true,
        lifecycle,
        protection,
        cfg_rev: 3,
        runtime_epoch: 7,
        checking: false,
        checked_at: Some(now.saturating_sub(4)),
        paused_until: None,
        lockdown: false,
        lockdown_manual: false,
        preset: cfg.preset,
        theme_mode: cfg.theme_mode,
        privacy_mask_ip: cfg.privacy_mask_ip,
        config: cfg,
        targets,
        access: AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            tun_iface: None,
            route_hint: true,
            observed_at: now.saturating_sub(4),
            revision: 7,
            note: "系统代理 127.0.0.1:7890 已启用".into(),
        },
        tripped: trip_info,
        agents: demo_agents(tripped),
        antigravity_proxy: demo_antigravity_proxy(now, scenario),
        updates: demo_updates(now, scenario),
        leak,
        env: EnvCheck {
            info: EnvInfo {
                tz_key: "Pacific Standard Time".into(),
                tz_label: "(UTC-08:00) 太平洋时间".into(),
                utc_offset_min: -480,
                locale: "en-US".into(),
                lang: "en-US".into(),
                region: "US".into(),
            },
            egress_country: Some("US".into()),
            egress_colo: Some("LAX".into()),
            expect_city: Some("洛杉矶".into()),
            expect_tz: Some("Pacific Standard Time".into()),
            tz_match: Some(true),
            locale_match: Some(true),
            note: "系统时区与出口城市（洛杉矶）一致".into(),
        },
        env_applied: None,
        self_check: demo_self_check(now, tripped),
        timeline: demo_timeline(now, scenario),
        launch_error: String::new(),
        last_error: String::new(),
        last_receipt: None,
        disarmed_reason: if scenario == DemoScenario::Disarmed {
            "用户暂不使用 AI，已执行流程 B 撤防".into()
        } else {
            String::new()
        },
        recent_logs: demo_logs(now, scenario),
        recent_toasts: Vec::new(),
        feishu: crate::protocol::FeishuStatus {
            enabled: false,
            has_webhook: false,
            webhook_masked: String::new(),
            has_secret: false,
            queued: 0,
            failed: 0,
            last_sent_at: None,
            last_error: String::new(),
        },
        leak_shield: crate::protocol::LeakShieldStatus {
            enabled: true,
            quic_blocked: true,
            dns_doh_blocked: false,
            ipv6_blocked: false,
            active_rules: 4,
            summary: "已拦截 QUIC UDP:443（生效 4 条护盾规则）".into(),
        },
        mihomo: crate::protocol::MihomoStatus {
            available: true,
            controller_url: "http://127.0.0.1:9090".into(),
            core_name: "Mihomo v1.19.12".into(),
            active_group: "Proxy".into(),
            active_node: if scenario == DemoScenario::Trip {
                "HK-BGP-02".into()
            } else {
                "US-LAX-ISP-01".into()
            },
            active_delay_ms: Some(if scenario == DemoScenario::Trip { 188 } else { 58 }),
            candidates: vec![
                crate::protocol::MihomoNodeInfo {
                    name: "US-LAX-ISP-01".into(),
                    delay_ms: Some(58),
                },
                crate::protocol::MihomoNodeInfo {
                    name: "US-SJC-02".into(),
                    delay_ms: Some(64),
                },
                crate::protocol::MihomoNodeInfo {
                    name: "SG-01".into(),
                    delay_ms: Some(42),
                },
                crate::protocol::MihomoNodeInfo {
                    name: "JP-NRT-03".into(),
                    delay_ms: Some(71),
                },
            ],
            note: if scenario == DemoScenario::Trip {
                "Mihomo v1.19.12 · 组 [Proxy] 当前节点：HK-BGP-02（188ms）".into()
            } else {
                "Mihomo v1.19.12 · 组 [Proxy] 当前节点：US-LAX-ISP-01（58ms）".into()
            },
        },
    }
}

/// Builds the zero-input onboarding probe result (`US · 洛杉矶 198.51.100.98`).
pub fn build_demo_onboarding_probe(proxy_active: bool) -> OnboardingProbeResult {
    if !proxy_active {
        return OnboardingProbeResult {
            access: AccessEvidence {
                level: AccessLevel::Uncovered,
                proxy_addr: None,
                tun_iface: None,
                route_hint: false,
                observed_at: now_unix_secs(),
                revision: 1,
                note: "未检测到活跃代理或 TUN 网卡".into(),
            },
            detected_proxy_port: None,
            probe: None,
            installed_agents: vec!["claude".into(), "chatgpt".into(), "antigravity".into()],
            recommended_strategy: None,
            standby_notice: Some(
                "未检测到活跃代理（系统代理未开启且无 TUN 网卡），建议先开启代理节点后再布防，或先进入安全待命态。".into(),
            ),
            options: vec![
                OnboardingOption {
                    strategy: OnboardingStrategy::RecommendRegion,
                    recommended: true,
                    title: "推荐：允许常用合规国家（US / SG / JP）".into(),
                    subtitle: "代理启动后自动放行合规地区节点，防止意外直连真实宽带出口。".into(),
                    preset: PolicyPreset::StandardRegion,
                    expect_ips: Vec::new(),
                    expect_regions: vec!["US".into(), "SG".into(), "JP".into()],
                },
                OnboardingOption {
                    strategy: OnboardingStrategy::CustomCidrOrRegions,
                    recommended: false,
                    title: "自定义多国或 CIDR 网段".into(),
                    subtitle: "手动填写国家代码（如 US, JP）或网段（如 198.51.100.0/24）。".into(),
                    preset: PolicyPreset::StandardRegion,
                    expect_ips: Vec::new(),
                    expect_regions: vec!["US".into()],
                },
            ],
        };
    }

    OnboardingProbeResult {
        access: AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            tun_iface: None,
            route_hint: true,
            observed_at: now_unix_secs(),
            revision: 1,
            note: "已识别系统代理 127.0.0.1:7890".into(),
        },
        detected_proxy_port: Some(7890),
        probe: Some(ProbeResult {
            reachable: true,
            status: Some(200),
            ip: Some("198.51.100.98".into()),
            country: Some("US".into()),
            raw_region: Some("US".into()),
            colo: Some("LAX".into()),
            city: Some("洛杉矶".into()),
            latency_ms: 56,
            parsed_as: "trace".into(),
            detail: "US · 洛杉矶 198.51.100.98".into(),
        }),
        installed_agents: vec!["claude".into(), "chatgpt".into(), "antigravity".into()],
        recommended_strategy: Some(OnboardingStrategy::RecommendRegion),
        standby_notice: None,
        options: vec![
            OnboardingOption {
                strategy: OnboardingStrategy::RecommendRegion,
                recommended: true,
                title: "推荐：允许当前国家节点（US）".into(),
                subtitle: "机场在 US 同国多节点间负载均衡时不会误熔断，同时严防漂移到非预期地区或直连。".into(),
                preset: PolicyPreset::StandardRegion,
                expect_ips: Vec::new(),
                expect_regions: vec!["US".into()],
            },
            OnboardingOption {
                strategy: OnboardingStrategy::StrictStaticIp,
                recommended: false,
                title: "严格：仅锁定当前静态 IP（198.51.100.98）".into(),
                subtitle: "适用于独享静态住宅/ISP 节点，出口 IP 一旦变化立即触发隔离。".into(),
                preset: PolicyPreset::StrictStaticIp,
                expect_ips: vec!["198.51.100.98".into()],
                expect_regions: vec!["US".into()],
            },
            OnboardingOption {
                strategy: OnboardingStrategy::CustomCidrOrRegions,
                recommended: false,
                title: "自定义多国或 CIDR".into(),
                subtitle: "自行指定允许的国家代码（如 US, JP, SG）或 IPv4 CIDR 网段（如 198.51.100.0/24）。".into(),
                preset: PolicyPreset::StandardRegion,
                expect_ips: vec!["198.51.100.0/24".into()],
                expect_regions: vec!["US".into(), "JP".into()],
            },
        ],
    }
}
