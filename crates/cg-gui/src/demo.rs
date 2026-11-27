//! Standalone `--demo [pass|trip|disarmed|wizard]` scenario snapshots for visual & smoke testing.
//!
//! Uses ONLY RFC 5737 test-net IPv4 addresses (`198.51.100.98`, `198.51.100.0/24`, `203.0.113.45`).

use crate::protocol::{
    AccessEvidence, AccessLevel, AccountVault, AgentKind, AgentRuntimeStatus, AnchorKind,
    AntigravityProxyState, AntigravityProxyStatus, AsnClassification, BurstGuardMode,
    BurstGuardStatus, CleanRoomBackupMeta, CleanRoomFinding, CleanRoomReport, CleanRoomRiskLevel,
    CleanRoomScope, CleanRoomVector, ComponentUpdateStatus, Config, CutMode, DefenseCheckItem,
    DefenseSelfCheck, DnsCoherenceReport, ElectronHygieneReport, EnvCheck, EnvInfo,
    FirewallBackendPref, GeoVelocityAlert, GuardSnapshot, HookIntegrationStatus, HotkeyStatus,
    IpPurityReport, LeakConn, LeakReport, Lifecycle, LogEntry, LogLevel, MsixIsolationMode,
    OnboardingOption, OnboardingProbeResult, OnboardingStrategy, OperationItemReceipt,
    OperationReceipt, OperationStatus, PolicyPreset, ProbeResult, ProtectionState, RiskAssessment,
    RiskDimensionItem, SNAPSHOT_SCHEMA_VERSION, SafetyGrade, SelfCheckStatus, StunLeakReport,
    Target, TargetState, TargetStatus, TimelineBucket, TimelineStatus, TripInfo, UpdateCheckPhase,
    UpdateSummary, VaultRuntimeState, VaultRuntimeStatus, WfpBlockedEvent, WfpStatus,
    WslBridgeStatus, default_builtin_targets,
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

fn demo_vault_configs() -> Vec<AccountVault> {
    vec![
        AccountVault {
            id: "work-claude-max".into(),
            name: "Work-Max · 美国静态住宅".into(),
            accent_hex: "#5B69D0".into(),
            enabled: true,
            pinned_regions: vec!["US".into()],
            pinned_ips: vec!["198.51.100.0/24".into()],
            pinned_asn: Some(7922),
            dedicated_proxy_port: Some(7890),
            preferred_mihomo_group: Some("Proxy".into()),
            preferred_mihomo_node: Some("US-LAX-ISP-01".into()),
            auto_align_mihomo_on_vault_launch: false,
            min_safety_score: 85,
            cooldown_after_ip_change_secs: 900,
            share_ide_extensions: true,
            msix_isolation_mode: MsixIsolationMode::AutoVerifyLock,
        },
        AccountVault {
            id: "personal-jp-lab".into(),
            name: "Personal-Lab · 日本独立仓".into(),
            accent_hex: "#16A34A".into(),
            enabled: true,
            pinned_regions: vec!["JP".into(), "SG".into()],
            pinned_ips: Vec::new(),
            pinned_asn: Some(4713),
            dedicated_proxy_port: Some(7892),
            preferred_mihomo_group: Some("Proxy".into()),
            preferred_mihomo_node: Some("JP-NRT-03".into()),
            auto_align_mihomo_on_vault_launch: false,
            min_safety_score: 75,
            cooldown_after_ip_change_secs: 900,
            share_ide_extensions: true,
            msix_isolation_mode: MsixIsolationMode::ExclusiveSwapLock,
        },
    ]
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
        guarded_agents: vec![
            "claude".into(),
            "chatgpt".into(),
            "antigravity".into(),
            "cursor".into(),
        ],
        theme_mode: ThemeMode::Auto,
        firewall_backend: FirewallBackendPref::AutoWfpFirst,
        wfp_boot_guard: false,
        vaults: demo_vault_configs(),
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
            id: "cursor".into(),
            name: "Cursor IDE".into(),
            kind: AgentKind::Gui,
            installed: true,
            guarded: true,
            running_count: if tripped { 0 } else { 1 },
            orphan_count: 0,
            quarantined: tripped,
            firewall_rules: 0,
            install_paths: vec![r"C:\Users\demo\AppData\Local\Programs\cursor\Cursor.exe".into()],
        },
        AgentRuntimeStatus {
            id: "windsurf".into(),
            name: "Windsurf IDE".into(),
            kind: AgentKind::Gui,
            installed: true,
            guarded: false,
            running_count: 0,
            orphan_count: 0,
            quarantined: false,
            firewall_rules: 0,
            install_paths: vec![
                r"C:\Users\demo\AppData\Local\Programs\Windsurf\Windsurf.exe".into(),
            ],
        },
        AgentRuntimeStatus {
            id: "zed".into(),
            name: "Zed IDE".into(),
            kind: AgentKind::Gui,
            installed: true,
            guarded: false,
            running_count: 0,
            orphan_count: 0,
            quarantined: false,
            firewall_rules: 0,
            install_paths: vec![r"C:\Users\demo\AppData\Local\Programs\Zed\Zed.exe".into()],
        },
        AgentRuntimeStatus {
            id: "trae".into(),
            name: "Trae IDE".into(),
            kind: AgentKind::Gui,
            installed: false,
            guarded: false,
            running_count: 0,
            orphan_count: 0,
            quarantined: false,
            firewall_rules: 0,
            install_paths: Vec::new(),
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
        AgentRuntimeStatus {
            id: "gemini".into(),
            name: "Gemini CLI".into(),
            kind: AgentKind::Cli,
            installed: true,
            guarded: true,
            running_count: 0,
            orphan_count: 0,
            quarantined: false,
            firewall_rules: 0,
            install_paths: vec![r"C:\Users\demo\AppData\Roaming\npm\gemini.cmd".into()],
        },
        AgentRuntimeStatus {
            id: "aider".into(),
            name: "Aider CLI".into(),
            kind: AgentKind::Cli,
            installed: false,
            guarded: false,
            running_count: 0,
            orphan_count: 0,
            quarantined: false,
            firewall_rules: 0,
            install_paths: Vec::new(),
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
                message: "已终止 3 个受管桌面进程并写入 6 条应用级防火墙隔离规则（回读核验通过）"
                    .into(),
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
    let pkg_ver = env!("CARGO_PKG_VERSION");
    let claudeguard = ComponentUpdateStatus {
        id: "claudeguard".into(),
        name: "ClaudeGuard 主程序".into(),
        repo: "daha1216/ClaudeGuard".into(),
        phase: UpdateCheckPhase::UpToDate,
        installed_version: Some(pkg_ver.into()),
        latest_version: Some(pkg_ver.into()),
        release_url: Some(format!(
            "https://github.com/daha1216/ClaudeGuard/releases/tag/v{pkg_ver}"
        )),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: format!("当前 v{pkg_ver} 已是最新正式版本（官方签名校验已启用）"),
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
    let antigravity_cn = ComponentUpdateStatus {
        id: "antigravity_cn".into(),
        name: "Antigravity 中文汉化引擎".into(),
        repo: "Silas-02/antigravity-desktop-cn".into(),
        phase: UpdateCheckPhase::UpdateAvailable,
        installed_version: Some("2026.03.15".into()),
        latest_version: Some("2026.03.19".into()),
        release_url: Some("https://github.com/Silas-02/antigravity-desktop-cn".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "发现仓库新提交：本地 2026.03.15 -> 上游 2026.03.19".into(),
    };
    let ag_usage_monitor = ComponentUpdateStatus {
        id: "ag_usage_monitor".into(),
        name: "antigravity-usage-monitor".into(),
        repo: "yuhuan-dev/antigravity-usage-monitor".into(),
        phase: UpdateCheckPhase::UpdateAvailable,
        installed_version: Some("1.5.3".into()),
        latest_version: Some("1.6.0".into()),
        release_url: Some("https://github.com/yuhuan-dev/antigravity-usage-monitor".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "发现新版本：当前 v1.5.3 -> 最新 v1.6.0".into(),
    };
    let ag_capsule = ComponentUpdateStatus {
        id: "ag_capsule".into(),
        name: "agy-capsule".into(),
        repo: "Lumidarin/agy-capsule".into(),
        phase: UpdateCheckPhase::UpToDate,
        installed_version: Some("1.1.2".into()),
        latest_version: Some("1.1.2".into()),
        release_url: Some("https://github.com/Lumidarin/agy-capsule".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "当前 v1.1.2 已是最新官方版本".into(),
    };
    let cursor_ide = ComponentUpdateStatus {
        id: "cursor_ide".into(),
        name: "Cursor IDE".into(),
        repo: "Anysphere 官方渠道".into(),
        phase: UpdateCheckPhase::UpToDate,
        installed_version: Some("0.51.4".into()),
        latest_version: Some("0.51.4".into()),
        release_url: Some("https://www.cursor.com/downloads".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "当前 v0.51.4 已是最新官方版本".into(),
    };
    let windsurf_ide = ComponentUpdateStatus {
        id: "windsurf_ide".into(),
        name: "Windsurf IDE".into(),
        repo: "Codeium 官方渠道".into(),
        phase: if scenario == DemoScenario::Trip {
            UpdateCheckPhase::UpdateAvailable
        } else {
            UpdateCheckPhase::UpToDate
        },
        installed_version: Some("1.9.2".into()),
        latest_version: Some(if scenario == DemoScenario::Trip {
            "1.10.0".into()
        } else {
            "1.9.2".into()
        }),
        release_url: Some("https://windsurf.com/download".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: if scenario == DemoScenario::Trip {
            "发现新版本：当前 v1.9.2 -> 最新 v1.10.0".into()
        } else {
            "当前 v1.9.2 已是最新官方版本".into()
        },
    };
    let zed_ide = ComponentUpdateStatus {
        id: "zed_ide".into(),
        name: "Zed IDE".into(),
        repo: "zed-industries/zed".into(),
        phase: UpdateCheckPhase::UpToDate,
        installed_version: Some("0.188.3".into()),
        latest_version: Some("0.188.3".into()),
        release_url: Some("https://github.com/zed-industries/zed/releases".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "当前 v0.188.3 已是最新官方版本".into(),
    };
    let trae_ide = ComponentUpdateStatus {
        id: "trae_ide".into(),
        name: "Trae IDE".into(),
        repo: "Trae 官方渠道".into(),
        phase: UpdateCheckPhase::NotInstalled,
        installed_version: None,
        latest_version: Some("1.4.2".into()),
        release_url: Some("https://www.trae.ai/".into()),
        asset_url: None,
        checked_at: Some(now.saturating_sub(18)),
        note: "本机未检测到 Trae IDE 安装路径".into(),
    };
    UpdateSummary {
        claudeguard,
        antigravity_proxy,
        claude_desktop,
        claude_code,
        codex_desktop,
        codex_cli,
        antigravity_ide,
        antigravity_cn,
        ag_usage_monitor,
        ag_capsule,
        cursor_ide,
        windsurf_ide,
        zed_ide,
        trae_ide,
        claude_msix_version: Some("5.1231.2.0".into()),
        codex_msix_version: Some("26.1111.2228.0".into()),
    }
}

pub fn demo_cleanroom_report(now: u64, scope: &CleanRoomScope) -> CleanRoomReport {
    let mut findings = Vec::new();
    if scope.claude {
        findings.push(CleanRoomFinding {
            id: "v1-claude-json".into(),
            client_id: "claude".into(),
            vector: CleanRoomVector::ClaudeCodeState,
            risk_weight: 40,
            location_display: "%USERPROFILE%\\.claude.json & telemetry\\".into(),
            correlation_keys: vec![
                "userID".into(),
                "anonymousId".into(),
                "oauthAccount".into(),
                "cachedStatsigGates".into(),
            ],
            masked_preview: "anonymousId=anon-9f*** · 3 批未上传遥测缓存".into(),
            bytes_size: 48_320,
            preservation_note: "100% 保留 mcpServers / CLAUDE.md / settings.json / skills/".into(),
        });
        findings.push(CleanRoomFinding {
            id: "v2-claude-msix-crashpad".into(),
            client_id: "claude".into(),
            vector: CleanRoomVector::DesktopChromiumAndCrashpad,
            risk_weight: 35,
            location_display: "Packages\\Claude_*\\LocalCache\\Roaming\\Claude\\Crashpad".into(),
            correlation_keys: vec![
                "Network\\Cookies".into(),
                "Local Storage\\leveldb".into(),
                "Crashpad\\pending".into(),
            ],
            masked_preview: "Cookies + LevelDB + 2 份挂起崩溃信封".into(),
            bytes_size: 1_942_016,
            preservation_note: "100% 保留 claude_desktop_config.json (桌面 MCP 配置)".into(),
        });
        findings.push(CleanRoomFinding {
            id: "v3-win-cred-anthropic".into(),
            client_id: "claude".into(),
            vector: CleanRoomVector::WindowsCredentialManager,
            risk_weight: 15,
            location_display: "Windows 凭据管理器 (Generic)".into(),
            correlation_keys: vec!["Claude Safe Storage".into(), "claude-code-oauth".into()],
            masked_preview: "2 条 OAuth / SafeStorage 加密元数据（绝不读取明文）".into(),
            bytes_size: 1_024,
            preservation_note: "清理前自动封入 CGBAK005 加密时光机备份".into(),
        });
        findings.push(CleanRoomFinding {
            id: "v4-orphan-claude-proc".into(),
            client_id: "claude".into(),
            vector: CleanRoomVector::OrphanMemoryProcess,
            risk_weight: 10,
            location_display: "内存常驻子进程树".into(),
            correlation_keys: vec!["cowork-svc.exe".into(), "claude.exe".into()],
            masked_preview: "1 个孤儿驻留进程存在退出回写竞态风险".into(),
            bytes_size: 0,
            preservation_note: "清理第 0 步先清退进程并验证句柄释放".into(),
        });
    }
    if scope.chatgpt_codex {
        findings.push(CleanRoomFinding {
            id: "v1-codex-auth".into(),
            client_id: "chatgpt".into(),
            vector: CleanRoomVector::ClaudeCodeState,
            risk_weight: 25,
            location_display: "%USERPROFILE%\\.codex\\auth.json".into(),
            correlation_keys: vec!["auth.json".into(), "OpenAI.Codex LocalCache".into()],
            masked_preview: "已缓存 OpenAI 会话令牌与历史日志".into(),
            bytes_size: 16_384,
            preservation_note: "保留用户自定义 config.toml 与项目指令".into(),
        });
    }
    if scope.cursor {
        findings.push(CleanRoomFinding {
            id: "v2-cursor-storage".into(),
            client_id: "cursor".into(),
            vector: CleanRoomVector::DesktopChromiumAndCrashpad,
            risk_weight: 20,
            location_display: "%APPDATA%\\Cursor\\User\\globalStorage\\storage.json".into(),
            correlation_keys: vec![
                "telemetry.machineId".into(),
                "telemetry.macMachineId".into(),
                "telemetry.devDeviceId".into(),
            ],
            masked_preview: "需重置 3 项 Cursor 机器码遥测键".into(),
            bytes_size: 24_576,
            preservation_note: "100% 保留已装扩展、主题与快捷键".into(),
        });
    }
    if scope.antigravity {
        findings.push(CleanRoomFinding {
            id: "v2-ag-session".into(),
            client_id: "antigravity".into(),
            vector: CleanRoomVector::DesktopChromiumAndCrashpad,
            risk_weight: 15,
            location_display: "%APPDATA%\\Antigravity\\Network\\Cookies".into(),
            correlation_keys: vec!["Cookies".into(), "Local Storage".into()],
            masked_preview: "浏览器内核会话缓存与旧账号状态".into(),
            bytes_size: 312_000,
            preservation_note: "100% 保留 version.dll 代理注入配置与 MCP 技能".into(),
        });
    }
    if scope.windsurf {
        findings.push(CleanRoomFinding {
            id: "v2-windsurf-storage".into(),
            client_id: "windsurf".into(),
            vector: CleanRoomVector::DesktopChromiumAndCrashpad,
            risk_weight: 15,
            location_display: "%APPDATA%\\Windsurf\\User\\globalStorage\\storage.json".into(),
            correlation_keys: vec!["telemetry.machineId".into(), "Cookies".into()],
            masked_preview: "Windsurf 机器标识与会话缓存".into(),
            bytes_size: 18_432,
            preservation_note: "100% 保留扩展与工作区配置".into(),
        });
    }

    let pollution_score: u8 = findings
        .iter()
        .map(|f| u16::from(f.risk_weight))
        .sum::<u16>()
        .min(100) as u8;
    let risk_level = match pollution_score {
        0 => CleanRoomRiskLevel::Clean,
        1..=25 => CleanRoomRiskLevel::Low,
        26..=69 => CleanRoomRiskLevel::Elevated,
        _ => CleanRoomRiskLevel::CriticalChainBanRisk,
    };
    let summary = if findings.is_empty() {
        "净室复核通过 · 未发现跨号关联污染残留".into()
    } else {
        format!(
            "只读深度扫描命中 {} 项跨号关联源（污染指数 {}/100）",
            findings.len(),
            pollution_score
        )
    };
    CleanRoomReport {
        scanned_at: now,
        scope: scope.clone(),
        pollution_score,
        risk_level,
        findings,
        preserved_assets_summary: vec![
            "CLAUDE.md（全局与项目指令 100% 保留）".into(),
            "settings.json（模型偏好与 CLI Hook 100% 保留）".into(),
            "mcpServers & claude_desktop_config.json（全部 MCP 工具 100% 保留）".into(),
            "skills/ · commands/ · agents/（自定义技能与工作流 100% 保留）".into(),
        ],
        summary,
    }
}

pub fn demo_cleanroom_backups(now: u64) -> Vec<CleanRoomBackupMeta> {
    vec![
        CleanRoomBackupMeta {
            backup_id: "cgbak-20261126-2110".into(),
            created_at: now.saturating_sub(86_400),
            file_path: r"%LOCALAPPDATA%\ClaudeGuard\backups\cgbak-20261126-2110.cgbak".into(),
            archive_bytes: 214_528,
            item_count: 6,
            sha256_hex: "9f3b8c2a11d4e7054f90aa21cc0178d5a9e33b102f8c74a1".into(),
            clients_included: vec!["claude".into(), "cursor".into()],
        },
        CleanRoomBackupMeta {
            backup_id: "cgbak-20261120-0945".into(),
            created_at: now.saturating_sub(86_400 * 6),
            file_path: r"%LOCALAPPDATA%\ClaudeGuard\backups\cgbak-20261120-0945.cgbak".into(),
            archive_bytes: 142_336,
            item_count: 4,
            sha256_hex: "4a12e8b07f6690c21b33e905a170cd82ee4119fa6d0b3412".into(),
            clients_included: vec!["claude".into()],
        },
    ]
}

fn demo_wfp_status(now: u64, scenario: DemoScenario) -> WfpStatus {
    let now_ms = now.saturating_mul(1000);
    let mut recent = vec![
        WfpBlockedEvent {
            seq: 304,
            timestamp_ms: now_ms.saturating_sub(14_000),
            pid: Some(18420),
            agent_id: "claude".into(),
            app_path: "Claude.exe".into(),
            remote_ip: "198.51.100.42".into(),
            remote_port: 443,
            protocol: "udp".into(),
            layer: "ale_auth_connect_v4".into(),
            filter_reason: "quic_shield".into(),
        },
        WfpBlockedEvent {
            seq: 303,
            timestamp_ms: now_ms.saturating_sub(58_000),
            pid: Some(22910),
            agent_id: "cursor".into(),
            app_path: "Cursor.exe".into(),
            remote_ip: "203.0.113.45".into(),
            remote_port: 443,
            protocol: "tcp".into(),
            layer: "ale_auth_connect_v4".into(),
            filter_reason: "direct_nic_bypass".into(),
        },
        WfpBlockedEvent {
            seq: 302,
            timestamp_ms: now_ms.saturating_sub(182_000),
            pid: Some(15604),
            agent_id: "antigravity".into(),
            app_path: "language_server_windows_x64.exe".into(),
            remote_ip: "198.51.100.53".into(),
            remote_port: 443,
            protocol: "tcp".into(),
            layer: "ale_auth_connect_v4".into(),
            filter_reason: "doh_shield".into(),
        },
    ];
    if scenario == DemoScenario::Trip {
        recent.insert(
            0,
            WfpBlockedEvent {
                seq: 305,
                timestamp_ms: now_ms.saturating_sub(4_000),
                pid: Some(18420),
                agent_id: "claude".into(),
                app_path: "Claude.exe".into(),
                remote_ip: "203.0.113.45".into(),
                remote_port: 443,
                protocol: "tcp".into(),
                layer: "ale_auth_connect_v4".into(),
                filter_reason: "app_quarantine".into(),
            },
        );
    }
    WfpStatus {
        active_backend: "WFP 内核动态子层 (Dynamic Session)".into(),
        sublayer_registered: scenario != DemoScenario::Disarmed,
        dynamic_session_open: scenario != DemoScenario::Disarmed,
        boot_time_filters_armed: false,
        active_filter_count: if scenario == DemoScenario::Disarmed {
            0
        } else if scenario == DemoScenario::Trip {
            22
        } else {
            14
        },
        net_event_subscribed: scenario != DemoScenario::Disarmed,
        total_blocked_packets: if scenario == DemoScenario::Trip {
            27
        } else {
            12
        },
        recent_blocked: recent,
        last_error: String::new(),
    }
}

fn demo_risk_assessment(now: u64, scenario: DemoScenario) -> RiskAssessment {
    match scenario {
        DemoScenario::Trip => RiskAssessment {
            score: 28,
            grade: SafetyGrade::F,
            headline: "检测到跨洲瞬移与机房出口漂移 · 极高封号风险".into(),
            dimensions: vec![
                RiskDimensionItem {
                    id: "asn_purity".into(),
                    name: "ASN 住宅纯净度".into(),
                    max_score: 20,
                    score: 4,
                    healthy: false,
                    detail: "当前出口为云机房/VPS 段 (AS45102)".into(),
                    remediation_action: Some("切换至原生住宅 ISP 节点".into()),
                },
                RiskDimensionItem {
                    id: "abuse_score".into(),
                    name: "威胁情报欺诈值".into(),
                    max_score: 15,
                    score: 3,
                    healthy: false,
                    detail: "综合欺诈指数 78% · 邻近 /24 污染偏高".into(),
                    remediation_action: Some("更换独享静态住宅 IP".into()),
                },
                RiskDimensionItem {
                    id: "geo_velocity".into(),
                    name: "7 日时空轨迹".into(),
                    max_score: 15,
                    score: 0,
                    healthy: false,
                    detail: "7 分钟内 US→HK 位移 11,640 km（超音速瞬移）".into(),
                    remediation_action: Some("等待 15 分钟冷却或确认换仓".into()),
                },
                RiskDimensionItem {
                    id: "webrtc_stun".into(),
                    name: "WebRTC STUN 穿透".into(),
                    max_score: 10,
                    score: 0,
                    healthy: false,
                    detail: "UDP 直连暴露反射出口 CN".into(),
                    remediation_action: Some("启用 Electron 防漏参数与 WFP 护盾".into()),
                },
                RiskDimensionItem {
                    id: "dns_coherence".into(),
                    name: "DNS 地理一致性".into(),
                    max_score: 10,
                    score: 2,
                    healthy: false,
                    detail: "检测到国内递归 DNS 泄露".into(),
                    remediation_action: Some("开启阻断 DNS / DoH 直连".into()),
                },
                RiskDimensionItem {
                    id: "wfp_shield".into(),
                    name: "WFP 内核防抢跑".into(),
                    max_score: 10,
                    score: 10,
                    healthy: true,
                    detail: "动态子层已实时截停 27 个越界包".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "dual_stack".into(),
                    name: "IPv6 双栈一致性".into(),
                    max_score: 5,
                    score: 5,
                    healthy: true,
                    detail: "未发现 IPv6 旁路分流".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "electron_hygiene".into(),
                    name: "Electron 启动卫生".into(),
                    max_score: 5,
                    score: 4,
                    healthy: true,
                    detail: "QUIC / WebRTC 启动参数已注入".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "tz_locale".into(),
                    name: "时区与语言指纹".into(),
                    max_score: 5,
                    score: 0,
                    healthy: false,
                    detail: "系统时区与 HK 出口不一致".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "burst_guard".into(),
                    name: "交互速率防风控".into(),
                    max_score: 5,
                    score: 0,
                    healthy: true,
                    detail: "当前已熔断暂停".into(),
                    remediation_action: None,
                },
            ],
            recommendations: vec![
                "立即切回美国原生住宅 ISP 静态出口并等待防瞬移冷却".into(),
                "开启 DNS / DoH 护盾以消除国内递归解析泄露".into(),
            ],
            geo_velocity_alert: Some(GeoVelocityAlert {
                vault_id: Some("work-claude-max".into()),
                from_country: "US".into(),
                from_city: "洛杉矶".into(),
                to_country: "HK".into(),
                to_city: "香港".into(),
                distance_km: 11_640,
                elapsed_secs: 420,
                implied_speed_kmh: 99_771,
                cooldown_until: Some(now + 780),
            }),
            distinct_subnets_1h: 3,
            distinct_countries_24h: 2,
            ip_purity: IpPurityReport {
                ip: Some("203.0.113.45".into()),
                country: Some("HK".into()),
                city: Some("香港".into()),
                lat_tenths: Some(223),
                lon_tenths: Some(1142),
                asn: Some(45102),
                asn_org: "Datacenter Relay Hosting".into(),
                classification: AsnClassification::DatacenterHosting,
                abuse_risk_score: 78,
                abuser_score_bps: 1450,
                is_datacenter: true,
                is_proxy_or_vpn: true,
                is_tor: false,
                is_bogon_or_relay: false,
                dual_stack_split_detected: false,
                ipv6_egress_country: None,
                source_tag: "demo_intel".into(),
                checked_at: now.saturating_sub(10),
            },
            stun_leak: StunLeakReport {
                checked_at: now.saturating_sub(10),
                stun_reachable_direct: true,
                leaked: true,
                reflexive_ip: Some("203.0.113.45".into()),
                reflexive_country: Some("CN".into()),
                summary: "警告：UDP STUN 穿透暴露非代理反射 IP".into(),
            },
            dns_coherence: DnsCoherenceReport {
                checked_at: now.saturating_sub(10),
                coherent: false,
                domestic_resolver_detected: true,
                fake_ip_active: false,
                resolver_countries: vec!["CN".into(), "HK".into()],
                summary: "检测到国内递归 DNS 分流，存在域名归属泄露风险".into(),
            },
            electron_hygiene: ElectronHygieneReport {
                checked_at: now.saturating_sub(10),
                webrtc_flag_enforced: true,
                quic_disabled_flag: true,
                host_resolver_enforced: true,
                unguarded_running_agents: Vec::new(),
                summary: "Electron 防漏参数配置正常".into(),
            },
            evaluated_at: now.saturating_sub(10),
        },
        _ => RiskAssessment {
            score: 94,
            grade: SafetyGrade::S,
            headline: "原生住宅 ISP 出口纯净 · 极低封号风险".into(),
            dimensions: vec![
                RiskDimensionItem {
                    id: "asn_purity".into(),
                    name: "ASN 住宅纯净度".into(),
                    max_score: 20,
                    score: 20,
                    healthy: true,
                    detail: "AS7922 · 原生住宅 ISP (Comcast Cable)".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "abuse_score".into(),
                    name: "威胁情报欺诈值".into(),
                    max_score: 15,
                    score: 14,
                    healthy: true,
                    detail: "综合欺诈指数 2% · /24 邻段极净 (0.35%)".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "geo_velocity".into(),
                    name: "7 日时空轨迹".into(),
                    max_score: 15,
                    score: 15,
                    healthy: true,
                    detail: "0 次跨洲瞬移 · 24h 稳定单国 US".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "webrtc_stun".into(),
                    name: "WebRTC STUN 穿透".into(),
                    max_score: 10,
                    score: 10,
                    healthy: true,
                    detail: "RFC 5389 UDP STUN 实测 0 直连泄露".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "dns_coherence".into(),
                    name: "DNS 地理一致性".into(),
                    max_score: 10,
                    score: 9,
                    healthy: true,
                    detail: "远端解析 US 一致 · 无国内 DNS 泄露".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "wfp_shield".into(),
                    name: "WFP 内核防抢跑".into(),
                    max_score: 10,
                    score: 8,
                    healthy: true,
                    detail: "动态子层已激活 (14 条过滤规则)".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "dual_stack".into(),
                    name: "IPv6 双栈一致性".into(),
                    max_score: 5,
                    score: 5,
                    healthy: true,
                    detail: "无 IPv4/IPv6 出口撕裂".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "electron_hygiene".into(),
                    name: "Electron 启动卫生".into(),
                    max_score: 5,
                    score: 4,
                    healthy: true,
                    detail: "QUIC/WebRTC/HostResolver 参数已生效".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "tz_locale".into(),
                    name: "时区与语言指纹".into(),
                    max_score: 5,
                    score: 5,
                    healthy: true,
                    detail: "太平洋时间 (UTC-08:00) 与洛杉矶出口对齐".into(),
                    remediation_action: None,
                },
                RiskDimensionItem {
                    id: "burst_guard".into(),
                    name: "交互速率防风控".into(),
                    max_score: 5,
                    score: 4,
                    healthy: true,
                    detail: "4 次/分钟 · 人类自然交互节律".into(),
                    remediation_action: None,
                },
            ],
            recommendations: vec![
                "当前出口纯净度达到 S 级，建议保持静态住宅节点稳定不频繁切国".into(),
            ],
            geo_velocity_alert: None,
            distinct_subnets_1h: 1,
            distinct_countries_24h: 1,
            ip_purity: IpPurityReport {
                ip: Some("198.51.100.98".into()),
                country: Some("US".into()),
                city: Some("洛杉矶".into()),
                lat_tenths: Some(340),
                lon_tenths: Some(-1182),
                asn: Some(7922),
                asn_org: "Comcast Cable Communications".into(),
                classification: AsnClassification::IspResidential,
                abuse_risk_score: 2,
                abuser_score_bps: 35,
                is_datacenter: false,
                is_proxy_or_vpn: false,
                is_tor: false,
                is_bogon_or_relay: false,
                dual_stack_split_detected: false,
                ipv6_egress_country: None,
                source_tag: "demo_intel".into(),
                checked_at: now.saturating_sub(4),
            },
            stun_leak: StunLeakReport {
                checked_at: now.saturating_sub(4),
                stun_reachable_direct: false,
                leaked: false,
                reflexive_ip: None,
                reflexive_country: None,
                summary: "未检测到 WebRTC UDP STUN 直连反射泄露".into(),
            },
            dns_coherence: DnsCoherenceReport {
                checked_at: now.saturating_sub(4),
                coherent: true,
                domestic_resolver_detected: false,
                fake_ip_active: false,
                resolver_countries: vec!["US".into()],
                summary: "DNS 解析归属 (US) 与代理出口完全一致".into(),
            },
            electron_hygiene: ElectronHygieneReport {
                checked_at: now.saturating_sub(4),
                webrtc_flag_enforced: true,
                quic_disabled_flag: true,
                host_resolver_enforced: true,
                unguarded_running_agents: Vec::new(),
                summary: "全部运行中 Electron 客户端均携带防漏卫生参数".into(),
            },
            evaluated_at: now.saturating_sub(4),
        },
    }
}

fn demo_vault_statuses(now: u64, scenario: DemoScenario) -> Vec<VaultRuntimeStatus> {
    let tripped = scenario == DemoScenario::Trip;
    vec![
        VaultRuntimeStatus {
            id: "work-claude-max".into(),
            name: "Work-Max · 美国静态住宅".into(),
            accent_hex: "#5B69D0".into(),
            state: if tripped {
                VaultRuntimeState::EgressMismatch
            } else {
                VaultRuntimeState::ActiveRunning
            },
            running_pids: if tripped { vec![] } else { vec![18420, 19204] },
            running_apps: if tripped {
                vec![]
            } else {
                vec!["claude".into(), "claude-code".into()]
            },
            egress_matches_contract: !tripped,
            cooldown_remaining_secs: 0,
            last_active_at: Some(now.saturating_sub(180)),
            last_ip_masked: Some("198.51.*.*".into()),
            last_country: Some("US".into()),
            vault_dir: r"%LOCALAPPDATA%\ClaudeGuard\vaults\work-claude-max".into(),
            summary: if tripped {
                "当前出口 HK 与契约 (US / AS7922) 不符，已阻断启动".into()
            } else {
                "物理隔离目录与独立机器码生效 · 2 个进程运行中".into()
            },
        },
        VaultRuntimeStatus {
            id: "personal-jp-lab".into(),
            name: "Personal-Lab · 日本独立仓".into(),
            accent_hex: "#16A34A".into(),
            state: if tripped {
                VaultRuntimeState::CoolingDown
            } else {
                VaultRuntimeState::Ready
            },
            running_pids: Vec::new(),
            running_apps: Vec::new(),
            egress_matches_contract: !tripped,
            cooldown_remaining_secs: if tripped { 515 } else { 0 },
            last_active_at: Some(now.saturating_sub(3_400)),
            last_ip_masked: Some("198.51.*.*".into()),
            last_country: Some("JP".into()),
            vault_dir: r"%LOCALAPPDATA%\ClaudeGuard\vaults\personal-jp-lab".into(),
            summary: if tripped {
                "换 IP 防瞬移冷却倒计时中（08:35）".into()
            } else {
                "独立端口 :7892 · 严格 MSIX 独占锁待命就绪".into()
            },
        },
    ]
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
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        version: env!("CARGO_PKG_VERSION").into(),
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
            active_delay_ms: Some(if scenario == DemoScenario::Trip {
                188
            } else {
                58
            }),
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
        wfp: demo_wfp_status(now, scenario),
        risk_assessment: demo_risk_assessment(now, scenario),
        vaults: demo_vault_statuses(now, scenario),
        last_cleanroom_report: Some(demo_cleanroom_report(now, &CleanRoomScope::default())),
        cleanroom_backup_count: 2,
        hooks: HookIntegrationStatus {
            claude_code_hook_installed: true,
            pwsh_profile_wrapped: true,
            vault_hooks_synced_count: 2,
            total_gate_checks: 148,
            total_gate_blocks: if scenario == DemoScenario::Trip { 5 } else { 2 },
            last_gate_latency_us: 840,
            summary: "Pre-Prompt 门禁钩子已接管 Claude Code & PowerShell（平均耗时 0.84ms）".into(),
        },
        wsl_bridge: WslBridgeStatus {
            enabled: true,
            listening: scenario != DemoScenario::Disarmed,
            bound_port: Some(17891),
            token_ready: true,
            synced_distros: vec!["Ubuntu-24.04".into()],
            proxy_desync_detected: scenario == DemoScenario::Trip,
            summary: if scenario == DemoScenario::Trip {
                "警告：检测到 Ubuntu-24.04 代理环境变量与宿主机失步".into()
            } else {
                "127.0.0.1:17891 HMAC 桥接运行中 · 已同步 1 个 WSL2 发行版".into()
            },
        },
        burst_guard: BurstGuardStatus {
            mode: BurstGuardMode::WarnOnly,
            prompts_last_1m: 4,
            prompts_last_15m: 26,
            robotic_cadence_detected: false,
            unauthorized_oauth_client_detected: false,
            suspicious_processes: Vec::new(),
            summary: "当前速率 4 次/分 · 交互节律自然，未发现异常 OAuth 代理占用".into(),
        },
        hotkeys: HotkeyStatus {
            enabled: true,
            panic_lockdown_chord: "Ctrl+Alt+Shift+L".into(),
            quick_hud_chord: "Ctrl+Alt+Shift+H".into(),
            panic_registered_ok: true,
            hud_registered_ok: true,
            conflict_note: String::new(),
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
