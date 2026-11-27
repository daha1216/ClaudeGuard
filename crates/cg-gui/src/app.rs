//! Root GPUI application controller, Dual-Mode window manager (HUD + Console),
//! zero-VRAM lifecycle, background IPC polling, and Win32 tray integration.

use crate::assets::{EmbeddedAssets, brand_mark, ui_icon};
use crate::demo::DemoScenario;
use crate::ipc::{
    DaemonClient, TransportEndpoint, TransportError, launch_agent_normal_user, open_external_url,
    start_daemon_service_elevated,
};
use crate::motion::{
    DirectionalTransition, PresenceSpring, SlidingIndicatorState, rgba_with_alpha_scale,
    spring_sheet, spring_snappy, sync_windows_reduce_motion,
};
use crate::protocol::{
    ANCHOR_KINDS, AnchorKind, CleanRoomBackupMeta, CleanRoomReport, CleanRoomScope, Config,
    DEFAULT_PIPE_NAME, GuardSnapshot, Lifecycle, LogEntry, LogLevel, OnboardingProbeResult,
    OperationStatus, POLICY_PRESETS, PipeRequest, PipeResponse, PolicyPreset, SanitizedHealthCard,
    Target, UpdateCheckPhase, normalize_ip_or_cidr,
};
use crate::state::{
    ConsoleProjection, ConsoleProjectionInput, DraftStore, HudProjection, NavSection, TargetDraft,
    VaultDraft, extract_region_tokens_lossy, parse_and_validate_regions,
    project_console_from_input, project_hud, split_tokens,
};
use crate::theme::{
    THEME_MODES, THEME_STYLES, ThemeMode, ThemePalette, ThemeStyle, layout, load_saved_theme_style,
    resolve_styled_palette, save_theme_style, system_prefers_light_theme, theme_mode_label,
};
use crate::tray_win::{
    HotkeyRegistrationReport, LogicalRect, SingleInstanceOutcome, TrayChannel, TrayEvent,
    TrayHandle, TrayTone, acquire_single_instance, apply_win11_round_corners, compute_hud_bounds,
    ensure_window_on_screen, minimize_window_smooth, primary_work_area_logical,
    restore_window_if_minimized, signal_existing_tray_instance, toggle_maximize_window_smooth,
};
use crate::views;
use crate::widgets::controls::{
    float_shadow, liquid_glass_pill, offset_pane, segmented_capsule_item, segmented_capsule_track,
    spinning_ui_icon,
};
use crate::widgets::text_input::{self, ActivePaletteGlobal, DraftTextInput};
use gpui::{
    AnimationExt, App, Bounds, BoxShadow, ClipboardItem, Context, Entity, FocusHandle, Focusable,
    KeyBinding, MouseButton, ScrollHandle, SpringAnimation, StyleRefinement, TitlebarOptions,
    Transformation, UniformListScrollHandle, Window, WindowAppearance, WindowBounds,
    WindowControlArea, WindowKind, WindowOptions, actions, div, point, prelude::*, px, radians,
    relative, rgb, rgba, size,
};
use gpui_platform::application;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

const POLL_INTERVAL_ACTIVE: Duration = Duration::from_secs(2);
const POLL_INTERVAL_IDLE: Duration = Duration::from_secs(5);
const CONFIRM_WINDOW: Duration = Duration::from_secs(4);
const HUD_DISMISS_DEBOUNCE: Duration = Duration::from_millis(260);
const HEADER_HEIGHT: f32 = 32.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsoleCacheKey {
    snapshot_seq: u64,
    queried_logs_seq: u64,
    connected: bool,
    privacy_mask: bool,
    selected_bucket: Option<usize>,
    nav: NavSection,
    time_bucket: u64,
}

#[derive(Default)]
struct RequestOptions {
    ok_msg: Option<String>,
    explicit_scope: Option<ActionScope>,
    optimistic_key: Option<&'static str>,
    config_seq: Option<u64>,
    is_ui_pref_save: bool,
    clear_targets_dirty_on_ok: bool,
    clear_feishu_inputs_on_ok: bool,
}

/// Contextual one-click recovery action attached to Dynamic-Island floating toasts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToastAction {
    OpenExplorerPath(String),
    JumpAntigravityRepair,
    RearmNow,
    JumpBreaker,
    CopyText { label: &'static str, text: String },
}

/// Scoped in-flight action keys so one pending RPC doesn't disable unrelated controls or spinners.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionScope {
    RecheckAll,
    RecheckTarget(String),
    UpdatesAll,
    UpdatesComponent(String),
    ExportDiagnostics,
    RepairAntigravity,
    SyncLeakShield,
    SaveFeishu,
    TestFeishu,
    EnvAlign,
    SaveTargets,
    LaunchGate(String),
    StartService,
    Flow,
    VaultOp(String),
    CleanRoomScan,
    CleanRoomExecute,
    CleanRoomRestore,
    DeepRiskAudit,
    ConfigureHooks,
    SyncWslBridge,
    BuildHealthCard,
}

actions!([
    FocusGlobalSearch,
    FocusNextField,
    FocusPrevField,
    DismissHudWindow,
    DismissConsoleOverlay,
    SaveCurrentView,
    RefreshCurrentView,
    NavTab1,
    NavTab2,
    NavTab3,
    NavTab4,
    NavTab5,
    NavTab6,
    NavTab7,
    NavTab8,
    NavTab9
]);

/// Sub-tabs for Mode B `熔断` page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BreakerSubTab {
    #[default]
    Rules,
    Live,
}

impl BreakerSubTab {
    const fn index(self) -> usize {
        match self {
            Self::Rules => 0,
            Self::Live => 1,
        }
    }
}

/// Sub-tabs for Mode B `防漏` page (no Mihomo proxy-policy mutation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnvSubTab {
    #[default]
    Shield,
    RiskRadar,
    HooksWsl,
    Antigravity,
    Timezone,
}

impl EnvSubTab {
    const fn index(self) -> usize {
        match self {
            Self::Shield => 0,
            Self::RiskRadar => 1,
            Self::HooksWsl => 2,
            Self::Antigravity => 3,
            Self::Timezone => 4,
        }
    }
}

/// Sub-tabs for Mode B `通知` page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NotifySubTab {
    #[default]
    Events,
    Feishu,
}

impl NotifySubTab {
    const fn index(self) -> usize {
        match self {
            Self::Events => 0,
            Self::Feishu => 1,
        }
    }
}

/// Category filters inside the `Antigravity 精选插件与更新检测` modal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PluginCategory {
    #[default]
    All,
    Monitor,
    Localization,
    Proxy,
}

/// Command-line startup options for `claudeguard-gui.exe`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchArgs {
    pub start_in_tray: bool,
    pub start_hud: bool,
    pub initial_nav: NavSection,
    pub initial_subtab: Option<String>,
    pub initial_plugins_modal: bool,
    pub initial_theme: Option<ThemeMode>,
    pub endpoint: TransportEndpoint,
}

impl Default for LaunchArgs {
    fn default() -> Self {
        Self {
            start_in_tray: false,
            start_hud: false,
            initial_nav: NavSection::Overview,
            initial_subtab: None,
            initial_plugins_modal: false,
            initial_theme: None,
            endpoint: TransportEndpoint::Pipe(DEFAULT_PIPE_NAME.to_string()),
        }
    }
}

pub const USAGE: &str = concat!(
    "用法：claudeguard-gui [--tray | --hud] [--nav overview|vaults|cleanroom|targets|breaker|env|audit|updates|notify] [--subtab <name>] [--plugins] [--theme light|dark|auto] [--demo pass|trip|disarmed|wizard] [--pipe <端点>]\n",
    "\n",
    "  --tray                    启动后驻留系统托盘（0 窗口、0 VRAM），点击托盘呼出 HUD\n",
    "  --hud                     启动即打开 Mode A 快捷托盘 HUD (398x432)\n",
    "  --nav <section>           指定主控制台默认打开的页面（默认 overview）\n",
    "  --subtab <name>           指定子标签（rules|live|shield|risk|hooks|antigravity|tz|events|feishu）\n",
    "  --plugins                 启动后自动打开 Antigravity 精选插件与更新弹窗\n",
    "  --theme <mode>            初始主题覆盖：light | dark | auto\n",
    "  --demo <scenario>         独立演示模式：pass | trip | disarmed | wizard（不连接真实守护）\n",
    "  --pipe / --guardian-pipe  指定 Windows 命名管道端点（默认 \\\\.\\pipe\\ClaudeGuardV4）\n",
    "  --help                    显示帮助并退出\n",
);

pub fn parse_args(mut args: impl Iterator<Item = String>) -> Result<LaunchArgs, String> {
    let mut out = LaunchArgs::default();
    if let Ok(env_pipe) = std::env::var("CG_PIPE_NAME")
        && !env_pipe.trim().is_empty()
    {
        out.endpoint = TransportEndpoint::Pipe(env_pipe);
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Err(USAGE.to_string()),
            "--tray" => out.start_in_tray = true,
            "--hud" => out.start_hud = true,
            "--plugins" => out.initial_plugins_modal = true,
            "--subtab" => {
                let val = args
                    .next()
                    .ok_or_else(|| format!("{arg} 缺少子标签名\n{USAGE}"))?;
                out.initial_subtab = Some(val.to_ascii_lowercase());
            }
            "--theme" => {
                let val = args
                    .next()
                    .ok_or_else(|| format!("{arg} 缺少主题名\n{USAGE}"))?;
                out.initial_theme = Some(match val.to_ascii_lowercase().as_str() {
                    "light" => ThemeMode::Light,
                    "dark" => ThemeMode::Dark,
                    "auto" => ThemeMode::Auto,
                    _ => return Err(format!("未知 --theme 模式：{val}\n{USAGE}")),
                });
            }
            "--nav" => {
                let val = args
                    .next()
                    .ok_or_else(|| format!("{arg} 缺少页面名\n{USAGE}"))?;
                out.initial_nav = match val.to_ascii_lowercase().as_str() {
                    "overview" => NavSection::Overview,
                    "vaults" | "vault" => NavSection::Vaults,
                    "cleanroom" | "clean-room" => NavSection::CleanRoom,
                    "targets" => NavSection::Targets,
                    "breaker" => NavSection::Breaker,
                    "env" | "environment" => NavSection::Environment,
                    "audit" => NavSection::Audit,
                    "updates" => NavSection::Updates,
                    "notify" => NavSection::Notify,
                    _ => return Err(format!("未知 --nav 页面：{val}\n{USAGE}")),
                };
            }
            "--demo" => {
                let next = args.next().unwrap_or_else(|| "pass".to_string());
                let scenario = DemoScenario::parse(&next).ok_or_else(|| {
                    format!("未知 --demo 场景：{next}（支持 pass|trip|disarmed|wizard）\n{USAGE}")
                })?;
                out.endpoint = TransportEndpoint::Demo(scenario);
            }
            "--pipe" | "--guardian-pipe" => {
                let val = args
                    .next()
                    .ok_or_else(|| format!("{arg} 缺少管道端点名\n{USAGE}"))?;
                out.endpoint = TransportEndpoint::Pipe(val);
            }
            unknown => return Err(format!("未知参数：{unknown}\n{USAGE}")),
        }
    }
    Ok(out)
}

/// Persistent `DraftTextInput` entities held inside [`AppController`] so edits survive
/// background refreshes AND window close/reopen cycles.
pub struct InputHandles {
    pub search: Entity<DraftTextInput>,
    pub proxy_port: Entity<DraftTextInput>,
    pub interval_secs: Entity<DraftTextInput>,
    pub trip_threshold: Entity<DraftTextInput>,
    pub new_target_name: Entity<DraftTextInput>,
    pub new_target_url: Entity<DraftTextInput>,
    pub new_target_ips: Entity<DraftTextInput>,
    pub new_target_regions: Entity<DraftTextInput>,
    pub target_ips: HashMap<String, Entity<DraftTextInput>>,
    pub target_regions: HashMap<String, Entity<DraftTextInput>>,
    pub feishu_webhook: Entity<DraftTextInput>,
    pub feishu_secret: Entity<DraftTextInput>,
    pub onboarding_cidr: Entity<DraftTextInput>,
    pub onboarding_regions: Entity<DraftTextInput>,
    pub vault_id: Entity<DraftTextInput>,
    pub vault_name: Entity<DraftTextInput>,
    pub vault_regions: Entity<DraftTextInput>,
    pub vault_ips: Entity<DraftTextInput>,
    pub vault_asn: Entity<DraftTextInput>,
    pub vault_proxy_port: Entity<DraftTextInput>,
    pub vault_mihomo_group: Entity<DraftTextInput>,
    pub vault_mihomo_node: Entity<DraftTextInput>,
    pub vault_min_score: Entity<DraftTextInput>,
    pub vault_cooldown: Entity<DraftTextInput>,
}

/// Central controller entity managing daemon IPC, drafts, theme, tray, and dual windows.
pub struct AppController {
    pub client: DaemonClient,
    pub snapshot: Option<Arc<GuardSnapshot>>,
    pub snapshot_seq: u64,
    pub connected: bool,
    pub connection_err: Option<String>,
    pub theme_mode: ThemeMode,
    pub theme_style: ThemeStyle,
    pub system_prefers_light: bool,
    pub last_applied_border_rgb: Option<u32>,
    pub privacy_mask: bool,
    pub nav_section: NavSection,
    pub policy_menu_open: bool,
    pub theme_menu_open: bool,
    pub breaker_tab: BreakerSubTab,
    pub env_tab: EnvSubTab,
    pub notify_tab: NotifySubTab,
    pub open_region_picker_for: Option<String>,
    pub show_add_target_drawer: bool,
    pub show_vault_drawer: bool,
    pub cleanroom_scope: CleanRoomScope,
    pub cleanroom_selected_ids: HashSet<String>,
    pub cleanroom_report: Option<CleanRoomReport>,
    pub cleanroom_backups: Vec<CleanRoomBackupMeta>,
    pub wfp_agent_filter: Option<String>,
    pub last_health_card: Option<SanitizedHealthCard>,
    pub audit_level_filter: Option<LogLevel>,
    pub selected_log_id: Option<u64>,
    pub show_plugins_modal: bool,
    pub plugin_category: PluginCategory,
    pub selected_bucket: Option<usize>,
    pub hovered_bucket: Option<usize>,
    pub drafts: DraftStore,
    pub inputs: InputHandles,
    pub console_scroll: ScrollHandle,
    pub audit_list_scroll: UniformListScrollHandle,
    pub show_onboarding: bool,
    pub onboarding_dismissed: bool,
    pub onboarding_probe: Option<OnboardingProbeResult>,
    pub onboarding_loading: bool,
    pub onboarding_submitting: bool,
    pub onboarding_error: Option<String>,
    pub onboarding_proxy_off_sim: bool,
    pub toast: Option<(String, bool)>,
    pub toast_action: Option<ToastAction>,
    pub toast_seq: u64,
    pub busy_action: bool,
    pub in_flight: HashSet<ActionScope>,
    pub in_flight_config: Option<(u64, Config)>,
    config_patch_seq: u64,
    pub optimistic_toggles: HashMap<&'static str, bool>,
    pub pending_confirm: Option<(String, Instant)>,
    pub queried_logs: Option<Arc<[LogEntry]>>,
    pub queried_logs_seq: u64,
    pub queried_logs_total: usize,
    pub logs_loading: bool,
    pub pending_ui_prefs_ops: usize,
    pub feishu_initialized: bool,
    pub feishu_dirty: bool,
    pub last_seen_toast_seq: Option<u64>,
    pub last_tray_state: Option<(TrayTone, bool, String)>,
    pub hud_auto_dismissed_at: Option<Instant>,
    pub hud_window: Option<gpui::WindowHandle<HudWindowView>>,
    pub console_window: Option<gpui::WindowHandle<ConsoleWindowView>>,
    pub tray: Option<TrayHandle>,
    cached_console_key: Option<ConsoleCacheKey>,
    cached_console_search: String,
    cached_console_err: Option<String>,
    cached_console_proj: Option<Arc<ConsoleProjection>>,
    cached_hud_key: Option<(u64, bool, bool, u64)>,
    cached_hud_err: Option<String>,
    cached_hud_proj: Option<Arc<HudProjection>>,
}

impl AppController {
    pub fn new(args: &LaunchArgs, tray: Option<TrayHandle>, cx: &mut Context<Self>) -> Self {
        let client = DaemonClient::new(args.endpoint.clone());
        let weak = cx.entity().downgrade();

        let make_input =
            |placeholder: &'static str,
             compact: bool,
             masked: bool,
             mono: bool,
             on_edit: fn(&mut AppController, &str) -> bool,
             on_submit: Option<fn(&mut AppController, &mut Context<AppController>)>,
             cx: &mut Context<Self>|
             -> Entity<DraftTextInput> {
                let weak_cb = weak.clone();
                let weak_sub = weak.clone();
                cx.new(|cx| {
                    let mut inp = DraftTextInput::new(cx)
                        .with_placeholder(placeholder)
                        .with_compact(compact)
                        .with_masked(masked)
                        .with_monospace(mono)
                        .with_on_change(move |text, _window, cx| {
                            let _ = weak_cb.update(cx, |ctrl, cx| {
                                if on_edit(ctrl, text) {
                                    cx.notify();
                                }
                            });
                        });
                    if let Some(submit_fn) = on_submit {
                        inp = inp.with_on_submit(move |_window, cx| {
                            let _ = weak_sub.update(cx, |ctrl, cx| {
                                submit_fn(ctrl, cx);
                            });
                        });
                    }
                    inp
                })
            };

        let weak_search_submit = weak.clone();
        let search_input = cx.new(|cx| {
            let weak_cb = weak.clone();
            DraftTextInput::new(cx)
                .with_placeholder("Ctrl+K 搜索日志（Enter 检索）")
                .with_compact(true)
                .with_masked(false)
                .with_monospace(false)
                .with_on_change(move |text, _window, cx| {
                    let _ = weak_cb.update(cx, |ctrl, cx| {
                        ctrl.drafts.search_query = text.to_string();
                        ctrl.invalidate_console_cache();
                        if ctrl.nav_section == NavSection::Audit {
                            cx.notify();
                        }
                    });
                })
                .with_on_submit(move |_window, cx| {
                    let _ = weak_search_submit.update(cx, |ctrl, cx| {
                        ctrl.refresh_audit_logs(cx);
                    });
                })
        });

        let inputs = InputHandles {
            search: search_input,
            proxy_port: make_input(
                "7890",
                true,
                false,
                true,
                |ctrl, text| {
                    let was_dirty = ctrl.drafts.dirty;
                    ctrl.drafts.proxy_port = text.to_string();
                    ctrl.drafts.mark_dirty();
                    !was_dirty
                },
                Some(AppController::save_target_drafts),
                cx,
            ),
            interval_secs: make_input(
                "15",
                true,
                false,
                true,
                |ctrl, text| {
                    let was_dirty = ctrl.drafts.dirty;
                    ctrl.drafts.interval_secs = text.to_string();
                    ctrl.drafts.mark_dirty();
                    !was_dirty
                },
                Some(AppController::save_target_drafts),
                cx,
            ),
            trip_threshold: make_input(
                "2",
                true,
                false,
                true,
                |ctrl, text| {
                    let was_dirty = ctrl.drafts.dirty;
                    ctrl.drafts.trip_threshold = text.to_string();
                    ctrl.drafts.mark_dirty();
                    !was_dirty
                },
                Some(AppController::save_target_drafts),
                cx,
            ),
            new_target_name: make_input(
                "名称，如 OpenAI API",
                true,
                false,
                false,
                |ctrl, text| {
                    ctrl.drafts.new_target_name = text.to_string();
                    false
                },
                Some(AppController::add_custom_target_from_draft),
                cx,
            ),
            new_target_url: make_input(
                "https://api.openai.com/cdn-cgi/trace",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.new_target_url = text.to_string();
                    false
                },
                Some(AppController::add_custom_target_from_draft),
                cx,
            ),
            new_target_ips: make_input(
                "IP / CIDR，如 198.51.100.0/24（可选）",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.new_target_ips = text.to_string();
                    false
                },
                Some(AppController::add_custom_target_from_draft),
                cx,
            ),
            new_target_regions: make_input(
                "如 US, SG",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.new_target_regions = text.to_string();
                    true
                },
                Some(AppController::add_custom_target_from_draft),
                cx,
            ),
            target_ips: HashMap::new(),
            target_regions: HashMap::new(),
            feishu_webhook: make_input(
                "https://open.feishu.cn/open-apis/bot/v2/hook/…",
                false,
                false,
                true,
                |ctrl, text| {
                    let was_dirty = ctrl.feishu_dirty;
                    ctrl.drafts.feishu_webhook = text.to_string();
                    ctrl.feishu_dirty = true;
                    !was_dirty
                },
                Some(AppController::save_feishu_from_drafts),
                cx,
            ),
            feishu_secret: make_input(
                "加签密钥（可选）",
                false,
                true,
                true,
                |ctrl, text| {
                    let was_dirty = ctrl.feishu_dirty;
                    ctrl.drafts.feishu_secret = text.to_string();
                    ctrl.feishu_dirty = true;
                    !was_dirty
                },
                Some(AppController::save_feishu_from_drafts),
                cx,
            ),
            onboarding_cidr: make_input(
                "如 203.0.113.0/24（可选）",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.onboarding_custom_cidr = text.to_string();
                    false
                },
                Some(AppController::complete_onboarding),
                cx,
            ),
            onboarding_regions: make_input(
                "如 US, JP, SG",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.onboarding_custom_regions = text.to_string();
                    false
                },
                Some(AppController::complete_onboarding),
                cx,
            ),
            vault_id: make_input(
                "如 work-claude-max",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.id = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    ctrl.drafts.vault_validation_error = None;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_name: make_input(
                "如 主力 Max (US 住宅)",
                true,
                false,
                false,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.name = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_regions: make_input(
                "如 US, JP",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.pinned_regions_text = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_ips: make_input(
                "如 198.51.100.0/24",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.pinned_ips_text = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_asn: make_input(
                "如 7922",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.pinned_asn_text = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_proxy_port: make_input(
                "如 7892",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.dedicated_proxy_port_text = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_mihomo_group: make_input(
                "如 Proxy",
                true,
                false,
                false,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.preferred_mihomo_group = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_mihomo_node: make_input(
                "如 US-LAX-ISP-01",
                true,
                false,
                false,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.preferred_mihomo_node = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_min_score: make_input(
                "80",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.min_safety_score_text = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
            vault_cooldown: make_input(
                "900",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.vault_draft.cooldown_secs_text = text.to_string();
                    ctrl.drafts.vault_dirty = true;
                    false
                },
                Some(AppController::save_vault_draft),
                cx,
            ),
        };

        let system_prefers_light = system_prefers_light_theme();
        let initial_theme_mode = args.initial_theme.unwrap_or(ThemeMode::Auto);
        let initial_theme_style = load_saved_theme_style();
        let initial_palette = resolve_styled_palette(
            initial_theme_style,
            initial_theme_mode,
            system_prefers_light,
        );
        cx.set_global(ActivePaletteGlobal(initial_palette));

        let breaker_tab = match args.initial_subtab.as_deref() {
            Some("live") => BreakerSubTab::Live,
            _ => BreakerSubTab::Rules,
        };
        let env_tab = match args.initial_subtab.as_deref() {
            Some("risk" | "radar") => EnvSubTab::RiskRadar,
            Some("hooks" | "wsl" | "burst") => EnvSubTab::HooksWsl,
            Some("antigravity" | "ag") => EnvSubTab::Antigravity,
            Some("tz" | "timezone") => EnvSubTab::Timezone,
            _ => EnvSubTab::Shield,
        };
        let notify_tab = match args.initial_subtab.as_deref() {
            Some("feishu") => NotifySubTab::Feishu,
            _ => NotifySubTab::Events,
        };

        let mut ctrl = Self {
            client,
            snapshot: None,
            snapshot_seq: 0,
            connected: false,
            connection_err: None,
            theme_mode: initial_theme_mode,
            theme_style: initial_theme_style,
            system_prefers_light,
            last_applied_border_rgb: Some(initial_palette.frame_border),
            privacy_mask: false,
            nav_section: args.initial_nav,
            policy_menu_open: false,
            theme_menu_open: false,
            breaker_tab,
            env_tab,
            notify_tab,
            open_region_picker_for: None,
            show_add_target_drawer: false,
            show_vault_drawer: false,
            cleanroom_scope: CleanRoomScope::default(),
            cleanroom_selected_ids: HashSet::new(),
            cleanroom_report: None,
            cleanroom_backups: Vec::new(),
            wfp_agent_filter: None,
            last_health_card: None,
            audit_level_filter: None,
            selected_log_id: None,
            show_plugins_modal: args.initial_plugins_modal,
            plugin_category: PluginCategory::All,
            selected_bucket: None,
            hovered_bucket: None,
            drafts: DraftStore::default(),
            inputs,
            console_scroll: ScrollHandle::new(),
            audit_list_scroll: UniformListScrollHandle::default(),
            show_onboarding: false,
            onboarding_dismissed: false,
            onboarding_probe: None,
            onboarding_loading: false,
            onboarding_submitting: false,
            onboarding_error: None,
            onboarding_proxy_off_sim: false,
            toast: None,
            toast_action: None,
            toast_seq: 0,
            busy_action: false,
            in_flight: HashSet::new(),
            in_flight_config: None,
            config_patch_seq: 0,
            optimistic_toggles: HashMap::new(),
            pending_confirm: None,
            queried_logs: None,
            queried_logs_seq: 0,
            queried_logs_total: 0,
            logs_loading: false,
            pending_ui_prefs_ops: 0,
            feishu_initialized: false,
            feishu_dirty: false,
            last_seen_toast_seq: None,
            last_tray_state: None,
            hud_auto_dismissed_at: None,
            hud_window: None,
            console_window: None,
            tray,
            cached_console_key: None,
            cached_console_search: String::new(),
            cached_console_err: None,
            cached_console_proj: None,
            cached_hud_key: None,
            cached_hud_err: None,
            cached_hud_proj: None,
        };

        // In demo mode, hydrate synchronously on startup so frame 0 renders with rich data immediately.
        if ctrl.client.is_demo()
            && let Ok(PipeResponse::Snapshot { snapshot }) =
                ctrl.client.exchange(PipeRequest::GetSnapshot)
        {
            ctrl.apply_snapshot(*snapshot, cx);
            if let Some(forced_theme) = args.initial_theme {
                ctrl.theme_mode = forced_theme;
                ctrl.refresh_global_palette(cx);
            }
        }

        // Start non-blocking background polling loop.
        ctrl.start_polling_loop(cx);
        ctrl
    }

    pub fn palette(&self) -> &'static ThemePalette {
        resolve_styled_palette(self.theme_style, self.theme_mode, self.system_prefers_light)
    }

    pub fn invalidate_console_cache(&mut self) {
        self.cached_console_key = None;
        self.cached_console_proj = None;
    }

    pub fn invalidate_hud_cache(&mut self) {
        self.cached_hud_key = None;
        self.cached_hud_proj = None;
    }

    pub fn console_projection(&mut self) -> Arc<ConsoleProjection> {
        let time_bucket = crate::demo::now_unix_secs() / 5;
        let key = ConsoleCacheKey {
            snapshot_seq: self.snapshot_seq,
            queried_logs_seq: self.queried_logs_seq,
            connected: self.connected,
            privacy_mask: self.privacy_mask,
            selected_bucket: self.selected_bucket,
            nav: self.nav_section,
            time_bucket,
        };
        let search_matches = self.nav_section != NavSection::Audit
            || self.cached_console_search == self.drafts.search_query;
        if self.cached_console_key == Some(key)
            && search_matches
            && self.cached_console_err == self.connection_err
            && let Some(proj) = self.cached_console_proj.as_ref()
        {
            return Arc::clone(proj);
        }
        let proj = Arc::new(project_console_from_input(ConsoleProjectionInput {
            snap: self.snapshot.as_deref(),
            connected: self.connected,
            connection_err: self.connection_err.as_deref(),
            privacy_mask: self.privacy_mask,
            selected_bucket: self.selected_bucket,
            search_query: &self.drafts.search_query,
            queried_logs: self.queried_logs.as_deref(),
            include_logs: self.nav_section == NavSection::Audit,
        }));
        self.cached_console_key = Some(key);
        self.cached_console_search = self.drafts.search_query.clone();
        self.cached_console_err = self.connection_err.clone();
        self.cached_console_proj = Some(Arc::clone(&proj));
        proj
    }

    pub fn hud_projection(&mut self) -> Arc<HudProjection> {
        let time_bucket = crate::demo::now_unix_secs() / 5;
        let key = (
            self.snapshot_seq,
            self.connected,
            self.privacy_mask,
            time_bucket,
        );
        if self.cached_hud_key == Some(key)
            && self.cached_hud_err == self.connection_err
            && let Some(proj) = self.cached_hud_proj.as_ref()
        {
            return Arc::clone(proj);
        }
        let proj = Arc::new(project_hud(
            self.snapshot.as_deref(),
            self.connected,
            self.connection_err.as_deref(),
            self.privacy_mask,
        ));
        self.cached_hud_key = Some(key);
        self.cached_hud_err = self.connection_err.clone();
        self.cached_hud_proj = Some(Arc::clone(&proj));
        proj
    }

    pub fn refresh_global_palette(&mut self, cx: &mut App) {
        let palette = self.palette();
        cx.set_global(ActivePaletteGlobal(palette));
        let border_rgb = palette.frame_border;
        if self.last_applied_border_rgb != Some(border_rgb) {
            self.last_applied_border_rgb = Some(border_rgb);
            if self.hud_window.is_some() {
                apply_win11_round_corners("ClaudeGuard Quick HUD", border_rgb);
            }
            if self.console_window.is_some() {
                apply_win11_round_corners("ClaudeGuard v4", border_rgb);
            }
        }
    }

    pub fn on_window_appearance_changed(
        &mut self,
        appearance: WindowAppearance,
        cx: &mut Context<Self>,
    ) {
        let prefers_light = !matches!(
            appearance,
            WindowAppearance::Dark | WindowAppearance::VibrantDark
        );
        sync_windows_reduce_motion(cx);
        if self.system_prefers_light != prefers_light {
            self.system_prefers_light = prefers_light;
            self.refresh_global_palette(cx);
            cx.notify();
        }
    }

    pub fn cycle_theme_mode(&mut self, cx: &mut Context<Self>) {
        let next = match self.theme_mode {
            ThemeMode::Auto => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
            ThemeMode::Dark => ThemeMode::Auto,
        };
        self.set_theme_mode(next, cx);
    }

    pub fn set_theme_mode(&mut self, mode: ThemeMode, cx: &mut Context<Self>) {
        self.theme_mode = mode;
        if mode == ThemeMode::Auto {
            self.system_prefers_light = system_prefers_light_theme();
        }
        self.refresh_global_palette(cx);
        let msg = format!("主题已切换为「{}」", theme_mode_label(mode));
        if self.connected {
            self.save_ui_pref_patch(move |cfg| cfg.theme_mode = mode, msg, cx);
        } else {
            self.set_toast(msg, true, cx);
        }
        cx.notify();
    }

    pub fn set_theme_style(&mut self, style: ThemeStyle, cx: &mut Context<Self>) {
        if self.theme_style == style {
            return;
        }
        self.theme_style = style;
        save_theme_style(style);
        self.refresh_global_palette(cx);
        self.set_toast(format!("界面风格已切换为「{}」", style.label()), true, cx);
        cx.notify();
    }

    pub fn toggle_privacy_mask(&mut self, cx: &mut Context<Self>) {
        let next = !self.privacy_mask;
        self.privacy_mask = next;
        self.invalidate_console_cache();
        self.invalidate_hud_cache();
        if self.connected {
            self.save_ui_pref_patch(
                move |cfg| cfg.privacy_mask_ip = next,
                if next {
                    "已开启 IP 脱敏"
                } else {
                    "已关闭 IP 脱敏"
                }
                .to_string(),
                cx,
            );
        }
        cx.notify();
    }

    pub fn has_modal_open(&self) -> bool {
        self.show_onboarding || self.show_plugins_modal
    }

    pub fn set_nav(&mut self, section: NavSection, cx: &mut Context<Self>) {
        let changed = self.nav_section != section;
        self.nav_section = section;
        self.policy_menu_open = false;
        self.theme_menu_open = false;
        self.open_region_picker_for = None;
        self.pending_confirm = None;
        if changed {
            self.console_scroll.set_offset(point(px(0.), px(0.)));
            self.selected_log_id = None;
            self.invalidate_console_cache();
        }
        if section == NavSection::CleanRoom && self.connected && self.cleanroom_backups.is_empty() {
            self.refresh_cleanroom_backups(cx);
        }
        if section == NavSection::Audit && self.connected {
            cx.spawn(async move |this, cx| {
                cx.background_executor()
                    .timer(Duration::from_millis(430))
                    .await;
                let _ = this.update(cx, |ctrl, cx| {
                    if ctrl.nav_section == NavSection::Audit && ctrl.connected {
                        ctrl.refresh_audit_logs(cx);
                    }
                });
            })
            .detach();
        }
        cx.notify();
    }

    pub fn is_scope_busy(&self, scope: &ActionScope) -> bool {
        self.in_flight.contains(scope)
    }

    pub fn effective_toggle(&self, key: &'static str, actual: bool) -> bool {
        self.optimistic_toggles.get(key).copied().unwrap_or(actual)
    }

    pub fn is_confirm_armed(&self, key: &str) -> bool {
        self.pending_confirm
            .as_ref()
            .is_some_and(|(k, at)| k == key && at.elapsed() <= CONFIRM_WINDOW)
    }

    pub fn arm_or_consume_confirm(
        &mut self,
        key: impl Into<String>,
        cx: &mut Context<Self>,
    ) -> bool {
        let key_str = key.into();
        if self.is_confirm_armed(&key_str) {
            self.pending_confirm = None;
            cx.notify();
            return true;
        }
        let now = Instant::now();
        self.pending_confirm = Some((key_str.clone(), now));
        cx.notify();
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(CONFIRM_WINDOW).await;
            let _ = this.update(cx, |ctrl, cx| {
                if ctrl
                    .pending_confirm
                    .as_ref()
                    .is_some_and(|(k, at)| k == &key_str && *at == now)
                {
                    ctrl.pending_confirm = None;
                    cx.notify();
                }
            });
        })
        .detach();
        false
    }

    pub fn copy_to_clipboard(&mut self, text: String, label: &str, cx: &mut Context<Self>) {
        if text.trim().is_empty() {
            return;
        }
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.set_toast(format!("已复制{label}"), true, cx);
    }

    pub fn open_url_async(&mut self, url: String, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let res = cx
                .background_executor()
                .spawn(async move { open_external_url(&url) })
                .await;
            if let Err(err) = res {
                let _ = this.update(cx, |ctrl, cx| {
                    ctrl.set_toast(err, false, cx);
                });
            }
        })
        .detach();
    }

    pub fn open_path_in_explorer_async(&mut self, path: String, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let res = cx
                .background_executor()
                .spawn(async move {
                    let clean_path = path.trim().trim_matches('"').replace('/', "\\");
                    if clean_path.is_empty()
                        || clean_path.chars().any(|c| c.is_control() || c == '"')
                    {
                        return Err("路径无效，无法在资源管理器中定位".to_string());
                    }
                    #[cfg(windows)]
                    {
                        use std::os::windows::process::CommandExt;
                        std::process::Command::new("explorer.exe")
                            .raw_arg(format!("/select,\"{clean_path}\""))
                            .spawn()
                            .map(|_| ())
                            .map_err(|e| format!("无法打开资源管理器：{e}"))
                    }
                    #[cfg(not(windows))]
                    {
                        let _ = clean_path;
                        Err("仅 Windows 支持在资源管理器中定位文件".to_string())
                    }
                })
                .await;
            if let Err(err) = res {
                let _ = this.update(cx, |ctrl, cx| {
                    ctrl.set_toast(err, false, cx);
                });
            }
        })
        .detach();
    }

    pub fn clear_search_query(&mut self, cx: &mut Context<Self>) {
        self.drafts.search_query.clear();
        self.inputs
            .search
            .update(cx, |i, cx| i.set_text_silent("", cx));
        self.invalidate_console_cache();
        if self.nav_section == NavSection::Audit && self.connected {
            self.refresh_audit_logs(cx);
        }
        cx.notify();
    }

    pub fn close_floating_menus(&mut self, cx: &mut Context<Self>) {
        let mut changed = false;
        if self.policy_menu_open {
            self.policy_menu_open = false;
            changed = true;
        }
        if self.theme_menu_open {
            self.theme_menu_open = false;
            changed = true;
        }
        if self.open_region_picker_for.is_some() {
            self.open_region_picker_for = None;
            changed = true;
        }
        if changed {
            cx.notify();
        }
    }

    /// Toggles a 2-letter ISO region code in a target's visual allowlist draft (or `__new__` drawer).
    pub fn toggle_target_region(&mut self, target_id: &str, code: &str, cx: &mut Context<Self>) {
        let upper = code.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return;
        }
        if target_id == "__new__" {
            let mut list = extract_region_tokens_lossy(&self.drafts.new_target_regions);
            if let Some(pos) = list.iter().position(|c| c == &upper) {
                list.remove(pos);
            } else {
                list.push(upper);
            }
            let joined = list.join(", ");
            self.drafts.new_target_regions = joined.clone();
            self.inputs.new_target_regions.update(cx, |inp, cx| {
                inp.set_text_silent(&joined, cx);
            });
            cx.notify();
            return;
        }

        if let Some(t) = self.drafts.targets.iter_mut().find(|x| x.id == target_id) {
            let mut list = extract_region_tokens_lossy(&t.expect_regions_text);
            if let Some(pos) = list.iter().position(|c| c == &upper) {
                list.remove(pos);
            } else {
                list.push(upper);
            }
            let joined = list.join(", ");
            t.expect_regions_text = joined.clone();
            if let Some(inp) = self.inputs.target_regions.get(target_id) {
                inp.update(cx, |i, cx| i.set_text_silent(&joined, cx));
            }
            self.drafts.mark_dirty();
            cx.notify();
        }
    }

    pub fn select_timeline_bucket(
        &mut self,
        idx: usize,
        jump_to_audit: bool,
        cx: &mut Context<Self>,
    ) {
        if self.selected_bucket == Some(idx) && !jump_to_audit {
            self.selected_bucket = None;
        } else {
            self.selected_bucket = Some(idx);
        }
        if jump_to_audit {
            self.nav_section = NavSection::Audit;
        }
        if self.nav_section == NavSection::Audit && self.connected {
            self.refresh_audit_logs(cx);
        }
        cx.notify();
    }

    pub fn clear_timeline_bucket(&mut self, cx: &mut Context<Self>) {
        self.selected_bucket = None;
        if self.nav_section == NavSection::Audit && self.connected {
            self.refresh_audit_logs(cx);
        }
        cx.notify();
    }

    pub fn refresh_audit_logs(&mut self, cx: &mut Context<Self>) {
        if !self.connected && !self.client.is_demo() {
            return;
        }
        let client = self.client.clone();
        let query = {
            let trimmed = self.drafts.search_query.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        };
        let (since_ts, until_ts) = self
            .selected_bucket
            .and_then(|idx| {
                let raw = self.snapshot.as_ref()?.timeline.as_slice();
                if raw.len() == 96 {
                    let pair = raw.chunks(2).nth(idx)?;
                    let first = &pair[0];
                    let second = pair.get(1).unwrap_or(first);
                    let secs = u64::from(first.bucket_secs + second.bucket_secs);
                    Some((Some(first.bucket_start), Some(first.bucket_start + secs)))
                } else {
                    let b = raw.get(idx)?;
                    Some((
                        Some(b.bucket_start),
                        Some(b.bucket_start + u64::from(b.bucket_secs)),
                    ))
                }
            })
            .unwrap_or((None, None));

        self.logs_loading = true;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let req = PipeRequest::QueryLogs {
                since_ts,
                until_ts,
                limit: Some(250),
                query,
            };
            let res = cx
                .background_executor()
                .spawn(async move { client.exchange(req) })
                .await;

            let _ = this.update(cx, |ctrl, cx| {
                ctrl.logs_loading = false;
                match res {
                    Ok(PipeResponse::Logs { entries, total }) => {
                        ctrl.queried_logs = Some(Arc::from(entries));
                        ctrl.queried_logs_seq = ctrl.queried_logs_seq.wrapping_add(1);
                        ctrl.queried_logs_total = total;
                        ctrl.invalidate_console_cache();
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        ctrl.set_toast(message, false, cx);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        let msg = err.to_string();
                        if matches!(err, TransportError::DaemonOffline(_)) {
                            ctrl.connected = false;
                            ctrl.connection_err = Some(msg.clone());
                        }
                        ctrl.set_toast(msg, false, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn start_polling_loop(&self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            loop {
                let (client, any_window_open) = match this.read_with(cx, |ctrl, _| {
                    (
                        ctrl.client.clone(),
                        ctrl.console_window.is_some() || ctrl.hud_window.is_some(),
                    )
                }) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let res = cx
                    .background_executor()
                    .spawn(async move { client.exchange(PipeRequest::GetSnapshot) })
                    .await;

                let updated = this.update(cx, |ctrl, cx| {
                    let mut should_notify = false;
                    match res {
                        Ok(PipeResponse::Snapshot { snapshot }) => {
                            let same = ctrl.connected
                                && ctrl.snapshot.as_deref() == Some(snapshot.as_ref());
                            if !same {
                                ctrl.apply_snapshot(*snapshot, cx);
                                should_notify = true;
                            } else {
                                ctrl.sync_tray_status();
                            }
                        }
                        Ok(PipeResponse::Error { message, .. }) => {
                            let changed =
                                ctrl.connected || ctrl.connection_err.as_deref() != Some(&message);
                            ctrl.connected = false;
                            ctrl.connection_err = Some(message);
                            if changed {
                                ctrl.invalidate_console_cache();
                                ctrl.invalidate_hud_cache();
                                ctrl.sync_tray_status();
                                should_notify = true;
                            }
                        }
                        Ok(_) => {}
                        Err(err) => {
                            let msg = err.to_string();
                            let changed =
                                ctrl.connected || ctrl.connection_err.as_deref() != Some(&msg);
                            ctrl.connected = false;
                            ctrl.connection_err = Some(msg);
                            if changed {
                                ctrl.invalidate_console_cache();
                                ctrl.invalidate_hud_cache();
                                ctrl.sync_tray_status();
                                should_notify = true;
                            }
                        }
                    }
                    if should_notify {
                        cx.notify();
                    }
                });
                if updated.is_err() {
                    break;
                }
                let interval = if any_window_open {
                    POLL_INTERVAL_ACTIVE
                } else {
                    POLL_INTERVAL_IDLE
                };
                cx.background_executor().timer(interval).await;
            }
        })
        .detach();
    }

    pub fn apply_snapshot(&mut self, snapshot: GuardSnapshot, cx: &mut Context<Self>) {
        let prev_cfg_rev = self.snapshot.as_ref().map(|s| s.cfg_rev);
        self.connected = true;
        self.connection_err = None;
        if self.pending_ui_prefs_ops == 0 && prev_cfg_rev != Some(snapshot.cfg_rev) {
            self.theme_mode = snapshot.theme_mode;
            self.privacy_mask = snapshot.privacy_mask_ip;
            self.refresh_global_palette(cx);
        }
        let synced = self
            .drafts
            .sync_from_snapshot(&snapshot.config, snapshot.cfg_rev);
        if synced {
            self.sync_input_entities_from_drafts(cx);
        }
        if snapshot.lifecycle == Lifecycle::Unconfigured && !self.onboarding_dismissed {
            let was_open = self.show_onboarding;
            self.show_onboarding = true;
            if !was_open && self.onboarding_probe.is_none() && !self.onboarding_loading {
                self.probe_onboarding(cx);
            }
        } else if snapshot.lifecycle != Lifecycle::Unconfigured {
            self.show_onboarding = false;
            self.onboarding_submitting = false;
            self.onboarding_error = None;
        }
        // Relay new Session-0 daemon notifications to Session-1 Windows Action Center
        let max_toast_seq = snapshot
            .recent_toasts
            .iter()
            .map(|t| t.seq)
            .max()
            .unwrap_or(0);
        match self.last_seen_toast_seq {
            None => {
                // Seed high-water mark on first snapshot so historical events do not replay
                self.last_seen_toast_seq = Some(max_toast_seq);
            }
            Some(prev_seq) => {
                if snapshot.config.notify.enabled
                    && let Some(tray) = self.tray.as_ref()
                {
                    for ev in &snapshot.recent_toasts {
                        if ev.seq > prev_seq {
                            let is_err = matches!(
                                ev.class.as_str(),
                                "trip" | "leak" | "antigravity_proxy" | "warning"
                            );
                            tray.show_balloon(&ev.title, &ev.body, is_err);
                        }
                    }
                }
                if max_toast_seq > prev_seq {
                    self.last_seen_toast_seq = Some(max_toast_seq);
                }
            }
        }
        if !self.feishu_initialized || !self.feishu_dirty {
            self.drafts.feishu_enabled = snapshot.feishu.enabled;
            self.feishu_initialized = true;
            self.feishu_dirty = false;
        }
        if let Some(tray) = self.tray.as_ref() {
            tray.sync_hotkeys(
                snapshot.config.global_hotkeys_enabled,
                &snapshot.config.hotkey_panic_lockdown,
                &snapshot.config.hotkey_quick_hud,
            );
        }
        if let Some(report) = snapshot.last_cleanroom_report.clone() {
            self.cleanroom_report = Some(report);
        }
        self.snapshot = Some(Arc::new(snapshot));
        self.snapshot_seq = self.snapshot_seq.wrapping_add(1);
        self.invalidate_console_cache();
        self.invalidate_hud_cache();
        self.sync_tray_status();
    }

    fn sync_input_entities_from_drafts(&mut self, cx: &mut Context<Self>) {
        let port = self.drafts.proxy_port.clone();
        let interval = self.drafts.interval_secs.clone();
        let thresh = self.drafts.trip_threshold.clone();
        self.inputs
            .proxy_port
            .update(cx, |i, cx| i.set_text_silent(&port, cx));
        self.inputs
            .interval_secs
            .update(cx, |i, cx| i.set_text_silent(&interval, cx));
        self.inputs
            .trip_threshold
            .update(cx, |i, cx| i.set_text_silent(&thresh, cx));

        let weak = cx.entity().downgrade();
        let targets = self.drafts.targets.clone();
        self.inputs
            .target_ips
            .retain(|id, _| targets.iter().any(|t| &t.id == id));
        self.inputs
            .target_regions
            .retain(|id, _| targets.iter().any(|t| &t.id == id));

        for td in targets {
            let id_ip = td.id.clone();
            let weak_ip = weak.clone();
            let weak_ip_sub = weak.clone();
            let ip_entity = self
                .inputs
                .target_ips
                .entry(td.id.clone())
                .or_insert_with(|| {
                    cx.new(|cx| {
                        DraftTextInput::new(cx)
                            .with_placeholder("如 198.51.100.0/24（逗号分隔）")
                            .with_compact(true)
                            .with_monospace(true)
                            .with_on_change(move |text, _window, cx| {
                                let _ = weak_ip.update(cx, |ctrl, cx| {
                                    let was_dirty = ctrl.drafts.dirty;
                                    if let Some(row) =
                                        ctrl.drafts.targets.iter_mut().find(|r| r.id == id_ip)
                                    {
                                        row.expect_ips_text = text.to_string();
                                        ctrl.drafts.mark_dirty();
                                        if !was_dirty {
                                            cx.notify();
                                        }
                                    }
                                });
                            })
                            .with_on_submit(move |_window, cx| {
                                let _ = weak_ip_sub.update(cx, |ctrl, cx| {
                                    ctrl.save_target_drafts(cx);
                                });
                            })
                    })
                });
            ip_entity.update(cx, |i, cx| i.set_text_silent(&td.expect_ips_text, cx));

            let id_reg = td.id.clone();
            let weak_reg = weak.clone();
            let weak_reg_sub = weak.clone();
            let reg_entity = self
                .inputs
                .target_regions
                .entry(td.id.clone())
                .or_insert_with(|| {
                    cx.new(|cx| {
                        DraftTextInput::new(cx)
                            .with_placeholder("如 IE, SE, HK")
                            .with_compact(true)
                            .with_monospace(true)
                            .with_on_change(move |text, _window, cx| {
                                let _ = weak_reg.update(cx, |ctrl, cx| {
                                    if let Some(row) =
                                        ctrl.drafts.targets.iter_mut().find(|r| r.id == id_reg)
                                    {
                                        row.expect_regions_text = text.to_string();
                                        ctrl.drafts.mark_dirty();
                                        cx.notify();
                                    }
                                });
                            })
                            .with_on_submit(move |_window, cx| {
                                let _ = weak_reg_sub.update(cx, |ctrl, cx| {
                                    ctrl.save_target_drafts(cx);
                                });
                            })
                    })
                });
            reg_entity.update(cx, |i, cx| i.set_text_silent(&td.expect_regions_text, cx));
        }
    }

    fn sync_tray_status(&mut self) {
        if self.tray.is_none() {
            return;
        }
        let now = crate::demo::now_unix_secs();
        let proj = self.hud_projection();
        let paused = self.snapshot.as_ref().is_some_and(|s| s.is_paused_at(now));
        let tone = TrayTone::from(proj.hero.tone);
        let tip = if proj.safety_evaluated {
            let vault_seg = proj
                .active_vault_name
                .as_deref()
                .map(|v| format!("活跃仓: {v} | "))
                .unwrap_or_default();
            format!(
                "ClaudeGuard v5 · {}分 {}级\n{vault_seg}WFP拦截: {} | {}",
                proj.safety_score,
                proj.safety_grade.code(),
                proj.wfp_blocked_total,
                proj.hero.title
            )
        } else {
            format!("ClaudeGuard v5 · {}", proj.hero.title)
        };
        let next_state = (tone, paused, tip.clone());
        if self.last_tray_state.as_ref() == Some(&next_state) {
            return;
        }
        self.last_tray_state = Some(next_state);
        if let Some(tray) = self.tray.as_ref() {
            tray.set_status(tone, paused, &tip);
        }
    }

    pub fn set_toast(&mut self, msg: impl Into<String>, ok: bool, cx: &mut Context<Self>) {
        self.set_toast_with_action(msg, ok, None, cx);
    }

    pub fn set_toast_with_path(
        &mut self,
        msg: impl Into<String>,
        ok: bool,
        action_path: Option<String>,
        cx: &mut Context<Self>,
    ) {
        self.set_toast_with_action(msg, ok, action_path.map(ToastAction::OpenExplorerPath), cx);
    }

    pub fn set_toast_with_action(
        &mut self,
        msg: impl Into<String>,
        ok: bool,
        action: Option<ToastAction>,
        cx: &mut Context<Self>,
    ) {
        self.toast_seq = self.toast_seq.wrapping_add(1);
        let seq = self.toast_seq;
        self.toast = Some((msg.into(), ok));
        self.toast_action = action;
        cx.notify();

        let timeout = if self.toast_action.is_some() {
            Duration::from_millis(8500)
        } else if ok {
            Duration::from_millis(3500)
        } else {
            Duration::from_millis(6000)
        };
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(timeout).await;
            let _ = this.update(cx, |ctrl, cx| {
                if ctrl.toast_seq == seq {
                    ctrl.toast = None;
                    ctrl.toast_action = None;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn scope_for_request(req: &PipeRequest) -> Option<ActionScope> {
        match req {
            PipeRequest::RecheckNow { target_id: None } => Some(ActionScope::RecheckAll),
            PipeRequest::RecheckNow {
                target_id: Some(id),
            } => Some(ActionScope::RecheckTarget(id.clone())),
            PipeRequest::CheckUpdates { component: None } => Some(ActionScope::UpdatesAll),
            PipeRequest::CheckUpdates { component: Some(c) } => {
                Some(ActionScope::UpdatesComponent(c.clone()))
            }
            PipeRequest::ExportDiagnostics => Some(ActionScope::ExportDiagnostics),
            PipeRequest::RepairAntigravityProxy => Some(ActionScope::RepairAntigravity),
            PipeRequest::SyncLeakShield => Some(ActionScope::SyncLeakShield),
            PipeRequest::SaveFeishuConfig { .. } => Some(ActionScope::SaveFeishu),
            PipeRequest::TestFeishu { .. } => Some(ActionScope::TestFeishu),
            PipeRequest::ApplyEnvAlignment { .. } | PipeRequest::RollbackEnvAlignment => {
                Some(ActionScope::EnvAlign)
            }
            PipeRequest::RecoverSafeFlowA
            | PipeRequest::DisarmAndRestoreFlowB { .. }
            | PipeRequest::Rearm
            | PipeRequest::SetManualLockdown { .. }
            | PipeRequest::TriggerPanicLockdown => Some(ActionScope::Flow),
            PipeRequest::UpsertVault { vault } => Some(ActionScope::VaultOp(vault.id.clone())),
            PipeRequest::DeleteVault { vault_id, .. }
            | PipeRequest::LaunchVault { vault_id, .. }
            | PipeRequest::StopVault { vault_id }
            | PipeRequest::GenerateVaultShortcuts { vault_id } => {
                Some(ActionScope::VaultOp(vault_id.clone()))
            }
            PipeRequest::ScanCleanRoom { .. } => Some(ActionScope::CleanRoomScan),
            PipeRequest::ExecuteCleanRoom { .. } => Some(ActionScope::CleanRoomExecute),
            PipeRequest::RestoreCleanRoomBackup { .. } => Some(ActionScope::CleanRoomRestore),
            PipeRequest::RunDeepRiskAudit => Some(ActionScope::DeepRiskAudit),
            PipeRequest::ConfigureCliHooks { .. } => Some(ActionScope::ConfigureHooks),
            PipeRequest::SyncWslBridge => Some(ActionScope::SyncWslBridge),
            PipeRequest::BuildHealthCard { .. } => Some(ActionScope::BuildHealthCard),
            _ => None,
        }
    }

    pub fn send_request(
        &mut self,
        req: PipeRequest,
        ok_msg: Option<&'static str>,
        cx: &mut Context<Self>,
    ) {
        self.send_request_inner(
            req,
            RequestOptions {
                ok_msg: ok_msg.map(str::to_string),
                ..RequestOptions::default()
            },
            cx,
        );
    }

    pub fn send_request_msg(
        &mut self,
        req: PipeRequest,
        ok_msg: Option<String>,
        cx: &mut Context<Self>,
    ) {
        self.send_request_inner(
            req,
            RequestOptions {
                ok_msg,
                ..RequestOptions::default()
            },
            cx,
        );
    }

    fn send_request_inner(
        &mut self,
        req: PipeRequest,
        opts: RequestOptions,
        cx: &mut Context<Self>,
    ) {
        let RequestOptions {
            ok_msg,
            explicit_scope,
            optimistic_key,
            config_seq,
            is_ui_pref_save,
            clear_targets_dirty_on_ok,
            clear_feishu_inputs_on_ok,
        } = opts;
        let is_export = matches!(req, PipeRequest::ExportDiagnostics);
        let scope = explicit_scope.or_else(|| Self::scope_for_request(&req));
        let client = self.client.clone();
        self.busy_action = true;
        if let Some(sc) = scope.clone() {
            self.in_flight.insert(sc);
        }
        if is_ui_pref_save {
            self.pending_ui_prefs_ops = self.pending_ui_prefs_ops.saturating_add(1);
        }
        cx.notify();

        cx.spawn(async move |this, cx| {
            let res = cx
                .background_executor()
                .spawn(async move { client.exchange(req) })
                .await;

            let _ = this.update(cx, |ctrl, cx| {
                if let Some(sc) = scope.as_ref() {
                    ctrl.in_flight.remove(sc);
                }
                if let Some(opt_k) = optimistic_key {
                    ctrl.optimistic_toggles.remove(opt_k);
                }
                if let Some(seq) = config_seq
                    && ctrl
                        .in_flight_config
                        .as_ref()
                        .is_some_and(|(cur, _)| *cur == seq)
                {
                    ctrl.in_flight_config = None;
                }
                if is_ui_pref_save {
                    ctrl.pending_ui_prefs_ops = ctrl.pending_ui_prefs_ops.saturating_sub(1);
                }
                ctrl.busy_action = !ctrl.in_flight.is_empty();
                match res {
                    Ok(PipeResponse::Snapshot { snapshot }) => {
                        if clear_targets_dirty_on_ok {
                            ctrl.drafts.dirty = false;
                            ctrl.drafts.validation_error = None;
                        }
                        if clear_feishu_inputs_on_ok {
                            ctrl.clear_feishu_draft_inputs(cx);
                        }
                        ctrl.apply_snapshot(*snapshot, cx);
                        if let Some(msg) = ok_msg {
                            ctrl.set_toast(msg, true, cx);
                        }
                    }
                    Ok(PipeResponse::Ack { receipt, snapshot }) => {
                        let hard_failed = receipt
                            .as_ref()
                            .is_some_and(|rc| rc.status == OperationStatus::Failed);
                        if !hard_failed {
                            if clear_targets_dirty_on_ok {
                                ctrl.drafts.dirty = false;
                                ctrl.drafts.validation_error = None;
                            }
                            if clear_feishu_inputs_on_ok {
                                ctrl.clear_feishu_draft_inputs(cx);
                            }
                        }
                        if let Some(snap) = snapshot {
                            ctrl.apply_snapshot(*snap, cx);
                        }
                        if let Some(ref rc) = receipt
                            && rc.status == OperationStatus::Failed
                        {
                            let detail = rc
                                .error
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .unwrap_or_else(|| format!("操作未通过：{}", rc.verified_scope));
                            ctrl.set_toast(detail, false, cx);
                        } else if let Some(ref rc) = receipt
                            && rc.status == OperationStatus::Partial
                        {
                            let detail = rc
                                .error
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .unwrap_or_else(|| {
                                    format!("已完成可用项，部分未通过：{}", rc.verified_scope)
                                });
                            ctrl.set_toast(detail, false, cx);
                        } else if is_export
                            && let Some(path) = receipt
                                .as_ref()
                                .map(|r| r.verified_scope.trim().to_string())
                                .filter(|p| !p.is_empty())
                        {
                            ctrl.set_toast_with_path(
                                format!("已导出脱敏诊断包：{path}"),
                                true,
                                Some(path),
                                cx,
                            );
                        } else if let Some(msg) = ok_msg {
                            ctrl.set_toast(msg, true, cx);
                        }
                    }
                    Ok(PipeResponse::CleanRoomScan { report }) => {
                        ctrl.cleanroom_report = Some(*report);
                        ctrl.cleanroom_selected_ids.clear();
                        if let Some(msg) = ok_msg {
                            ctrl.set_toast(msg, true, cx);
                        }
                    }
                    Ok(PipeResponse::CleanRoomBackups { backups }) => {
                        ctrl.cleanroom_backups = backups;
                        if let Some(msg) = ok_msg {
                            ctrl.set_toast(msg, true, cx);
                        }
                    }
                    Ok(PipeResponse::HealthCard { mut card }) => {
                        let md = card.markdown_snippet.clone();
                        cx.write_to_clipboard(ClipboardItem::new_string(md));
                        let saved = card.saved_png_path.clone().or_else(|| {
                            let is_dark = ctrl.palette().is_dark;
                            crate::health_card::export_health_card_png(
                                &mut card,
                                ctrl.snapshot.as_deref(),
                                is_dark,
                                None,
                            )
                            .ok()
                            .map(|p| p.to_string_lossy().into_owned())
                        });
                        ctrl.last_health_card = Some(*card);
                        if let Some(path) = saved {
                            ctrl.set_toast_with_path(
                                "已生成零隐私泄露体检卡 PNG 并复制 Markdown 到剪贴板",
                                true,
                                Some(path),
                                cx,
                            );
                        } else {
                            ctrl.set_toast("已复制脱敏防封体检卡 Markdown 到剪贴板", true, cx);
                        }
                    }
                    Ok(PipeResponse::FastGateVerdict {
                        allowed, reason, ..
                    }) => {
                        ctrl.set_toast(reason, allowed, cx);
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        ctrl.set_toast(message, false, cx);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        let msg = err.to_string();
                        if matches!(err, TransportError::DaemonOffline(_)) {
                            ctrl.connected = false;
                            ctrl.connection_err = Some(msg.clone());
                            ctrl.invalidate_console_cache();
                            ctrl.invalidate_hud_cache();
                            ctrl.sync_tray_status();
                        }
                        ctrl.set_toast(msg, false, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn clear_feishu_draft_inputs(&mut self, cx: &mut Context<Self>) {
        self.drafts.feishu_webhook.clear();
        self.drafts.feishu_secret.clear();
        self.drafts.feishu_clear_secret = false;
        self.feishu_dirty = false;
        self.inputs
            .feishu_webhook
            .update(cx, |i, cx| i.set_text_silent("", cx));
        self.inputs
            .feishu_secret
            .update(cx, |i, cx| i.set_text_silent("", cx));
    }

    pub fn save_feishu_from_drafts(&mut self, cx: &mut Context<Self>) {
        let webhook_raw = self.drafts.feishu_webhook.trim().to_string();
        let secret_raw = self.drafts.feishu_secret.trim().to_string();
        let webhook = (!webhook_raw.is_empty()).then_some(webhook_raw);
        let secret = (!secret_raw.is_empty()).then_some(secret_raw);
        let enabled = self.drafts.feishu_enabled;
        let clear_secret = self.drafts.feishu_clear_secret;
        self.send_request_inner(
            PipeRequest::SaveFeishuConfig {
                enabled,
                webhook,
                secret,
                clear_secret,
            },
            RequestOptions {
                ok_msg: Some("飞书配置已加密保存".into()),
                explicit_scope: Some(ActionScope::SaveFeishu),
                clear_feishu_inputs_on_ok: true,
                ..RequestOptions::default()
            },
            cx,
        );
    }

    pub fn reset_feishu_drafts(&mut self, cx: &mut Context<Self>) {
        self.drafts.feishu_enabled = self.snapshot.as_ref().is_some_and(|s| s.feishu.enabled);
        self.clear_feishu_draft_inputs(cx);
        self.set_toast("已撤销未保存的飞书配置改动", true, cx);
        cx.notify();
    }

    fn base_config_for_patch(&self) -> Option<Config> {
        self.in_flight_config
            .as_ref()
            .map(|(_, cfg)| cfg.clone())
            .or_else(|| self.snapshot.as_ref().map(|s| s.config.clone()))
    }

    fn record_in_flight_config(&mut self, cfg: &Config) -> u64 {
        self.config_patch_seq = self.config_patch_seq.wrapping_add(1);
        let seq = self.config_patch_seq;
        self.in_flight_config = Some((seq, cfg.clone()));
        seq
    }

    fn save_ui_pref_patch(
        &mut self,
        mutate: impl FnOnce(&mut Config) + Send + 'static,
        ok_msg: String,
        cx: &mut Context<Self>,
    ) {
        let Some(mut cfg) = self.base_config_for_patch() else {
            return;
        };
        mutate(&mut cfg);
        let seq = self.record_in_flight_config(&cfg);
        self.send_request_inner(
            PipeRequest::SaveConfig { config: cfg },
            RequestOptions {
                ok_msg: Some(ok_msg),
                config_seq: Some(seq),
                is_ui_pref_save: true,
                ..RequestOptions::default()
            },
            cx,
        );
    }

    pub fn save_config_patch(
        &mut self,
        mutate: impl FnOnce(&mut Config) + Send + 'static,
        ok_msg: &'static str,
        cx: &mut Context<Self>,
    ) {
        self.save_config_patch_msg(mutate, ok_msg.to_string(), cx);
    }

    pub fn save_config_patch_msg(
        &mut self,
        mutate: impl FnOnce(&mut Config) + Send + 'static,
        ok_msg: String,
        cx: &mut Context<Self>,
    ) {
        let Some(mut cfg) = self.base_config_for_patch() else {
            return;
        };
        mutate(&mut cfg);
        let seq = self.record_in_flight_config(&cfg);
        self.send_request_inner(
            PipeRequest::SaveConfig { config: cfg },
            RequestOptions {
                ok_msg: Some(ok_msg),
                config_seq: Some(seq),
                ..RequestOptions::default()
            },
            cx,
        );
    }

    pub fn save_toggle_patch(
        &mut self,
        key: &'static str,
        next: bool,
        mutate: impl FnOnce(&mut Config) + Send + 'static,
        ok_msg: &'static str,
        cx: &mut Context<Self>,
    ) {
        let Some(mut cfg) = self.base_config_for_patch() else {
            return;
        };
        mutate(&mut cfg);
        let seq = self.record_in_flight_config(&cfg);
        self.optimistic_toggles.insert(key, next);
        self.send_request_inner(
            PipeRequest::SaveConfig { config: cfg },
            RequestOptions {
                ok_msg: Some(ok_msg.to_string()),
                optimistic_key: Some(key),
                config_seq: Some(seq),
                ..RequestOptions::default()
            },
            cx,
        );
    }

    pub fn save_target_drafts(&mut self, cx: &mut Context<Self>) {
        let Some(base) = self.base_config_for_patch() else {
            self.set_toast("尚未收到守护快照，无法保存", false, cx);
            return;
        };
        match self.drafts.build_updated_config(&base) {
            Ok(next_cfg) => {
                self.drafts.validation_error = None;
                let seq = self.record_in_flight_config(&next_cfg);
                self.send_request_inner(
                    PipeRequest::SaveConfig { config: next_cfg },
                    RequestOptions {
                        ok_msg: Some("目标与白名单配置已保存".into()),
                        explicit_scope: Some(ActionScope::SaveTargets),
                        config_seq: Some(seq),
                        clear_targets_dirty_on_ok: true,
                        ..RequestOptions::default()
                    },
                    cx,
                );
            }
            Err(err) => {
                self.drafts.validation_error = Some(err.clone());
                self.set_toast(err, false, cx);
            }
        }
    }

    /// Saves unsaved target drafts first (when `dirty == true`) and immediately triggers
    /// `RecheckNow` on `target_id` so probes never run against stale saved rules.
    pub fn save_and_recheck_target(
        &mut self,
        target_id: String,
        target_name: String,
        cx: &mut Context<Self>,
    ) {
        if !self.drafts.dirty {
            self.send_request_msg(
                PipeRequest::RecheckNow {
                    target_id: Some(target_id),
                },
                Some(format!("已重检：{target_name}")),
                cx,
            );
            return;
        }

        let Some(base) = self.base_config_for_patch() else {
            self.set_toast("尚未收到守护快照，无法保存并重检", false, cx);
            return;
        };
        let next_cfg = match self.drafts.build_updated_config(&base) {
            Ok(cfg) => cfg,
            Err(err) => {
                self.drafts.validation_error = Some(err.clone());
                self.set_toast(err, false, cx);
                return;
            }
        };

        self.drafts.validation_error = None;
        let seq = self.record_in_flight_config(&next_cfg);
        let save_scope = ActionScope::SaveTargets;
        let rc_scope = ActionScope::RecheckTarget(target_id.clone());
        self.in_flight.insert(save_scope.clone());
        self.in_flight.insert(rc_scope.clone());
        self.busy_action = true;
        let client = self.client.clone();
        cx.notify();

        cx.spawn(async move |this, cx| {
            let outcome = cx
                .background_executor()
                .spawn(async move {
                    let save_res = client.exchange(PipeRequest::SaveConfig { config: next_cfg })?;
                    if let PipeResponse::Error { .. } = save_res {
                        return Ok((save_res, None));
                    }
                    if let PipeResponse::Ack {
                        receipt: Some(ref rc),
                        ..
                    } = save_res
                        && rc.status == OperationStatus::Failed
                    {
                        return Ok((save_res, None));
                    }
                    let rc_res = client.exchange(PipeRequest::RecheckNow {
                        target_id: Some(target_id),
                    })?;
                    Ok::<_, TransportError>((save_res, Some(rc_res)))
                })
                .await;

            let _ = this.update(cx, |ctrl, cx| {
                ctrl.in_flight.remove(&save_scope);
                ctrl.in_flight.remove(&rc_scope);
                if ctrl
                    .in_flight_config
                    .as_ref()
                    .is_some_and(|(cur, _)| *cur == seq)
                {
                    ctrl.in_flight_config = None;
                }
                ctrl.busy_action = !ctrl.in_flight.is_empty();

                match outcome {
                    Ok((save_resp, recheck_opt)) => match save_resp {
                        PipeResponse::Error { message, .. } => {
                            ctrl.set_toast(message, false, cx);
                        }
                        PipeResponse::Ack {
                            receipt: Some(rc),
                            snapshot,
                        } if rc.status == OperationStatus::Failed => {
                            if let Some(snap) = snapshot {
                                ctrl.apply_snapshot(*snap, cx);
                            }
                            let detail = rc
                                .error
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| format!("保存未通过：{}", rc.verified_scope));
                            ctrl.set_toast(detail, false, cx);
                        }
                        other_save => {
                            ctrl.drafts.dirty = false;
                            ctrl.drafts.validation_error = None;
                            match recheck_opt {
                                Some(PipeResponse::Snapshot { snapshot })
                                | Some(PipeResponse::Ack {
                                    snapshot: Some(snapshot),
                                    ..
                                }) => {
                                    ctrl.apply_snapshot(*snapshot, cx);
                                    ctrl.set_toast(
                                        format!("已保存并重检：{target_name}"),
                                        true,
                                        cx,
                                    );
                                }
                                Some(PipeResponse::Error { message, .. }) => {
                                    ctrl.set_toast(message, false, cx);
                                }
                                _ => {
                                    if let PipeResponse::Ack {
                                        snapshot: Some(snap),
                                        ..
                                    }
                                    | PipeResponse::Snapshot { snapshot: snap } = other_save
                                    {
                                        ctrl.apply_snapshot(*snap, cx);
                                    }
                                    ctrl.set_toast(
                                        format!("已保存并重检：{target_name}"),
                                        true,
                                        cx,
                                    );
                                }
                            }
                        }
                    },
                    Err(err) => {
                        let msg = err.to_string();
                        if matches!(err, TransportError::DaemonOffline(_)) {
                            ctrl.connected = false;
                            ctrl.connection_err = Some(msg.clone());
                            ctrl.invalidate_console_cache();
                            ctrl.invalidate_hud_cache();
                            ctrl.sync_tray_status();
                        }
                        ctrl.set_toast(msg, false, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn reset_target_drafts(&mut self, cx: &mut Context<Self>) {
        if let Some(snap) = self.snapshot.clone() {
            self.drafts.force_load(&snap.config, snap.cfg_rev);
            self.sync_input_entities_from_drafts(cx);
            self.set_toast("已还原为当前生效配置", true, cx);
        }
    }

    pub fn add_custom_target_from_draft(&mut self, cx: &mut Context<Self>) {
        let name = self.drafts.new_target_name.trim().to_string();
        let url = self.drafts.new_target_url.trim().to_string();
        let raw_ips = split_tokens(&self.drafts.new_target_ips);

        if name.is_empty() {
            let err = "请填写新目标名称".to_string();
            self.drafts.validation_error = Some(err.clone());
            self.set_toast(err, false, cx);
            return;
        }
        if name.chars().count() > 16 {
            let err = "新目标名称不能超过 16 个字符".to_string();
            self.drafts.validation_error = Some(err.clone());
            self.set_toast(err, false, cx);
            return;
        }
        if !url.starts_with("https://") {
            let err = "探测地址须以 https:// 开头".to_string();
            self.drafts.validation_error = Some(err.clone());
            self.set_toast(err, false, cx);
            return;
        }
        let mut ips = Vec::with_capacity(raw_ips.len());
        for raw in raw_ips {
            let Some(norm) = normalize_ip_or_cidr(&raw) else {
                let err = format!("无效的 IP 或 CIDR：「{raw}」");
                self.drafts.validation_error = Some(err.clone());
                self.set_toast(err, false, cx);
                return;
            };
            if !ips.contains(&norm) {
                ips.push(norm);
            }
        }
        let regions = match parse_and_validate_regions(&self.drafts.new_target_regions) {
            Ok(regs) => regs,
            Err(err) => {
                self.drafts.validation_error = Some(err.clone());
                self.set_toast(err, false, cx);
                return;
            }
        };
        if ips.is_empty() && regions.is_empty() {
            let err = "请至少填写 1 个允许地区或静态 IP / CIDR".to_string();
            self.drafts.validation_error = Some(err.clone());
            self.set_toast(err, false, cx);
            return;
        }

        let id = format!(
            "custom-{}",
            crate::demo::now_unix_secs() % 1_000_000 + self.drafts.targets.len() as u64
        );
        let target = Target {
            id,
            name,
            builtin: false,
            enabled: true,
            anchor_url: url,
            anchor_kind: AnchorKind::Auto,
            expect_ips: ips,
            expect_regions: regions,
            timeout_secs: 12,
            bind_agent: None,
        };
        self.drafts.targets.push(TargetDraft::from_target(&target));
        self.drafts.new_target_name.clear();
        self.drafts.new_target_url.clear();
        self.drafts.new_target_ips.clear();
        self.drafts.new_target_regions.clear();
        self.inputs
            .new_target_name
            .update(cx, |i, cx| i.set_text_silent("", cx));
        self.inputs
            .new_target_url
            .update(cx, |i, cx| i.set_text_silent("", cx));
        self.inputs
            .new_target_ips
            .update(cx, |i, cx| i.set_text_silent("", cx));
        self.inputs
            .new_target_regions
            .update(cx, |i, cx| i.set_text_silent("", cx));
        self.show_add_target_drawer = false;
        self.drafts.mark_dirty();
        self.drafts.validation_error = None;
        self.sync_input_entities_from_drafts(cx);
        self.set_toast("已加入草稿，点「保存配置」生效", true, cx);
    }

    pub fn start_daemon_service(&mut self, cx: &mut Context<Self>) {
        if self.client.is_demo() || self.is_scope_busy(&ActionScope::StartService) {
            return;
        }
        let client = self.client.clone();
        self.in_flight.insert(ActionScope::StartService);
        self.busy_action = true;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let start_res = cx
                .background_executor()
                .spawn(async move { start_daemon_service_elevated() })
                .await;

            if let Err(err) = start_res {
                let _ = this.update(cx, |ctrl, cx| {
                    ctrl.in_flight.remove(&ActionScope::StartService);
                    ctrl.busy_action = !ctrl.in_flight.is_empty();
                    ctrl.set_toast_with_action(
                        err,
                        false,
                        Some(ToastAction::CopyText {
                            label: "复制启动命令",
                            text: "Start-Service ClaudeGuardService".into(),
                        }),
                        cx,
                    );
                    cx.notify();
                });
                return;
            }

            let mut recovered: Option<GuardSnapshot> = None;
            for _ in 0..6 {
                cx.background_executor()
                    .timer(Duration::from_millis(500))
                    .await;
                let poll_client = client.clone();
                let res = cx
                    .background_executor()
                    .spawn(async move { poll_client.exchange(PipeRequest::GetSnapshot) })
                    .await;
                if let Ok(PipeResponse::Snapshot { snapshot }) = res {
                    recovered = Some(*snapshot);
                    break;
                }
            }

            let _ = this.update(cx, |ctrl, cx| {
                ctrl.in_flight.remove(&ActionScope::StartService);
                ctrl.busy_action = !ctrl.in_flight.is_empty();
                if let Some(snap) = recovered {
                    ctrl.apply_snapshot(snap, cx);
                    if ctrl.show_onboarding && ctrl.onboarding_probe.is_none() {
                        ctrl.probe_onboarding(cx);
                    }
                    ctrl.set_toast("守护服务已启动并成功连接", true, cx);
                } else {
                    ctrl.set_toast_with_action(
                        "已发起服务启动，若仍未就绪可复制命令在管理员终端执行",
                        false,
                        Some(ToastAction::CopyText {
                            label: "复制启动命令",
                            text: "Start-Service ClaudeGuardService".into(),
                        }),
                        cx,
                    );
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn delete_target_draft(&mut self, id: &str, cx: &mut Context<Self>) {
        let before = self.drafts.targets.len();
        self.drafts.targets.retain(|t| t.builtin || t.id != id);
        if self.drafts.targets.len() < before {
            self.drafts.mark_dirty();
            self.sync_input_entities_from_drafts(cx);
            cx.notify();
        }
    }

    pub fn toggle_target_draft_enabled(&mut self, id: &str, cx: &mut Context<Self>) {
        if let Some(row) = self.drafts.targets.iter_mut().find(|r| r.id == id) {
            row.enabled = !row.enabled;
            self.drafts.mark_dirty();
            cx.notify();
        }
    }

    pub fn cycle_target_draft_kind(&mut self, id: &str, cx: &mut Context<Self>) {
        if let Some(row) = self.drafts.targets.iter_mut().find(|r| r.id == id) {
            let idx = ANCHOR_KINDS
                .iter()
                .position(|k| *k == row.anchor_kind)
                .unwrap_or(0);
            row.anchor_kind = ANCHOR_KINDS[(idx + 1) % ANCHOR_KINDS.len()];
            self.drafts.mark_dirty();
            cx.notify();
        }
    }

    pub fn toggle_agent_guarded(&mut self, agent_id: &str, cx: &mut Context<Self>) {
        let id = agent_id.to_string();
        self.save_config_patch(
            move |cfg| {
                if let Some(pos) = cfg.guarded_agents.iter().position(|a| a == &id) {
                    cfg.guarded_agents.remove(pos);
                } else {
                    cfg.guarded_agents.push(id);
                }
            },
            "受管对象清单已更新",
            cx,
        );
    }

    pub fn launch_app_with_gate(
        &mut self,
        agent_id: String,
        install_paths: Vec<String>,
        cx: &mut Context<Self>,
    ) {
        if !self.connected && !self.client.is_demo() {
            self.set_toast_with_action(
                "守护未连接 · 安全闭锁，禁止启动受管 AI 客户端",
                false,
                Some(ToastAction::CopyText {
                    label: "复制启动命令",
                    text: "Start-Service ClaudeGuardService".into(),
                }),
                cx,
            );
            return;
        }
        let scope = ActionScope::LaunchGate(agent_id.clone());
        if self.is_scope_busy(&scope) {
            return;
        }
        let client = self.client.clone();
        self.in_flight.insert(scope.clone());
        self.busy_action = true;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let req = PipeRequest::CheckLaunchGate {
                agent_id: Some(agent_id.clone()),
            };
            let res = cx
                .background_executor()
                .spawn(async move { client.exchange(req) })
                .await;

            let _ = this.update(cx, |ctrl, cx| {
                match res {
                    Ok(PipeResponse::LaunchGate {
                        allowed,
                        reason,
                        snapshot,
                    }) => {
                        if let Some(snap) = snapshot {
                            ctrl.apply_snapshot(*snap, cx);
                        }
                        if allowed {
                            if ctrl.client.is_demo() {
                                ctrl.in_flight.remove(&scope);
                                ctrl.busy_action = !ctrl.in_flight.is_empty();
                                ctrl.set_toast(
                                    format!("[演示] 门禁放行：将以普通用户权限启动 {agent_id}"),
                                    true,
                                    cx,
                                );
                            } else {
                                let aid_bg = agent_id.clone();
                                let paths_bg = install_paths.clone();
                                let scope_bg = scope.clone();
                                cx.spawn(async move |this_l, cx| {
                                    let launch_res = cx
                                        .background_executor()
                                        .spawn(async move {
                                            launch_agent_normal_user(&aid_bg, &paths_bg)
                                        })
                                        .await;
                                    let _ = this_l.update(cx, |c, cx| {
                                        c.in_flight.remove(&scope_bg);
                                        c.busy_action = !c.in_flight.is_empty();
                                        match launch_res {
                                            Ok(msg) => c.set_toast(msg, true, cx),
                                            Err(err) => c.set_toast(err, false, cx),
                                        }
                                        cx.notify();
                                    });
                                })
                                .detach();
                            }
                        } else {
                            ctrl.in_flight.remove(&scope);
                            ctrl.busy_action = !ctrl.in_flight.is_empty();
                            let recovery_action =
                                ctrl.suggest_launch_block_action(&agent_id, &reason);
                            ctrl.set_toast_with_action(
                                format!("启动门禁拦截：{reason}"),
                                false,
                                recovery_action,
                                cx,
                            );
                        }
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        ctrl.in_flight.remove(&scope);
                        ctrl.busy_action = !ctrl.in_flight.is_empty();
                        ctrl.set_toast(message, false, cx);
                    }
                    Ok(_) => {
                        ctrl.in_flight.remove(&scope);
                        ctrl.busy_action = !ctrl.in_flight.is_empty();
                    }
                    Err(err) => {
                        ctrl.in_flight.remove(&scope);
                        ctrl.busy_action = !ctrl.in_flight.is_empty();
                        ctrl.set_toast(err.to_string(), false, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn suggest_launch_block_action(&self, agent_id: &str, reason: &str) -> Option<ToastAction> {
        if let Some(snap) = self.snapshot.as_ref() {
            if agent_id == "antigravity"
                && snap.config.require_antigravity_proxy
                && snap.antigravity_proxy.installed
                && !snap.antigravity_proxy.is_ready_for_launch()
            {
                return Some(ToastAction::JumpAntigravityRepair);
            }
            if snap.lifecycle == Lifecycle::Disarmed {
                return Some(ToastAction::RearmNow);
            }
            if snap.is_tripped() {
                return Some(ToastAction::JumpBreaker);
            }
        }
        if reason.contains("注入") || reason.contains("version.dll") {
            Some(ToastAction::JumpAntigravityRepair)
        } else if reason.contains("撤防") {
            Some(ToastAction::RearmNow)
        } else if reason.contains("熔断") || reason.contains("隔离") {
            Some(ToastAction::JumpBreaker)
        } else {
            None
        }
    }

    fn hydrate_onboarding_custom_from_probe(
        &mut self,
        probe: &OnboardingProbeResult,
        cx: &mut Context<Self>,
    ) {
        let custom_opt = probe
            .options
            .iter()
            .find(|o| o.strategy == crate::protocol::OnboardingStrategy::CustomCidrOrRegions);
        let suggested_cidr = custom_opt
            .and_then(|o| o.expect_ips.first().cloned())
            .or_else(|| {
                probe
                    .probe
                    .as_ref()
                    .and_then(|p| p.ip.as_deref())
                    .and_then(|ip| {
                        let parts: Vec<&str> = ip.split('.').collect();
                        (parts.len() == 4)
                            .then(|| format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
                    })
            })
            .unwrap_or_default();
        let suggested_regions = custom_opt
            .filter(|o| !o.expect_regions.is_empty())
            .map(|o| o.expect_regions.join(", "))
            .or_else(|| {
                probe
                    .probe
                    .as_ref()
                    .and_then(|p| p.country.as_deref())
                    .filter(|c| !c.is_empty())
                    .map(|c| c.to_ascii_uppercase())
            })
            .unwrap_or_default();

        if self.drafts.onboarding_custom_cidr.trim().is_empty() && !suggested_cidr.is_empty() {
            self.drafts.onboarding_custom_cidr = suggested_cidr.clone();
            self.inputs
                .onboarding_cidr
                .update(cx, |i, cx| i.set_text_silent(&suggested_cidr, cx));
        }
        if self.drafts.onboarding_custom_regions.trim().is_empty() && !suggested_regions.is_empty()
        {
            self.drafts.onboarding_custom_regions = suggested_regions.clone();
            self.inputs
                .onboarding_regions
                .update(cx, |i, cx| i.set_text_silent(&suggested_regions, cx));
        }
    }

    pub fn probe_onboarding(&mut self, cx: &mut Context<Self>) {
        self.onboarding_error = None;
        if self.client.is_demo() {
            let probe = crate::demo::build_demo_onboarding_probe(!self.onboarding_proxy_off_sim);
            if let Some(rec) = probe.recommended_strategy {
                self.drafts.onboarding_strategy = rec;
            } else if let Some(first) = probe.options.first() {
                self.drafts.onboarding_strategy = first.strategy;
            }
            self.hydrate_onboarding_custom_from_probe(&probe, cx);
            self.onboarding_probe = Some(probe);
            self.onboarding_loading = false;
            cx.notify();
            return;
        }

        let client = self.client.clone();
        self.onboarding_loading = true;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let res = cx
                .background_executor()
                .spawn(async move { client.exchange(PipeRequest::ProbeOnboarding) })
                .await;

            let _ = this.update(cx, |ctrl, cx| {
                ctrl.onboarding_loading = false;
                match res {
                    Ok(PipeResponse::OnboardingProbe { probe }) => {
                        if let Some(rec) = probe.recommended_strategy {
                            ctrl.drafts.onboarding_strategy = rec;
                        } else if let Some(first) = probe.options.first() {
                            ctrl.drafts.onboarding_strategy = first.strategy;
                        }
                        ctrl.hydrate_onboarding_custom_from_probe(&probe, cx);
                        ctrl.onboarding_probe = Some(probe);
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        let msg = format!("向导环境探测失败：{message}");
                        ctrl.onboarding_error = Some(msg.clone());
                        ctrl.set_toast(msg, false, cx);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        let msg = err.to_string();
                        if matches!(err, TransportError::DaemonOffline(_)) {
                            ctrl.connected = false;
                            ctrl.connection_err = Some(msg.clone());
                        }
                        ctrl.onboarding_error = Some(msg.clone());
                        ctrl.set_toast(msg, false, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn complete_onboarding(&mut self, cx: &mut Context<Self>) {
        if self.onboarding_submitting {
            return;
        }
        let base = self
            .snapshot
            .as_ref()
            .map(|s| s.config.clone())
            .unwrap_or_default();
        let Some(probe) = self.onboarding_probe.as_ref() else {
            self.onboarding_error = Some("正在探测本机环境，请稍候".into());
            cx.notify();
            return;
        };
        let cfg = match crate::state::build_onboarding_config(
            &base,
            probe,
            self.drafts.onboarding_strategy,
            &self.drafts.onboarding_custom_cidr,
            &self.drafts.onboarding_custom_regions,
        ) {
            Ok(cfg) => cfg,
            Err(err) => {
                self.onboarding_error = Some(err);
                cx.notify();
                return;
            }
        };

        // Keep modal open until daemon confirms persistence; prevents flicker and
        // avoids 1s background poll reopening the modal on validation/IPC failure.
        let client = self.client.clone();
        self.onboarding_submitting = true;
        self.onboarding_error = None;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let res = cx
                .background_executor()
                .spawn(
                    async move { client.exchange(PipeRequest::CompleteOnboarding { config: cfg }) },
                )
                .await;

            let _ = this.update(cx, |ctrl, cx| {
                ctrl.onboarding_submitting = false;
                match res {
                    Ok(PipeResponse::Snapshot { snapshot }) => {
                        let armed = snapshot.lifecycle != Lifecycle::Unconfigured;
                        ctrl.apply_snapshot(*snapshot, cx);
                        if armed {
                            ctrl.show_onboarding = false;
                            ctrl.onboarding_dismissed = false;
                            ctrl.onboarding_error = None;
                            ctrl.set_toast("首次配置已完成并开始布防", true, cx);
                        } else {
                            ctrl.show_onboarding = true;
                            ctrl.onboarding_error =
                                Some("配置尚未生效，请检查白名单配置后重试".into());
                        }
                    }
                    Ok(PipeResponse::Ack { receipt, snapshot }) => {
                        if let Some(snap) = snapshot {
                            ctrl.apply_snapshot(*snap, cx);
                        }
                        if let Some(rc) = receipt
                            && matches!(
                                rc.status,
                                OperationStatus::Failed | OperationStatus::Partial
                            )
                        {
                            let detail = rc.error.filter(|s| !s.is_empty()).unwrap_or_else(|| {
                                format!("首次布防未完全通过：{}", rc.verified_scope)
                            });
                            ctrl.show_onboarding = true;
                            ctrl.onboarding_error = Some(detail);
                        } else if ctrl
                            .snapshot
                            .as_ref()
                            .is_some_and(|s| s.lifecycle == Lifecycle::Unconfigured)
                        {
                            ctrl.show_onboarding = true;
                            ctrl.onboarding_error = Some("配置尚未生效，请检查后重试".into());
                        } else {
                            ctrl.show_onboarding = false;
                            ctrl.onboarding_dismissed = false;
                            ctrl.onboarding_error = None;
                            ctrl.set_toast("首次配置已完成并开始布防", true, cx);
                        }
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        ctrl.show_onboarding = true;
                        ctrl.onboarding_error = Some(message);
                    }
                    Ok(_) => {
                        ctrl.show_onboarding = true;
                        ctrl.onboarding_error = Some("守护服务响应异常，请重试".into());
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        if matches!(err, TransportError::DaemonOffline(_)) {
                            ctrl.connected = false;
                            ctrl.connection_err = Some(msg.clone());
                        }
                        ctrl.show_onboarding = true;
                        ctrl.onboarding_error = Some(msg);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn skip_onboarding(&mut self, cx: &mut Context<Self>) {
        self.show_onboarding = false;
        self.onboarding_dismissed = true;
        self.onboarding_submitting = false;
        self.onboarding_error = None;
        self.set_toast("已跳过向导（只读），随时可从顶栏重新打开", true, cx);
    }

    pub fn open_onboarding_modal(&mut self, cx: &mut Context<Self>) {
        self.show_onboarding = true;
        self.onboarding_dismissed = false;
        self.onboarding_submitting = false;
        self.onboarding_error = None;
        self.probe_onboarding(cx);
        cx.notify();
    }

    pub fn toggle_pause_30m(&mut self, cx: &mut Context<Self>) {
        let now = crate::demo::now_unix_secs();
        let is_paused = self.snapshot.as_ref().is_some_and(|s| s.is_paused_at(now));
        let duration_secs = if is_paused { None } else { Some(1800) };
        let msg = if is_paused {
            "已恢复自动守护检测"
        } else {
            "已暂停自动拦截 30 分钟"
        };
        self.send_request(PipeRequest::Pause { duration_secs }, Some(msg), cx);
    }

    pub fn set_preset(&mut self, preset: PolicyPreset, cx: &mut Context<Self>) {
        if preset == PolicyPreset::StrictStaticIp
            && let Some(snap) = self.snapshot.as_ref()
        {
            let missing_ips = snap.config.targets.iter().any(|t| {
                t.enabled && t.anchor_kind != AnchorKind::Reachability && t.expect_ips.is_empty()
            });
            if missing_ips {
                self.set_nav(NavSection::Targets, cx);
                self.set_toast("请先在「目标」页为已启用目标绑定静态 IP 或 CIDR", false, cx);
                return;
            }
        }
        self.send_request(
            PipeRequest::SetPolicyPreset { preset },
            Some("守护策略档位已切换"),
            cx,
        );
    }

    pub fn hotkey_registration_report(&self) -> HotkeyRegistrationReport {
        self.tray
            .as_ref()
            .map(TrayHandle::hotkey_report)
            .unwrap_or_default()
    }

    pub fn open_new_vault_drawer(&mut self, cx: &mut Context<Self>) {
        self.drafts.vault_draft = VaultDraft::default();
        self.drafts.vault_dirty = false;
        self.drafts.vault_validation_error = None;
        self.show_vault_drawer = true;
        self.sync_vault_input_entities(cx);
        cx.notify();
    }

    pub fn open_edit_vault_drawer(&mut self, vault_id: &str, cx: &mut Context<Self>) {
        let found = self
            .snapshot
            .as_ref()
            .and_then(|s| s.config.vaults.iter().find(|v| v.id == vault_id))
            .cloned();
        if let Some(vault) = found {
            self.drafts.vault_draft = VaultDraft::from_vault(&vault);
            self.drafts.vault_dirty = false;
            self.drafts.vault_validation_error = None;
            self.show_vault_drawer = true;
            self.sync_vault_input_entities(cx);
            cx.notify();
        }
    }

    pub fn close_vault_drawer(&mut self, cx: &mut Context<Self>) {
        self.show_vault_drawer = false;
        self.drafts.vault_dirty = false;
        self.drafts.vault_validation_error = None;
        cx.notify();
    }

    pub fn adopt_egress_into_vault_draft(&mut self, cx: &mut Context<Self>) {
        if let Some(snap) = self.snapshot.clone() {
            self.drafts.vault_draft.adopt_current_egress(&snap);
            self.drafts.vault_dirty = true;
            self.sync_vault_input_entities(cx);
            self.set_toast("已采纳当前实时出口基线至隔离仓表单", true, cx);
        }
    }

    pub fn sync_vault_input_entities(&mut self, cx: &mut Context<Self>) {
        let d = self.drafts.vault_draft.clone();
        self.inputs
            .vault_id
            .update(cx, |i, cx| i.set_text_silent(&d.id, cx));
        self.inputs
            .vault_name
            .update(cx, |i, cx| i.set_text_silent(&d.name, cx));
        self.inputs
            .vault_regions
            .update(cx, |i, cx| i.set_text_silent(&d.pinned_regions_text, cx));
        self.inputs
            .vault_ips
            .update(cx, |i, cx| i.set_text_silent(&d.pinned_ips_text, cx));
        self.inputs
            .vault_asn
            .update(cx, |i, cx| i.set_text_silent(&d.pinned_asn_text, cx));
        self.inputs.vault_proxy_port.update(cx, |i, cx| {
            i.set_text_silent(&d.dedicated_proxy_port_text, cx)
        });
        self.inputs
            .vault_mihomo_group
            .update(cx, |i, cx| i.set_text_silent(&d.preferred_mihomo_group, cx));
        self.inputs
            .vault_mihomo_node
            .update(cx, |i, cx| i.set_text_silent(&d.preferred_mihomo_node, cx));
        self.inputs
            .vault_min_score
            .update(cx, |i, cx| i.set_text_silent(&d.min_safety_score_text, cx));
        self.inputs
            .vault_cooldown
            .update(cx, |i, cx| i.set_text_silent(&d.cooldown_secs_text, cx));
    }

    pub fn save_vault_draft(&mut self, cx: &mut Context<Self>) {
        match self.drafts.vault_draft.to_account_vault() {
            Ok(vault) => {
                self.drafts.vault_validation_error = None;
                self.drafts.vault_dirty = false;
                self.show_vault_drawer = false;
                let msg = format!("已保存主权隔离仓「{}」", vault.name);
                self.send_request_msg(PipeRequest::UpsertVault { vault }, Some(msg), cx);
            }
            Err(err) => {
                self.drafts.vault_validation_error = Some(err.clone());
                self.set_toast(err, false, cx);
            }
        }
    }

    pub fn run_cleanroom_scan(&mut self, cx: &mut Context<Self>) {
        let scope = self.cleanroom_scope.clone();
        self.send_request(
            PipeRequest::ScanCleanRoom { scope },
            Some("净室纯只读深度扫描已完成"),
            cx,
        );
    }

    pub fn execute_cleanroom_purge(&mut self, cx: &mut Context<Self>) {
        let scope = self.cleanroom_scope.clone();
        let selected_finding_ids: Vec<String> =
            self.cleanroom_selected_ids.iter().cloned().collect();
        self.send_request(
            PipeRequest::ExecuteCleanRoom {
                scope,
                selected_finding_ids,
            },
            Some("已完成加密备份并执行防连坐洗白（后置复核通过）"),
            cx,
        );
        self.refresh_cleanroom_backups(cx);
    }

    pub fn refresh_cleanroom_backups(&mut self, cx: &mut Context<Self>) {
        self.send_request(PipeRequest::ListCleanRoomBackups, None, cx);
    }

    pub fn restore_cleanroom_backup(&mut self, backup_id: String, cx: &mut Context<Self>) {
        let msg = format!("已从加密时光机备份 {backup_id} 还原");
        self.send_request_msg(
            PipeRequest::RestoreCleanRoomBackup { backup_id },
            Some(msg),
            cx,
        );
    }

    pub fn build_and_export_health_card(&mut self, export_png: bool, cx: &mut Context<Self>) {
        self.send_request(PipeRequest::BuildHealthCard { export_png }, None, cx);
    }
}

/// Opens or focuses Mode A Tray Quick HUD (`398x432` logical px), anchored bottom-right above taskbar.
pub fn open_hud_window(ctrl: Entity<AppController>, cx: &mut App) {
    let existing = ctrl.read(cx).hud_window;
    if let Some(handle) = existing
        && handle
            .update(cx, |_, window, _| {
                let _ = ensure_window_on_screen("ClaudeGuard Quick HUD");
                window.activate_window();
            })
            .is_ok()
    {
        return;
    }

    let primary = cx.primary_display();
    let display_id = primary.as_ref().map(|d| d.id());
    let work_area = primary
        .as_ref()
        .map(|d| {
            let vis = d.visible_bounds();
            LogicalRect {
                x: vis.origin.x.as_f32(),
                y: vis.origin.y.as_f32(),
                width: vis.size.width.as_f32(),
                height: vis.size.height.as_f32(),
            }
        })
        .unwrap_or_else(|| primary_work_area_logical(0.0));

    let hud_rect = compute_hud_bounds(work_area);
    let bounds = Bounds {
        origin: point(px(hud_rect.x), px(hud_rect.y)),
        size: size(px(hud_rect.width), px(hud_rect.height)),
    };
    let border_rgb = ctrl.read(cx).palette().frame_border;
    let ctrl_clone = ctrl.clone();
    if let Ok(handle) = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            display_id,
            titlebar: Some(TitlebarOptions {
                title: Some("ClaudeGuard Quick HUD".into()),
                appears_transparent: true,
                ..Default::default()
            }),
            kind: WindowKind::PopUp,
            is_resizable: false,
            is_minimizable: false,
            is_movable: true,
            focus: true,
            show: true,
            ..Default::default()
        },
        move |window, cx| cx.new(|cx| HudWindowView::new(ctrl_clone, window, cx)),
    ) {
        apply_win11_round_corners("ClaudeGuard Quick HUD", border_rgb);
        let _ = ensure_window_on_screen("ClaudeGuard Quick HUD");
        ctrl.update(cx, |c, _| c.hud_window = Some(handle));
    }
}

/// Toggles Mode A Tray Quick HUD (`window.remove_window()` drops SwapChain & VRAM to 0).
pub fn toggle_hud_window(ctrl: Entity<AppController>, cx: &mut App) {
    let (existing, recently_dismissed) = {
        let r = ctrl.read(cx);
        (
            r.hud_window,
            r.hud_auto_dismissed_at
                .is_some_and(|at| at.elapsed() < HUD_DISMISS_DEBOUNCE),
        )
    };
    if let Some(handle) = existing {
        let removed = handle
            .update(cx, |_, window, _| {
                window.remove_window();
            })
            .is_ok();
        ctrl.update(cx, |c, _| {
            c.hud_window = None;
            c.hud_auto_dismissed_at = Some(Instant::now());
        });
        if removed {
            return;
        }
    }
    if recently_dismissed {
        ctrl.update(cx, |c, _| c.hud_auto_dismissed_at = None);
        return;
    }
    open_hud_window(ctrl, cx);
}

/// Opens or focuses Mode B Wide Bento Main Console (`1020x720`, auto-clamped to DPI work area).
pub fn open_console_window(ctrl: Entity<AppController>, cx: &mut App) {
    let existing = ctrl.read(cx).console_window;
    if let Some(handle) = existing
        && handle
            .update(cx, |_, window, _| {
                let _ = restore_window_if_minimized("ClaudeGuard v4");
                let _ = ensure_window_on_screen("ClaudeGuard v4");
                window.activate_window();
            })
            .is_ok()
    {
        return;
    }

    let primary = cx.primary_display();
    let display_id = primary.as_ref().map(|d| d.id());
    let (bounds, min_w, min_h) = if let Some(d) = primary.as_ref() {
        let vis = d.visible_bounds();
        let avail_w = (vis.size.width.as_f32() - 24.0).max(640.0);
        let avail_h = (vis.size.height.as_f32() - 20.0).max(400.0);
        let w = layout::CONSOLE_WIDTH.min(avail_w);
        let h = layout::CONSOLE_HEIGHT.min(avail_h);
        let x = vis.origin.x.as_f32() + ((vis.size.width.as_f32() - w) * 0.5).max(0.0);
        let y = vis.origin.y.as_f32() + ((vis.size.height.as_f32() - h) * 0.5).max(0.0);
        (
            Bounds {
                origin: point(px(x), px(y)),
                size: size(px(w), px(h)),
            },
            layout::CONSOLE_MIN_WIDTH.min(w),
            layout::CONSOLE_MIN_HEIGHT.min(h),
        )
    } else {
        (
            Bounds::centered(
                None,
                size(px(layout::CONSOLE_WIDTH), px(layout::CONSOLE_HEIGHT)),
                cx,
            ),
            layout::CONSOLE_MIN_WIDTH,
            layout::CONSOLE_MIN_HEIGHT,
        )
    };

    let border_rgb = ctrl.read(cx).palette().frame_border;
    let ctrl_clone = ctrl.clone();
    if let Ok(handle) = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            display_id,
            titlebar: Some(TitlebarOptions {
                title: Some("ClaudeGuard v4".into()),
                appears_transparent: true,
                ..Default::default()
            }),
            kind: WindowKind::Normal,
            is_resizable: true,
            is_minimizable: true,
            is_movable: true,
            window_min_size: Some(size(px(min_w), px(min_h))),
            focus: true,
            show: true,
            ..Default::default()
        },
        move |window, cx| cx.new(|cx| ConsoleWindowView::new(ctrl_clone, window, cx)),
    ) {
        apply_win11_round_corners("ClaudeGuard v4", border_rgb);
        let _ = ensure_window_on_screen("ClaudeGuard v4");
        ctrl.update(cx, |c, _| c.console_window = Some(handle));
    }
}

/// Root view for Mode A — Tray Quick HUD (`398 × 432`).
pub struct HudWindowView {
    pub ctrl: Entity<AppController>,
    focus_handle: FocusHandle,
    was_activated: bool,
    entry_presence: PresenceSpring,
    toast_presence: PresenceSpring,
    last_toast: Option<(String, bool, Option<ToastAction>)>,
    _obs_sub: gpui::Subscription,
    _act_sub: gpui::Subscription,
    _app_sub: gpui::Subscription,
}

impl HudWindowView {
    pub fn new(ctrl: Entity<AppController>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();
        let _obs_sub = cx.observe(&ctrl, |_, _, cx| cx.notify());
        let ctrl_act = ctrl.clone();
        let _act_sub = cx.observe_window_activation(window, move |this, window, cx| {
            if window.is_window_active() {
                this.was_activated = true;
            } else if this.was_activated {
                ctrl_act.update(cx, |c, _| {
                    c.hud_window = None;
                    c.hud_auto_dismissed_at = Some(Instant::now());
                });
                window.remove_window();
            }
        });
        let ctrl_app = ctrl.clone();
        let initial_appearance = window.appearance();
        ctrl_app.update(cx, |c, cx| {
            c.on_window_appearance_changed(initial_appearance, cx)
        });
        let _app_sub = cx.observe_window_appearance(window, move |_, window, cx| {
            let app = window.appearance();
            ctrl_app.update(cx, |c, cx| c.on_window_appearance_changed(app, cx));
        });
        let ctrl_close = ctrl.clone();
        window.on_window_should_close(cx, move |_window, cx| {
            ctrl_close.update(cx, |c, _| {
                c.hud_window = None;
                c.hud_auto_dismissed_at = Some(Instant::now());
            });
            true
        });
        let mut entry_presence = PresenceSpring::new(false);
        entry_presence.set_open(true, cx.reduce_motion());
        window.focus(&focus_handle, cx);
        Self {
            ctrl,
            focus_handle,
            was_activated: false,
            entry_presence,
            toast_presence: PresenceSpring::new(false),
            last_toast: None,
            _obs_sub,
            _act_sub,
            _app_sub,
        }
    }

    fn on_dismiss(&mut self, _: &DismissHudWindow, window: &mut Window, cx: &mut Context<Self>) {
        self.ctrl.update(cx, |c, _| {
            c.hud_window = None;
            c.hud_auto_dismissed_at = Some(Instant::now());
        });
        window.remove_window();
    }
}

impl Focusable for HudWindowView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for HudWindowView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let now = Instant::now();
        let reduce_motion = cx.reduce_motion();
        let (p, proj, toast, toast_action, busy) = self.ctrl.update(cx, |c, _| {
            let p = c.palette();
            let proj = c.hud_projection();
            let toast = c.toast.clone();
            let toast_action = c.toast_action.clone();
            let busy = c.busy_action;
            (p, proj, toast, toast_action, busy)
        });

        if let Some((msg, ok)) = toast {
            self.last_toast = Some((msg, ok, toast_action));
            self.toast_presence.set_open(true, reduce_motion);
        } else {
            self.toast_presence.set_open(false, reduce_motion);
        }

        let mut animating = self.entry_presence.tick(now, spring_sheet());
        animating |= self.toast_presence.tick(now, spring_sheet());
        if !self.toast_presence.is_mounted() {
            self.last_toast = None;
        }
        if animating {
            window.request_animation_frame();
        }

        let entry_p = self.entry_presence.progress();
        let entry_y = (1.0 - self.entry_presence.raw_progress()) * 8.0;
        let toast_p = self.toast_presence.progress();
        let toast_y = (1.0 - self.toast_presence.raw_progress()) * 10.0;
        let show_toast = self.toast_presence.is_mounted();
        let ctrl_dismiss = self.ctrl.clone();

        let mut root = div()
            .id("hud-root")
            .key_context("HudWindow")
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(Self::on_dismiss))
            .relative()
            .size_full()
            .overflow_hidden()
            .bg(rgb(p.frame_bg))
            .border_1()
            .border_color(rgb(p.frame_border))
            .font_family("Segoe UI Variable Text")
            .text_color(rgb(p.text_primary))
            .child(
                div()
                    .size_full()
                    .opacity(entry_p)
                    .pt(px(entry_y.max(0.0)))
                    .child(views::hud::render_hud(
                        self.ctrl.clone(),
                        &proj,
                        busy,
                        p,
                        cx,
                    )),
            );

        if show_toast && let Some((msg, ok, toast_action)) = self.last_toast.clone() {
            let b = if ok { p.badge_pass } else { p.badge_fail };
            let pill_border = if ok {
                p.toast_border_rgba
            } else {
                p.hero_tripped.border
            };
            let ctrl_act_pill = self.ctrl.clone();
            let action_label: Option<&'static str> = toast_action.as_ref().map(|act| match act {
                ToastAction::OpenExplorerPath(_) => "打开目录",
                ToastAction::JumpAntigravityRepair => "去热修复 →",
                ToastAction::RearmNow => "立即布防",
                ToastAction::JumpBreaker => "去解封 →",
                ToastAction::CopyText { label, .. } => *label,
            });
            let mut right_row = div().flex().items_center().flex_shrink_0().gap(px(5.));
            if let (Some(lbl), Some(act)) = (action_label, toast_action) {
                right_row = right_row.child(
                    div()
                        .id("hud-toast-action-pill")
                        .px(px(7.))
                        .py(px(2.5))
                        .rounded(px(6.5))
                        .bg(rgb(p.accent_soft_bg))
                        .border_1()
                        .border_color(rgb(p.accent_soft_border))
                        .text_size(px(10.5))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(rgb(p.accent_soft_text))
                        .cursor_pointer()
                        .hover(|s| s.opacity(0.88))
                        .child(lbl)
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, window, cx| {
                                cx.stop_propagation();
                                match &act {
                                    ToastAction::OpenExplorerPath(path) => {
                                        let p_str = path.clone();
                                        ctrl_act_pill.update(cx, |c, cx| {
                                            c.open_path_in_explorer_async(p_str, cx);
                                        });
                                    }
                                    ToastAction::JumpAntigravityRepair => {
                                        ctrl_act_pill.update(cx, |c, cx| {
                                            c.toast = None;
                                            c.toast_action = None;
                                            c.env_tab = EnvSubTab::Antigravity;
                                            c.set_nav(NavSection::Environment, cx);
                                            c.hud_window = None;
                                        });
                                        open_console_window(ctrl_act_pill.clone(), cx);
                                        window.remove_window();
                                    }
                                    ToastAction::RearmNow => {
                                        ctrl_act_pill.update(cx, |c, cx| {
                                            c.toast = None;
                                            c.toast_action = None;
                                            c.send_request(
                                                PipeRequest::Rearm,
                                                Some("已重新布防，恢复出口守护"),
                                                cx,
                                            );
                                        });
                                    }
                                    ToastAction::JumpBreaker => {
                                        ctrl_act_pill.update(cx, |c, cx| {
                                            c.toast = None;
                                            c.toast_action = None;
                                            c.set_nav(NavSection::Breaker, cx);
                                            c.hud_window = None;
                                        });
                                        open_console_window(ctrl_act_pill.clone(), cx);
                                        window.remove_window();
                                    }
                                    ToastAction::CopyText { text, .. } => {
                                        let t_str = text.clone();
                                        ctrl_act_pill.update(cx, |c, cx| {
                                            c.copy_to_clipboard(t_str, "命令", cx);
                                        });
                                    }
                                }
                            }),
                        ),
                );
            }
            right_row = right_row.child(
                div()
                    .id("hud-toast-close")
                    .flex_shrink_0()
                    .cursor_pointer()
                    .p(px(2.))
                    .rounded(px(5.))
                    .child(ui_icon("icons/ui/close.svg", 10.5, p.text_muted))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            cx.stop_propagation();
                            ctrl_dismiss.update(cx, |c, cx| {
                                c.toast = None;
                                c.toast_action = None;
                                cx.notify();
                            });
                        }),
                    ),
            );
            root = root.child(
                div()
                    .absolute()
                    .bottom(px(54.0 - toast_y))
                    .left(px(12.))
                    .right(px(12.))
                    .opacity(toast_p)
                    .flex()
                    .justify_center()
                    .child(
                        div()
                            .id("hud-floating-toast")
                            .occlude()
                            .w_full()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap(px(8.))
                            .px(px(10.))
                            .py(px(7.))
                            .rounded(px(10.))
                            .bg(rgba(p.toast_bg_rgba))
                            .border_1()
                            .border_color(rgba(pill_border))
                            .shadow(float_shadow(p))
                            .on_mouse_up(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.))
                                    .flex_1()
                                    .min_w(px(0.))
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .w(px(6.))
                                            .h(px(6.))
                                            .rounded(px(999.))
                                            .bg(rgb(b.dot)),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.))
                                            .text_size(px(11.))
                                            .line_height(px(15.))
                                            .text_color(rgb(b.text))
                                            .child(msg),
                                    ),
                            )
                            .child(right_row),
                    ),
            );
        }

        root
    }
}

/// Cached top ceramic titlebar / utility header view.
///
/// Mounted via `Entity::cached(StyleRefinement)` inside [`ConsoleWindowView`] so 120Hz page
/// and sub-tab transitions replay its GPU scene directly without re-running `render()` or
/// DirectWrite text shaping.
struct ConsoleHeaderView {
    ctrl: Entity<AppController>,
    last_maximized: bool,
    _obs_sub: gpui::Subscription,
    _bounds_sub: gpui::Subscription,
}

impl ConsoleHeaderView {
    fn new(ctrl: Entity<AppController>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let last_maximized = window.is_maximized();
        let _obs_sub = cx.observe(&ctrl, |_, _, cx| cx.notify());
        let _bounds_sub = cx.observe_window_bounds(window, |this, window, cx| {
            let m = window.is_maximized();
            if this.last_maximized != m {
                this.last_maximized = m;
                cx.notify();
            }
        });
        Self {
            ctrl,
            last_maximized,
            _obs_sub,
            _bounds_sub,
        }
    }
}

impl Render for ConsoleHeaderView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let is_maximized = window.is_maximized();
        self.last_maximized = is_maximized;
        let (p, tripped, is_unconfigured, connection_banner) = {
            let r = self.ctrl.read(cx);
            let p = r.palette();
            let tripped = r.snapshot.as_ref().is_some_and(|s| s.is_tripped());
            let is_unconfigured = r
                .snapshot
                .as_ref()
                .is_some_and(|s| s.lifecycle == Lifecycle::Unconfigured);
            let connection_banner = if !r.connected {
                Some(
                    r.connection_err
                        .as_deref()
                        .map(|e| {
                            let clean = e
                                .trim()
                                .trim_start_matches("后台守护服务未连接：")
                                .trim_start_matches("守护服务未连接：")
                                .trim();
                            if clean.is_empty() {
                                "服务未响应".into()
                            } else {
                                clean.to_string()
                            }
                        })
                        .unwrap_or_else(|| "正在连接…".into()),
                )
            } else {
                None
            };
            (p, tripped, is_unconfigured, connection_banner)
        };

        render_ceramic_header(
            self.ctrl.clone(),
            tripped,
            is_unconfigured,
            connection_banner.as_deref(),
            is_maximized,
            p,
            cx,
        )
    }
}

/// Root view for Mode B — Wide Bento Main Console (`1020 × 720`).
pub struct ConsoleWindowView {
    pub ctrl: Entity<AppController>,
    focus_handle: FocusHandle,
    header_view: Entity<ConsoleHeaderView>,
    dock_indicator: SlidingIndicatorState,
    page_transition: DirectionalTransition<NavSection>,
    breaker_subtab: DirectionalTransition<BreakerSubTab>,
    env_subtab: DirectionalTransition<EnvSubTab>,
    notify_subtab: DirectionalTransition<NotifySubTab>,
    toast_presence: PresenceSpring,
    last_toast: Option<(String, bool, Option<ToastAction>)>,
    policy_presence: PresenceSpring,
    theme_presence: PresenceSpring,
    _obs_sub: gpui::Subscription,
    _app_sub: gpui::Subscription,
}

impl ConsoleWindowView {
    pub fn new(ctrl: Entity<AppController>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();
        let (initial_nav, initial_breaker_tab, initial_env_tab, initial_notify_tab) = {
            let r = ctrl.read(cx);
            (r.nav_section, r.breaker_tab, r.env_tab, r.notify_tab)
        };
        let header_ctrl = ctrl.clone();
        let header_view = cx.new(|cx| ConsoleHeaderView::new(header_ctrl, window, cx));
        let _obs_sub = cx.observe(&ctrl, |_, _, cx| cx.notify());
        let ctrl_app = ctrl.clone();
        let initial_appearance = window.appearance();
        ctrl_app.update(cx, |c, cx| {
            c.on_window_appearance_changed(initial_appearance, cx)
        });
        let _app_sub = cx.observe_window_appearance(window, move |_, window, cx| {
            let app = window.appearance();
            ctrl_app.update(cx, |c, cx| c.on_window_appearance_changed(app, cx));
        });
        let ctrl_close = ctrl.clone();
        window.on_window_should_close(cx, move |_window, cx| {
            let (close_to_tray, has_tray) = {
                let r = ctrl_close.read(cx);
                let ctt = r
                    .snapshot
                    .as_ref()
                    .map(|s| s.config.close_to_tray)
                    .unwrap_or(true);
                (ctt, r.tray.is_some())
            };
            ctrl_close.update(cx, |c, _| c.console_window = None);
            if !close_to_tray || !has_tray {
                ctrl_close.update(cx, |c, _| {
                    if let Some(mut tray) = c.tray.take() {
                        tray.shutdown();
                    }
                });
                cx.quit();
            }
            true
        });
        window.focus(&focus_handle, cx);
        Self {
            ctrl,
            focus_handle,
            header_view,
            dock_indicator: SlidingIndicatorState::new(),
            page_transition: DirectionalTransition::new(initial_nav),
            breaker_subtab: DirectionalTransition::new(initial_breaker_tab),
            env_subtab: DirectionalTransition::new(initial_env_tab),
            notify_subtab: DirectionalTransition::new(initial_notify_tab),
            toast_presence: PresenceSpring::new(false),
            last_toast: None,
            policy_presence: PresenceSpring::new(false),
            theme_presence: PresenceSpring::new(false),
            _obs_sub,
            _app_sub,
        }
    }

    fn on_focus_search(
        &mut self,
        _: &FocusGlobalSearch,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.ctrl.read(cx).has_modal_open() {
            return;
        }
        self.ctrl.update(cx, |c, cx| {
            if c.nav_section != NavSection::Audit {
                c.set_nav(NavSection::Audit, cx);
            }
        });
        let handle = self.ctrl.read(cx).inputs.search.read(cx).focus_handle(cx);
        window.focus(&handle, cx);
        cx.notify();
    }

    fn on_focus_next(&mut self, _: &FocusNextField, window: &mut Window, cx: &mut Context<Self>) {
        window.focus_next(cx);
    }

    fn on_focus_prev(&mut self, _: &FocusPrevField, window: &mut Window, cx: &mut Context<Self>) {
        window.focus_prev(cx);
    }

    fn on_dismiss_overlay(
        &mut self,
        _: &DismissConsoleOverlay,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.ctrl.update(cx, |c, cx| {
            if c.show_plugins_modal {
                c.show_plugins_modal = false;
                cx.notify();
            } else if c.show_onboarding {
                if !c.onboarding_submitting {
                    c.skip_onboarding(cx);
                }
            } else if c.policy_menu_open {
                c.policy_menu_open = false;
                cx.notify();
            } else if c.theme_menu_open {
                c.theme_menu_open = false;
                cx.notify();
            } else if c.open_region_picker_for.is_some() {
                c.open_region_picker_for = None;
                cx.notify();
            } else if c.show_add_target_drawer {
                c.show_add_target_drawer = false;
                cx.notify();
            } else if c.toast.is_some() {
                c.toast = None;
                c.toast_action = None;
                cx.notify();
            } else if c.pending_confirm.is_some() {
                c.pending_confirm = None;
                cx.notify();
            }
        });
    }

    fn on_save_current(
        &mut self,
        _: &SaveCurrentView,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.ctrl.read(cx).has_modal_open() {
            return;
        }
        self.ctrl.update(cx, |c, cx| match c.nav_section {
            NavSection::Targets => {
                if c.drafts.dirty {
                    c.save_target_drafts(cx);
                }
            }
            NavSection::Notify if c.notify_tab == NotifySubTab::Feishu => {
                c.save_feishu_from_drafts(cx);
            }
            _ => {}
        });
    }

    fn on_refresh_current(
        &mut self,
        _: &RefreshCurrentView,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.ctrl.read(cx).has_modal_open() {
            return;
        }
        self.ctrl.update(cx, |c, cx| {
            if !c.connected {
                c.send_request(PipeRequest::GetSnapshot, Some("已重新连接守护服务"), cx);
                return;
            }
            match c.nav_section {
                NavSection::Audit => c.refresh_audit_logs(cx),
                NavSection::Updates => {
                    let tripped = c.snapshot.as_ref().is_some_and(|s| s.is_tripped());
                    if tripped {
                        c.set_toast("当前处于熔断隔离态，已暂停联网检查更新", false, cx);
                    } else if !c.is_scope_busy(&ActionScope::UpdatesAll) {
                        c.send_request(
                            PipeRequest::CheckUpdates { component: None },
                            Some("已完成组件更新检查"),
                            cx,
                        );
                    }
                }
                _ => {
                    if !c.is_scope_busy(&ActionScope::RecheckAll) {
                        c.send_request(
                            PipeRequest::RecheckNow { target_id: None },
                            Some("已完成出口核验"),
                            cx,
                        );
                    }
                }
            }
        });
    }

    fn jump_nav(&mut self, section: NavSection, cx: &mut Context<Self>) {
        if self.ctrl.read(cx).has_modal_open() {
            return;
        }
        self.ctrl.update(cx, |c, cx| c.set_nav(section, cx));
    }

    fn on_nav_1(&mut self, _: &NavTab1, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Overview, cx);
    }
    fn on_nav_2(&mut self, _: &NavTab2, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Vaults, cx);
    }
    fn on_nav_3(&mut self, _: &NavTab3, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::CleanRoom, cx);
    }
    fn on_nav_4(&mut self, _: &NavTab4, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Targets, cx);
    }
    fn on_nav_5(&mut self, _: &NavTab5, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Breaker, cx);
    }
    fn on_nav_6(&mut self, _: &NavTab6, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Environment, cx);
    }
    fn on_nav_7(&mut self, _: &NavTab7, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Audit, cx);
    }
    fn on_nav_8(&mut self, _: &NavTab8, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Updates, cx);
    }
    fn on_nav_9(&mut self, _: &NavTab9, _: &mut Window, cx: &mut Context<Self>) {
        self.jump_nav(NavSection::Notify, cx);
    }
}

impl Focusable for ConsoleWindowView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for ConsoleWindowView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let now = Instant::now();
        let reduce_motion = cx.reduce_motion();

        let (
            p,
            nav,
            breaker_tab,
            env_tab,
            notify_tab,
            show_onboarding,
            show_plugins,
            policy_menu_open,
            theme_menu_open,
            snapshot_opt,
            toast,
            toast_action,
            targets_dirty,
            console_scroll,
            proj,
        ) = self.ctrl.update(cx, |c, _| {
            let p = c.palette();
            let proj = c.console_projection();
            (
                p,
                c.nav_section,
                c.breaker_tab,
                c.env_tab,
                c.notify_tab,
                c.show_onboarding,
                c.show_plugins_modal,
                c.policy_menu_open,
                c.theme_menu_open,
                c.snapshot.clone(),
                c.toast.clone(),
                c.toast_action.clone(),
                c.drafts.dirty,
                c.console_scroll.clone(),
                proj,
            )
        });

        let active_nav_idx = NavSection::ALL.iter().position(|s| *s == nav).unwrap_or(0);
        let prev_active_nav = self.page_transition.active();
        let nav_changed = prev_active_nav != nav;
        if nav_changed {
            self.dock_indicator.select(active_nav_idx, reduce_motion);
            let old_idx = NavSection::ALL
                .iter()
                .position(|s| *s == prev_active_nav)
                .unwrap_or(0);
            let dir = if active_nav_idx >= old_idx { 1 } else { -1 };
            self.page_transition.transition_to(nav, dir, reduce_motion);
            // Silently snap sub-tab transitions so they never compete with a main dock switch.
            self.breaker_subtab.transition_to(breaker_tab, 1, true);
            self.env_subtab.transition_to(env_tab, 1, true);
            self.notify_subtab.transition_to(notify_tab, 1, true);
        } else {
            let prev_breaker = self.breaker_subtab.active();
            if prev_breaker != breaker_tab {
                let dir = if breaker_tab.index() >= prev_breaker.index() {
                    1
                } else {
                    -1
                };
                self.breaker_subtab
                    .transition_to(breaker_tab, dir, reduce_motion);
            }
            let prev_env = self.env_subtab.active();
            if prev_env != env_tab {
                let dir = if env_tab.index() >= prev_env.index() {
                    1
                } else {
                    -1
                };
                self.env_subtab.transition_to(env_tab, dir, reduce_motion);
            }
            let prev_notify = self.notify_subtab.active();
            if prev_notify != notify_tab {
                let dir = if notify_tab.index() >= prev_notify.index() {
                    1
                } else {
                    -1
                };
                self.notify_subtab
                    .transition_to(notify_tab, dir, reduce_motion);
            }
        }

        if let Some((msg, ok)) = toast {
            self.last_toast = Some((msg, ok, toast_action));
            self.toast_presence.set_open(true, reduce_motion);
        } else {
            self.toast_presence.set_open(false, reduce_motion);
        }
        self.policy_presence
            .set_open(policy_menu_open, reduce_motion);
        self.theme_presence.set_open(theme_menu_open, reduce_motion);

        let mut animating = self.dock_indicator.tick(now);
        animating |= self.page_transition.tick(now);
        animating |= self.breaker_subtab.tick(now);
        animating |= self.env_subtab.tick(now);
        animating |= self.notify_subtab.tick(now);
        animating |= self.toast_presence.tick(now, spring_sheet());
        animating |= self.policy_presence.tick(now, spring_sheet());
        animating |= self.theme_presence.tick(now, spring_sheet());
        if !self.toast_presence.is_mounted() {
            self.last_toast = None;
        }
        if animating {
            window.request_animation_frame();
        }

        let ctrl_entity = self.ctrl.clone();
        let tripped = snapshot_opt.as_ref().is_some_and(|s| s.is_tripped());
        let ag_issue = snapshot_opt.as_ref().is_some_and(|s| {
            s.config.require_antigravity_proxy
                && s.antigravity_proxy.installed
                && !s.antigravity_proxy.is_ready_for_launch()
        });
        let has_any_update = snapshot_opt.as_ref().is_some_and(|s| {
            [
                &s.updates.claudeguard,
                &s.updates.antigravity_proxy,
                &s.updates.claude_desktop,
                &s.updates.claude_code,
                &s.updates.codex_desktop,
                &s.updates.codex_cli,
                &s.updates.antigravity_ide,
                &s.updates.antigravity_cn,
                &s.updates.ag_usage_monitor,
                &s.updates.ag_capsule,
                &s.updates.cursor_ide,
                &s.updates.windsurf_ide,
                &s.updates.zed_ide,
                &s.updates.trae_ide,
            ]
            .iter()
            .any(|slot| slot.phase == UpdateCheckPhase::UpdateAvailable)
        });
        let cleanroom_alert = snapshot_opt.as_ref().is_some_and(|s| {
            s.last_cleanroom_report
                .as_ref()
                .is_some_and(|r| r.pollution_score >= 60)
        });
        let vault_active = snapshot_opt.as_ref().is_some_and(|s| {
            s.vaults
                .iter()
                .any(|v| v.state == crate::protocol::VaultRuntimeState::ActiveRunning)
        });

        let mut header_cache_style = StyleRefinement::default();
        header_cache_style.size.width = Some(relative(1.0).into());
        header_cache_style.size.height = Some(px(HEADER_HEIGHT).into());
        header_cache_style.flex_shrink = Some(0.0);
        let header = self.header_view.clone().cached(header_cache_style);
        let dock_geom = self.dock_indicator.liquid_geometry();
        let active_icon_dy = self.page_transition.active_icon_bloom_dy();
        let active_icon_scale = self.page_transition.active_icon_bloom_scale();
        let dock = render_ceramic_dock(
            ctrl_entity.clone(),
            DockRenderState {
                active_nav: nav,
                active_nav_idx,
                pill_geom: dock_geom,
                active_icon_dy,
                active_icon_scale,
                vault_active,
                cleanroom_alert,
                targets_alert: tripped,
                targets_dirty,
                env_alert: tripped || ag_issue,
                has_update: has_any_update,
            },
            p,
            cx,
        );

        // Zero-Reflow Pure Horizontal Rail Glide + Per-Card In-Place Symmetric Unfold:
        // Single incoming pane translates in O(1) prepaint via `offset_pane(rail_dx, ...)`
        // (dy == 0.0, zero Taffy layout thrashing, zero double-page exiting ghost rebuild),
        // paired with crisp opacity unveil and sequential GPU per-card symmetric unfold.
        let page_choreo = self.page_transition.choreo();
        let rail_dx = self.page_transition.page_rail_dx(52.0);
        let page_op = self.page_transition.page_opacity();
        let breaker_subtab_dx = self.breaker_subtab.page_rail_dx(34.0);
        let env_subtab_dx = self.env_subtab.page_rail_dx(34.0);
        let notify_subtab_dx = self.notify_subtab.page_rail_dx(34.0);

        let page_content = match nav {
            NavSection::Overview => {
                views::overview::render_overview(ctrl_entity.clone(), &proj, page_choreo, p, cx)
            }
            NavSection::Vaults => {
                views::vaults::render_vaults_page(ctrl_entity.clone(), page_choreo, p, cx)
            }
            NavSection::CleanRoom => {
                views::cleanroom::render_cleanroom_page(ctrl_entity.clone(), page_choreo, p, cx)
            }
            NavSection::Targets => {
                views::targets::render_targets_page(ctrl_entity.clone(), page_choreo, p, cx)
            }
            NavSection::Breaker => views::breaker::render_breaker_page(
                ctrl_entity.clone(),
                &proj,
                page_choreo,
                breaker_subtab_dx,
                p,
                cx,
            ),
            NavSection::Environment => views::environment::render_environment_page(
                ctrl_entity.clone(),
                page_choreo,
                env_subtab_dx,
                p,
                cx,
            ),
            NavSection::Audit => {
                views::audit::render_audit_page(ctrl_entity.clone(), &proj, page_choreo, p, cx)
            }
            NavSection::Updates => {
                views::updates::render_updates_page(ctrl_entity.clone(), page_choreo, p, cx)
            }
            NavSection::Notify => views::notify::render_notify_page(
                ctrl_entity.clone(),
                page_choreo,
                notify_subtab_dx,
                p,
                cx,
            ),
        };

        let incoming_pane = div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.))
            .when(page_op < 0.995, |d| d.opacity(page_op))
            .child(page_content);

        let animated_page = div()
            .relative()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.))
            .pt(px(1.))
            .pb(px(12.))
            .overflow_x_hidden()
            .child(offset_pane(rail_dx, incoming_pane));

        let body_scroll = div()
            .id("console-scroll")
            .track_scroll(&console_scroll)
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.))
            .min_h(px(0.))
            .overflow_y_scroll()
            .pb(px(6.))
            .gap(px(11.))
            .child(animated_page);

        let ctrl_root_click = ctrl_entity.clone();
        let mut root = div()
            .id("console-root")
            .key_context("ConsoleWindow")
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(Self::on_focus_search))
            .on_action(cx.listener(Self::on_focus_next))
            .on_action(cx.listener(Self::on_focus_prev))
            .on_action(cx.listener(Self::on_dismiss_overlay))
            .on_action(cx.listener(Self::on_save_current))
            .on_action(cx.listener(Self::on_refresh_current))
            .on_action(cx.listener(Self::on_nav_1))
            .on_action(cx.listener(Self::on_nav_2))
            .on_action(cx.listener(Self::on_nav_3))
            .on_action(cx.listener(Self::on_nav_4))
            .on_action(cx.listener(Self::on_nav_5))
            .on_action(cx.listener(Self::on_nav_6))
            .on_action(cx.listener(Self::on_nav_7))
            .on_action(cx.listener(Self::on_nav_8))
            .on_action(cx.listener(Self::on_nav_9))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_root_click.update(cx, |c, cx| c.close_floating_menus(cx));
                }),
            )
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(p.frame_bg))
            .border_1()
            .border_color(rgb(p.frame_border))
            .font_family("Segoe UI Variable Text")
            .text_color(rgb(p.text_primary))
            .px(px(18.))
            .pt(px(14.))
            .pb(px(13.))
            .gap(px(11.))
            .child(header)
            .child(body_scroll)
            .child(dock);

        if self.policy_presence.is_mounted() {
            root = root.child(render_policy_dropdown_overlay(
                ctrl_entity.clone(),
                self.policy_presence.progress(),
                self.policy_presence.raw_progress(),
                self.policy_presence.is_open(),
                p,
                cx,
            ));
        }
        if self.theme_presence.is_mounted() {
            root = root.child(render_theme_popover_overlay(
                ctrl_entity.clone(),
                self.theme_presence.progress(),
                self.theme_presence.raw_progress(),
                self.theme_presence.is_open(),
                p,
                cx,
            ));
        }
        if show_plugins {
            root = root.child(views::plugins_modal::render_plugins_modal(
                ctrl_entity.clone(),
                p,
                cx,
            ));
        }
        if show_onboarding {
            root = root.child(views::onboarding::render_onboarding_modal(
                ctrl_entity.clone(),
                p,
                cx,
            ));
        }

        // Dynamic-Island Floating Toast Overlay: rendered LAST (above modals), ZERO layout shift!
        if self.toast_presence.is_mounted()
            && let Some((msg, ok, toast_action)) = self.last_toast.clone()
        {
            let b = if ok { p.badge_pass } else { p.badge_fail };
            let pill_border = if ok {
                p.toast_border_rgba
            } else {
                p.hero_tripped.border
            };
            let t_op = self.toast_presence.progress();
            let t_dy = (1.0 - self.toast_presence.raw_progress()) * 14.0;
            let ctrl_dismiss = ctrl_entity.clone();
            let ctrl_primary_act = ctrl_entity.clone();
            let ctrl_copy_path = ctrl_entity.clone();
            let hover_btn = p.sidebar_hover_bg;

            let mut pill = div()
                .id("floating-toast-pill")
                .occlude()
                .max_w(px(620.))
                .flex()
                .items_center()
                .justify_between()
                .gap(px(10.))
                .px(px(13.))
                .py(px(8.))
                .rounded(px(12.))
                .bg(rgba(p.toast_bg_rgba))
                .border_1()
                .border_color(rgba(pill_border))
                .shadow(float_shadow(p))
                .on_mouse_up(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .flex_1()
                        .min_w(px(0.))
                        .child(
                            div()
                                .flex_shrink_0()
                                .w(px(6.5))
                                .h(px(6.5))
                                .rounded(px(999.))
                                .bg(rgb(b.dot)),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .text_size(px(12.))
                                .line_height(px(16.))
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_color(rgb(if ok { p.text_primary } else { b.text }))
                                .child(msg),
                        ),
                );

            let mut right_actions = div().flex().items_center().flex_shrink_0().gap(px(5.));
            if let Some(action) = toast_action {
                match action {
                    ToastAction::OpenExplorerPath(path) => {
                        let p_open = path.clone();
                        let p_copy = path;
                        right_actions = right_actions
                            .child(
                                div()
                                    .id("toast-open-dir")
                                    .px(px(8.))
                                    .py(px(3.))
                                    .rounded(px(7.))
                                    .bg(rgb(p.accent_soft_bg))
                                    .border_1()
                                    .border_color(rgb(p.accent_soft_border))
                                    .text_size(px(11.))
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.accent_soft_text))
                                    .cursor_pointer()
                                    .hover(move |s| s.opacity(0.88))
                                    .child("打开目录")
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            cx.stop_propagation();
                                            let p = p_open.clone();
                                            ctrl_primary_act.update(cx, |c, cx| {
                                                c.open_path_in_explorer_async(p, cx);
                                            });
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .id("toast-copy-path")
                                    .px(px(8.))
                                    .py(px(3.))
                                    .rounded(px(7.))
                                    .bg(rgb(p.secondary_btn_bg))
                                    .border_1()
                                    .border_color(rgb(p.secondary_btn_border))
                                    .text_size(px(11.))
                                    .font_weight(gpui::FontWeight::MEDIUM)
                                    .text_color(rgb(p.text_secondary))
                                    .cursor_pointer()
                                    .hover(move |s| s.bg(rgb(hover_btn)))
                                    .child("复制路径")
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            cx.stop_propagation();
                                            let p = p_copy.clone();
                                            ctrl_copy_path.update(cx, |c, cx| {
                                                c.copy_to_clipboard(p, "诊断包路径", cx);
                                            });
                                        }),
                                    ),
                            );
                    }
                    other => {
                        let lbl: &'static str = match &other {
                            ToastAction::JumpAntigravityRepair => "去热修复 →",
                            ToastAction::RearmNow => "立即布防",
                            ToastAction::JumpBreaker => "去解封 →",
                            ToastAction::CopyText { label, .. } => label,
                            ToastAction::OpenExplorerPath(_) => "打开目录",
                        };
                        right_actions = right_actions.child(
                            div()
                                .id("toast-recovery-pill")
                                .px(px(8.5))
                                .py(px(3.))
                                .rounded(px(7.))
                                .bg(rgb(p.accent_soft_bg))
                                .border_1()
                                .border_color(rgb(p.accent_soft_border))
                                .text_size(px(11.))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(rgb(p.accent_soft_text))
                                .cursor_pointer()
                                .hover(|s| s.opacity(0.88))
                                .child(lbl)
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        cx.stop_propagation();
                                        let act = other.clone();
                                        ctrl_primary_act.update(cx, |c, cx| match act {
                                            ToastAction::JumpAntigravityRepair => {
                                                c.toast = None;
                                                c.toast_action = None;
                                                c.env_tab = EnvSubTab::Antigravity;
                                                c.set_nav(NavSection::Environment, cx);
                                            }
                                            ToastAction::RearmNow => {
                                                c.toast = None;
                                                c.toast_action = None;
                                                c.send_request(
                                                    PipeRequest::Rearm,
                                                    Some("已重新布防，恢复出口守护"),
                                                    cx,
                                                );
                                            }
                                            ToastAction::JumpBreaker => {
                                                c.toast = None;
                                                c.toast_action = None;
                                                c.set_nav(NavSection::Breaker, cx);
                                            }
                                            ToastAction::CopyText { text, .. } => {
                                                c.copy_to_clipboard(text, "命令", cx);
                                            }
                                            ToastAction::OpenExplorerPath(p) => {
                                                c.open_path_in_explorer_async(p, cx);
                                            }
                                        });
                                    }),
                                ),
                        );
                    }
                }
            }

            right_actions = right_actions.child(
                div()
                    .id("toast-dismiss")
                    .flex()
                    .items_center()
                    .justify_center()
                    .w(px(22.))
                    .h(px(22.))
                    .rounded(px(7.))
                    .cursor_pointer()
                    .hover(move |s| s.bg(rgb(hover_btn)))
                    .child(ui_icon("icons/ui/close.svg", 11.0, p.text_muted))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            cx.stop_propagation();
                            ctrl_dismiss.update(cx, |c, cx| {
                                c.toast = None;
                                c.toast_action = None;
                                cx.notify();
                            });
                        }),
                    ),
            );

            pill = pill.child(right_actions);

            // Outer positioning shell has NO `.id` or `.occlude()` so clicks pass through to UI below.
            root = root.child(
                div()
                    .absolute()
                    .bottom(px(62.0 - t_dy))
                    .left_0()
                    .right_0()
                    .px(px(24.))
                    .opacity(t_op)
                    .flex()
                    .justify_center()
                    .child(pill),
            );
        }

        root
    }
}

fn policy_preset_display(preset: PolicyPreset) -> (&'static str, &'static str) {
    match preset {
        PolicyPreset::LooseAntiDirect => ("宽松防直连", "仅防直连，不限出口地区"),
        PolicyPreset::StandardRegion => ("标准地区白名单", "匹配允许地区或静态 IP，越界即熔断"),
        PolicyPreset::StrictStaticIp => ("严格锁定静态 IP", "仅放行已绑定的静态 IP 或网段"),
    }
}

fn render_ceramic_header(
    ctrl: Entity<AppController>,
    tripped: bool,
    is_unconfigured: bool,
    connection_banner: Option<&str>,
    is_maximized: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleHeaderView>,
) -> gpui::Div {
    let ctrl_r = ctrl.read(cx);
    let current_preset = ctrl_r
        .snapshot
        .as_ref()
        .map(|s| s.preset)
        .unwrap_or(PolicyPreset::StandardRegion);
    let (preset_name, _) = policy_preset_display(current_preset);
    let policy_open = ctrl_r.policy_menu_open;
    let theme_menu_open = ctrl_r.theme_menu_open;
    let privacy_mask = ctrl_r.privacy_mask;
    let hud_open = ctrl_r.hud_window.is_some();
    let theme_style = ctrl_r.theme_style;
    let is_dark = p.is_dark;
    let busy = ctrl_r.busy_action;

    let ctrl_pol = ctrl.clone();
    let ctrl_onb = ctrl.clone();
    let ctrl_reconn = ctrl.clone();
    let ctrl_priv = ctrl.clone();
    let ctrl_hud = ctrl.clone();
    let ctrl_theme = ctrl.clone();
    let ctrl_close = ctrl;

    let hover_tile = p.sidebar_hover_bg;

    let mut header = div()
        .flex()
        .flex_shrink_0()
        .items_center()
        .justify_between()
        .w_full()
        .h(px(HEADER_HEIGHT))
        .px(px(2.))
        .gap(px(10.));

    // Left: Sculpted 28px Optical Prism Sanctuary Brand Mark + Policy selector
    let brand_emblem = if tripped {
        div()
            .w(px(28.))
            .h(px(28.))
            .rounded(px(8.5))
            .bg(rgba(p.badge_fail.bg))
            .border_1()
            .border_color(rgba(p.hero_tripped.border))
            .flex()
            .items_center()
            .justify_center()
            .child(ui_icon(
                "icons/ui/shield_alert.svg",
                15.5,
                p.badge_fail.text,
            ))
    } else {
        brand_mark(28.0, p.is_dark)
    };
    let mut left_group = div()
        .flex()
        .items_center()
        .gap(px(9.))
        .child(brand_emblem)
        .child(
            div()
                .text_size(px(14.))
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(rgb(p.text_primary))
                .child("ClaudeGuard"),
        )
        .child(
            div()
                .id("header-policy-select")
                .flex()
                .items_center()
                .gap(px(6.))
                .h(px(28.))
                .px(px(10.))
                .rounded(px(8.))
                .bg(rgb(p.card_bg))
                .border_1()
                .border_color(rgb(if policy_open {
                    p.primary_btn_bg
                } else {
                    p.line_strong
                }))
                .cursor_pointer()
                .hover(move |s| s.bg(rgb(hover_tile)))
                .active(|s| s.opacity(0.90))
                .child(
                    div()
                        .text_size(px(11.5))
                        .text_color(rgb(p.text_muted))
                        .child("策略"),
                )
                .child(
                    div()
                        .text_size(px(11.5))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(rgb(p.text_primary))
                        .child(preset_name),
                )
                .child(
                    ui_icon("icons/ui/chevrons.svg", 12.5, p.text_muted).with_spring(
                        "policy-chevron-spin",
                        SpringAnimation::new(spring_snappy())
                            .to(policy_open)
                            .with_epsilon(0.004),
                        |icon, phase| {
                            icon.with_transformation(Transformation::rotate(radians(
                                std::f32::consts::PI * phase.0.clamp(0.0, 1.0),
                            )))
                        },
                    ),
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        cx.stop_propagation();
                        ctrl_pol.update(cx, |c, cx| {
                            c.policy_menu_open = !c.policy_menu_open;
                            c.theme_menu_open = false;
                            c.open_region_picker_for = None;
                            cx.notify();
                        });
                    }),
                ),
        );

    if is_unconfigured {
        left_group = left_group.child(
            div()
                .id("header-open-onboarding")
                .flex()
                .items_center()
                .gap(px(5.))
                .h(px(28.))
                .px(px(10.))
                .rounded(px(8.))
                .bg(rgb(p.accent_soft_bg))
                .border_1()
                .border_color(rgb(p.accent_soft_border))
                .cursor_pointer()
                .hover(|s| s.opacity(0.90))
                .active(|s| s.opacity(0.82))
                .text_size(px(11.5))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .text_color(rgb(p.accent_soft_text))
                .child("首启向导")
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_onb.update(cx, |c, cx| c.open_onboarding_modal(cx));
                    }),
                ),
        );
    }

    // Center draggable area (embeds compact offline reconnect pill with ZERO vertical layout shift)
    let center_area = if let Some(banner_msg) = connection_banner {
        let short_msg: String = banner_msg.chars().take(18).collect();
        div()
            .flex()
            .flex_1()
            .h_full()
            .items_center()
            .justify_center()
            .window_control_area(WindowControlArea::Drag)
            .child(
                div()
                    .id("header-offline-pill")
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .h(px(26.))
                    .px(px(10.))
                    .rounded(px(999.))
                    .bg(rgba(p.badge_warn.bg))
                    .border_1()
                    .border_color(rgba(p.hero_disarmed.border))
                    .cursor_pointer()
                    .hover(|s| s.opacity(0.88))
                    .child(spinning_ui_icon(
                        "header-reconn-spin",
                        "icons/ui/refresh.svg",
                        11.0,
                        p.badge_warn.text,
                        busy,
                    ))
                    .child(
                        div()
                            .text_size(px(11.))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_color(rgb(p.badge_warn.text))
                            .child(if busy {
                                "重连守护服务…".to_string()
                            } else {
                                format!("守护未连接 · {short_msg} · 重连")
                            }),
                    )
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            cx.stop_propagation();
                            if !busy {
                                ctrl_reconn.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::GetSnapshot,
                                        Some("已重新连接守护服务"),
                                        cx,
                                    );
                                });
                            }
                        }),
                    ),
            )
    } else {
        div()
            .flex_1()
            .h_full()
            .window_control_area(WindowControlArea::Drag)
    };

    header = header
        .child(left_group)
        .child(center_area)
        // Right utility chips + multi-theme popover pill + calm window controls
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(6.))
                .child(
                    div()
                        .id("privacy-mask-toggle")
                        .flex()
                        .items_center()
                        .gap(px(5.))
                        .h(px(28.))
                        .px(px(10.))
                        .rounded(px(999.))
                        .bg(rgb(if privacy_mask {
                            p.accent_soft_bg
                        } else {
                            p.card_bg
                        }))
                        .border_1()
                        .border_color(rgb(if privacy_mask {
                            p.accent_soft_border
                        } else {
                            p.card_border
                        }))
                        .cursor_pointer()
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .active(|s| s.opacity(0.90))
                        .text_size(px(11.5))
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_color(rgb(if privacy_mask {
                            p.accent_soft_text
                        } else {
                            p.text_secondary
                        }))
                        .child(ui_icon(
                            "icons/ui/eye.svg",
                            13.0,
                            if privacy_mask {
                                p.accent_soft_text
                            } else {
                                p.text_secondary
                            },
                        ))
                        .child(if privacy_mask {
                            "已脱敏"
                        } else {
                            "IP 脱敏"
                        })
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_priv.update(cx, |c, cx| c.toggle_privacy_mask(cx));
                            }),
                        ),
                )
                .child(
                    div()
                        .id("header-open-hud")
                        .flex()
                        .items_center()
                        .h(px(28.))
                        .px(px(10.))
                        .rounded(px(999.))
                        .bg(rgb(if hud_open {
                            p.accent_soft_bg
                        } else {
                            p.card_bg
                        }))
                        .border_1()
                        .border_color(rgb(if hud_open {
                            p.accent_soft_border
                        } else {
                            p.card_border
                        }))
                        .cursor_pointer()
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .active(|s| s.opacity(0.90))
                        .text_size(px(11.5))
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_color(rgb(if hud_open {
                            p.accent_soft_text
                        } else {
                            p.text_secondary
                        }))
                        .child("托盘 HUD")
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                toggle_hud_window(ctrl_hud.clone(), cx);
                            }),
                        ),
                )
                .child(
                    div()
                        .id("header-theme-toggle")
                        .flex()
                        .items_center()
                        .justify_center()
                        .gap(px(5.5))
                        .h(px(28.))
                        .px(px(10.))
                        .rounded(px(999.))
                        .bg(rgb(p.card_bg))
                        .border_1()
                        .border_color(rgb(if theme_menu_open {
                            p.primary_btn_bg
                        } else {
                            p.card_border
                        }))
                        .cursor_pointer()
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .active(|s| s.opacity(0.90))
                        .child(
                            div()
                                .flex_shrink_0()
                                .w(px(8.5))
                                .h(px(8.5))
                                .rounded(px(999.))
                                .bg(rgb(theme_style.swatch_accent(is_dark)))
                                .border_1()
                                .border_color(rgb(p.card_border)),
                        )
                        .child(
                            div()
                                .text_size(px(11.5))
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_color(rgb(if theme_menu_open {
                                    p.text_primary
                                } else {
                                    p.text_secondary
                                }))
                                .child(theme_style.label()),
                        )
                        .child(ui_icon(
                            if is_dark {
                                "icons/ui/moon.svg"
                            } else {
                                "icons/ui/sun.svg"
                            },
                            11.5,
                            p.text_secondary,
                        ))
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                cx.stop_propagation();
                                ctrl_theme.update(cx, |c, cx| {
                                    c.theme_menu_open = !c.theme_menu_open;
                                    c.policy_menu_open = false;
                                    c.open_region_picker_for = None;
                                    cx.notify();
                                });
                            }),
                        ),
                )
                .child(div().w(px(1.)).h(px(14.)).bg(rgb(p.card_border)).mx(px(2.)))
                .child(
                    win_ctrl_btn("win-min", "icons/ui/win_min.svg", false, p)
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|_, _, window, cx| {
                                cx.stop_propagation();
                                if !minimize_window_smooth("ClaudeGuard v4") {
                                    window.minimize_window();
                                }
                            }),
                        ),
                )
                .child(
                    win_ctrl_btn(
                        "win-max",
                        if is_maximized {
                            "icons/ui/win_restore.svg"
                        } else {
                            "icons/ui/win_max.svg"
                        },
                        false,
                        p,
                    )
                    .window_control_area(WindowControlArea::Max)
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|_, _, window, cx| {
                            cx.stop_propagation();
                            if !toggle_maximize_window_smooth("ClaudeGuard v4") {
                                window.zoom_window();
                            }
                        }),
                    ),
                )
                .child(
                    win_ctrl_btn("win-close", "icons/ui/close.svg", true, p).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, window, cx| {
                            let (close_to_tray, has_tray) = {
                                let r = ctrl_close.read(cx);
                                let ctt = r
                                    .snapshot
                                    .as_ref()
                                    .map(|s| s.config.close_to_tray)
                                    .unwrap_or(true);
                                (ctt, r.tray.is_some())
                            };
                            ctrl_close.update(cx, |c, _| c.console_window = None);
                            window.remove_window();
                            if !close_to_tray || !has_tray {
                                ctrl_close.update(cx, |c, _| {
                                    if let Some(mut tray) = c.tray.take() {
                                        tray.shutdown();
                                    }
                                });
                                cx.quit();
                            }
                        }),
                    ),
                ),
        );
    header
}

fn render_policy_dropdown_overlay(
    ctrl: Entity<AppController>,
    progress: f32,
    raw_progress: f32,
    interactive: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Stateful<gpui::Div> {
    let ctrl_r = ctrl.read(cx);
    let current_preset = ctrl_r
        .snapshot
        .as_ref()
        .map(|s| s.preset)
        .unwrap_or(PolicyPreset::StandardRegion);
    let can_switch = interactive && ctrl_r.connected && !ctrl_r.busy_action;

    let options: Vec<_> = POLICY_PRESETS
        .into_iter()
        .map(|preset| {
            let active = preset == current_preset;
            let (title, desc) = policy_preset_display(preset);
            let ctrl_p = ctrl.clone();
            let hover = p.sidebar_hover_bg;
            div()
                .id(gpui::ElementId::Name(format!("pol-opt-{preset:?}").into()))
                .flex()
                .items_start()
                .justify_between()
                .gap(px(10.))
                .w_full()
                .px(px(10.))
                .py(px(8.))
                .rounded(px(9.))
                .cursor_pointer()
                .bg(rgb(if active { p.accent_soft_bg } else { p.card_bg }))
                .hover(move |s| s.bg(rgb(hover)))
                .active(|s| s.opacity(0.90))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(0.))
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(12.))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(rgb(if active {
                                    p.accent_soft_text
                                } else {
                                    p.text_primary
                                }))
                                .child(title),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .line_height(px(15.))
                                .text_color(rgb(p.text_muted))
                                .child(desc),
                        ),
                )
                .when(active, |row| {
                    row.child(div().pt(px(2.)).child(ui_icon(
                        "icons/ui/check.svg",
                        14.0,
                        p.accent_soft_text,
                    )))
                })
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        cx.stop_propagation();
                        ctrl_p.update(cx, |c, cx| {
                            c.policy_menu_open = false;
                            if can_switch {
                                c.set_preset(preset, cx);
                            } else {
                                cx.notify();
                            }
                        });
                    }),
                )
        })
        .collect();

    let ctrl_bg = ctrl;
    let slide_y = (1.0 - raw_progress) * -8.0;
    let menu_shadow = vec![
        BoxShadow::new(
            px(0.),
            px(14.),
            rgba_with_alpha_scale(p.shadow_float_rgba, progress).into(),
        )
        .blur_radius(px(34.))
        .spread_radius(px(-4.)),
    ];

    div()
        .id("policy-dropdown-backdrop")
        .absolute()
        .inset_0()
        .when(interactive, |bg| {
            bg.on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_bg.update(cx, |c, cx| {
                        c.policy_menu_open = false;
                        cx.notify();
                    });
                }),
            )
        })
        .child(
            div()
                .id("policy-dropdown-menu")
                .occlude()
                .absolute()
                .top(px(52.0 + slide_y))
                .left(px(140.))
                .w(px(300.))
                .p(px(5.))
                .gap(px(2.))
                .opacity(progress)
                .flex()
                .flex_col()
                .rounded(px(13.))
                .bg(rgb(p.card_bg))
                .border_1()
                .border_color(rgb(p.line_strong))
                .shadow(menu_shadow)
                .on_mouse_up(MouseButton::Left, |_, _, cx| {
                    cx.stop_propagation();
                })
                .children(options),
        )
}

fn render_theme_popover_overlay(
    ctrl: Entity<AppController>,
    progress: f32,
    raw_progress: f32,
    interactive: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Stateful<gpui::Div> {
    let ctrl_r = ctrl.read(cx);
    let current_mode = ctrl_r.theme_mode;
    let current_style = ctrl_r.theme_style;
    let is_dark = p.is_dark;

    let mode_hint = if current_mode == ThemeMode::Auto {
        if is_dark {
            "跟随系统 · 暗夜"
        } else {
            "跟随系统 · 浅色"
        }
    } else {
        theme_mode_label(current_mode)
    };

    let mode_items: Vec<_> = THEME_MODES
        .into_iter()
        .map(|mode| {
            let active = mode == current_mode;
            let ctrl_m = ctrl.clone();
            segmented_capsule_item(
                gpui::ElementId::Name(format!("theme-mode-{mode:?}").into()),
                theme_mode_label(mode),
                active,
                p,
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    cx.stop_propagation();
                    if interactive {
                        ctrl_m.update(cx, |c, cx| {
                            if c.theme_mode != mode {
                                c.set_theme_mode(mode, cx);
                            }
                        });
                    }
                }),
            )
        })
        .collect();

    let style_cards: Vec<_> = THEME_STYLES
        .into_iter()
        .map(|style| {
            let active = style == current_style;
            let ctrl_s = ctrl.clone();
            let hover_bg = p.sidebar_hover_bg;
            let hover_border = p.card_border;

            div()
                .id(gpui::ElementId::Name(
                    format!("theme-style-{}", style.key()).into(),
                ))
                .flex()
                .items_center()
                .justify_between()
                .gap(px(10.))
                .w_full()
                .px(px(9.))
                .py(px(6.))
                .rounded(px(10.))
                .border_1()
                .bg(rgb(if active { p.accent_soft_bg } else { p.card_bg }))
                .border_color(rgb(if active {
                    p.accent_soft_border
                } else {
                    p.card_bg
                }))
                .cursor_pointer()
                .when(!active, |row| {
                    row.hover(move |s| s.bg(rgb(hover_bg)).border_color(rgb(hover_border)))
                })
                .active(|s| s.opacity(0.92))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .flex_1()
                        .min_w(px(0.))
                        .child(
                            div()
                                .flex_shrink_0()
                                .w(px(26.))
                                .h(px(20.))
                                .rounded(px(6.))
                                .bg(rgb(style.swatch_surface(is_dark)))
                                .border_1()
                                .border_color(rgb(p.line_strong))
                                .flex()
                                .items_center()
                                .justify_center()
                                .child(
                                    div()
                                        .w(px(10.))
                                        .h(px(10.))
                                        .rounded(px(999.))
                                        .bg(rgb(style.swatch_accent(is_dark))),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w(px(0.))
                                .gap(px(1.5))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .text_color(rgb(if active {
                                            p.accent_soft_text
                                        } else {
                                            p.text_primary
                                        }))
                                        .child(style.label()),
                                )
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .line_height(px(14.))
                                        .text_color(rgb(p.text_muted))
                                        .child(style.tagline()),
                                ),
                        ),
                )
                .when(active, |row| {
                    row.child(ui_icon("icons/ui/check.svg", 13.5, p.accent_soft_text))
                })
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        cx.stop_propagation();
                        if interactive {
                            ctrl_s.update(cx, |c, cx| c.set_theme_style(style, cx));
                        }
                    }),
                )
        })
        .collect();

    let ctrl_bg = ctrl;
    let slide_y = (1.0 - raw_progress) * -8.0;

    div()
        .id("theme-popover-backdrop")
        .absolute()
        .inset_0()
        .when(interactive, |bg| {
            bg.on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    cx.stop_propagation();
                    ctrl_bg.update(cx, |c, cx| {
                        c.theme_menu_open = false;
                        cx.notify();
                    });
                }),
            )
        })
        .child(
            div()
                .id("theme-popover-menu")
                .occlude()
                .absolute()
                .top(px(52.0 + slide_y))
                .right(px(110.))
                .w(px(284.))
                .p(px(9.))
                .gap(px(5.))
                .opacity(progress)
                .flex()
                .flex_col()
                .rounded(px(14.))
                .bg(rgb(p.card_bg))
                .border_1()
                .border_color(rgb(p.line_strong))
                .shadow(float_shadow(p))
                .on_mouse_up(MouseButton::Left, |_, _, cx| {
                    cx.stop_propagation();
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .px(px(2.))
                        .child(
                            div()
                                .text_size(px(11.))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_muted))
                                .child("外观模式"),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child(mode_hint),
                        ),
                )
                .child(segmented_capsule_track(p).children(mode_items))
                .child(div().w_full().h(px(1.)).bg(rgb(p.card_border)).my(px(4.)))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .px(px(2.))
                        .child(
                            div()
                                .text_size(px(11.))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_muted))
                                .child("色彩风格"),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child("实时预览"),
                        ),
                )
                .child(div().flex().flex_col().gap(px(3.)).children(style_cards)),
        )
}

struct DockRenderState {
    active_nav: NavSection,
    active_nav_idx: usize,
    pill_geom: Option<(f32, f32)>,
    active_icon_dy: f32,
    active_icon_scale: f32,
    vault_active: bool,
    cleanroom_alert: bool,
    targets_alert: bool,
    targets_dirty: bool,
    env_alert: bool,
    has_update: bool,
}

fn render_ceramic_dock(
    ctrl: Entity<AppController>,
    st: DockRenderState,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Div {
    let DockRenderState {
        active_nav,
        active_nav_idx,
        pill_geom,
        active_icon_dy,
        active_icon_scale,
        vault_active,
        cleanroom_alert,
        targets_alert,
        targets_dirty,
        env_alert,
        has_update,
    } = st;
    let target_dot = if targets_alert {
        Some(p.badge_fail.dot)
    } else if targets_dirty {
        Some(p.badge_warn.dot)
    } else {
        None
    };

    let items: [(NavSection, &'static str, &'static str, Option<u32>); 9] = [
        (NavSection::Overview, "总览", "icons/ui/home.svg", None),
        (
            NavSection::Vaults,
            "多账号仓",
            "icons/ui/lock.svg",
            vault_active.then_some(p.badge_pass.dot),
        ),
        (
            NavSection::CleanRoom,
            "防连坐",
            "icons/ui/shield.svg",
            cleanroom_alert.then_some(p.badge_warn.dot),
        ),
        (
            NavSection::Targets,
            "目标",
            "icons/ui/globe.svg",
            target_dot,
        ),
        (NavSection::Breaker, "熔断", "icons/ui/flame.svg", None),
        (
            NavSection::Environment,
            "防漏",
            "icons/ui/radar.svg",
            env_alert.then_some(p.badge_fail.dot),
        ),
        (NavSection::Audit, "审计", "icons/ui/clock.svg", None),
        (
            NavSection::Updates,
            "更新",
            "icons/ui/download.svg",
            has_update.then_some(p.badge_warn.dot),
        ),
        (NavSection::Notify, "通知", "icons/ui/bell.svg", None),
    ];

    let dock_btns =
        items.into_iter().map(|(sec, label, icon_path, dot)| {
            let active = sec == active_nav;
            let ctrl_n = ctrl.clone();
            let fg = if active {
                p.sidebar_active_text
            } else {
                p.text_secondary
            };
            let hover_bg = p.sidebar_hover_bg;
            let hover_txt = p.text_primary;

            let dock_icon =
                if active {
                    div()
                        .relative()
                        .top(px(active_icon_dy))
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(ui_icon(icon_path, 14.0, fg).with_transformation(
                            Transformation::scale(size(active_icon_scale, active_icon_scale)),
                        ))
                        .into_any_element()
                } else {
                    ui_icon(icon_path, 14.0, fg).into_any_element()
                };

            let mut btn = div()
                .id(gpui::ElementId::Name(format!("dock-{sec:?}").into()))
                .relative()
                .flex()
                .items_center()
                .justify_center()
                .gap(px(6.))
                .h(px(32.))
                .px(px(12.))
                .rounded(px(10.5))
                .cursor_pointer()
                .text_size(px(12.))
                .font_weight(if active {
                    gpui::FontWeight::SEMIBOLD
                } else {
                    gpui::FontWeight::MEDIUM
                })
                .text_color(rgb(fg))
                .active(|s| s.opacity(0.86))
                .child(dock_icon)
                .child(label);

            if active {
                // Fallback solid pill only on frame 0 before `on_children_prepainted` measures bounds.
                if pill_geom.is_none() {
                    btn = btn
                        .bg(rgb(p.sidebar_active_bg))
                        .border_1()
                        .border_color(rgb(p.sidebar_active_border));
                }
            } else {
                btn = btn.hover(move |s| s.bg(rgb(hover_bg)).text_color(rgb(hover_txt)));
                if let Some(dot_rgb) = dot {
                    btn = btn.child(
                        div()
                            .absolute()
                            .top(px(5.))
                            .right(px(5.))
                            .w(px(5.5))
                            .h(px(5.5))
                            .rounded(px(999.))
                            .bg(rgb(dot_rgb)),
                    );
                }
            }

            btn.on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    cx.stop_propagation();
                    ctrl_n.update(cx, |c, cx| c.set_nav(sec, cx));
                }),
            )
        });

    let view_weak = cx.entity().downgrade();
    let buttons_row = div()
        .relative()
        .flex()
        .items_center()
        .gap(px(3.))
        .on_children_prepainted(move |bounds: Vec<Bounds<gpui::Pixels>>, window, cx| {
            if let Some(first) = bounds.first() {
                let origin_x = first.left().as_f32();
                let reduce_motion = cx.reduce_motion();
                let _ = view_weak.update(cx, |view, _| {
                    let was_init = view.dock_indicator.geometry().is_some();
                    view.dock_indicator.record_bounds(
                        origin_x,
                        &bounds,
                        active_nav_idx,
                        reduce_motion,
                    );
                    if !was_init || view.dock_indicator.is_active() {
                        window.request_animation_frame();
                    }
                });
            }
        })
        .children(dock_btns);

    let mut inner_track = div().relative().flex().items_center();
    if let Some((pill_x, pill_w)) = pill_geom {
        inner_track = inner_track.child(liquid_glass_pill(pill_x, pill_w, 10.5, p));
    }
    inner_track = inner_track.child(buttons_row);

    div()
        .flex()
        .flex_shrink_0()
        .w_full()
        .justify_center()
        .pt(px(1.))
        .child(
            div()
                .flex()
                .items_center()
                .p(px(4.))
                .rounded(px(15.))
                .bg(rgb(p.sidebar_bg))
                .border_1()
                .border_color(rgb(p.card_border))
                .shadow(vec![
                    BoxShadow::new(px(0.), px(1.), rgba(p.specular_top_rgba).into()).inset(),
                    BoxShadow::new(px(0.), px(2.), rgba(p.shadow_rgba).into()).blur_radius(px(6.)),
                    BoxShadow::new(px(0.), px(10.), rgba(p.shadow_float_rgba).into())
                        .blur_radius(px(26.))
                        .spread_radius(px(-6.)),
                ])
                .child(inner_track),
        )
}

fn win_ctrl_btn(
    id: &'static str,
    icon_path: &'static str,
    danger: bool,
    p: &'static ThemePalette,
) -> gpui::Stateful<gpui::Div> {
    let hover_bg = if danger {
        rgba(p.badge_fail.bg)
    } else {
        rgb(p.sidebar_hover_bg)
    };
    let hover_border = if danger {
        rgba(p.hero_tripped.border)
    } else {
        rgb(p.card_hover_border)
    };
    let icon_fg = p.text_secondary;
    div()
        .id(id)
        .flex()
        .items_center()
        .justify_center()
        .w(px(27.))
        .h(px(27.))
        .rounded(px(7.5))
        .bg(rgb(p.card_bg))
        .border_1()
        .border_color(rgb(p.card_border))
        .shadow(vec![
            BoxShadow::new(px(0.), px(1.), rgba(p.specular_top_rgba).into()).inset(),
        ])
        .cursor_pointer()
        .hover(move |s| s.bg(hover_bg).border_color(hover_border))
        .active(|s| s.opacity(0.84))
        .child(ui_icon(icon_path, 12.0, icon_fg))
}

/// Launches the GPUI desktop application + Win32 tray loop.
pub fn run(args: LaunchArgs) {
    let is_demo = matches!(args.endpoint, TransportEndpoint::Demo(_));
    let _single_instance_guard = if !is_demo {
        match acquire_single_instance() {
            SingleInstanceOutcome::Acquired(guard) => {
                if signal_existing_tray_instance(false, args.start_hud, args.start_in_tray) {
                    return;
                }
                Some(guard)
            }
            SingleInstanceOutcome::AlreadyRunning => {
                for attempt in 0..5 {
                    if signal_existing_tray_instance(false, args.start_hud, args.start_in_tray) {
                        break;
                    }
                    if attempt < 4 {
                        std::thread::sleep(Duration::from_millis(40));
                    }
                }
                return;
            }
        }
    } else {
        if signal_existing_tray_instance(true, args.start_hud, args.start_in_tray) {
            return;
        }
        None
    };

    let tray_channel = TrayChannel::new();
    let tray_handle = match TrayHandle::start(tray_channel.clone()) {
        Ok(h) => Some(h),
        Err(err) => {
            eprintln!("警告：托盘图标初始化失败：{err}");
            None
        }
    };

    application()
        .with_assets(EmbeddedAssets)
        .with_quit_mode(gpui::QuitMode::Explicit)
        .run(move |cx: &mut App| {
            sync_windows_reduce_motion(cx);
            text_input::bind_keys(cx);
            cx.bind_keys([
                KeyBinding::new("ctrl-k", FocusGlobalSearch, Some("ConsoleWindow")),
                KeyBinding::new("tab", FocusNextField, Some("ConsoleWindow")),
                KeyBinding::new("shift-tab", FocusPrevField, Some("ConsoleWindow")),
                KeyBinding::new("escape", DismissConsoleOverlay, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-s", SaveCurrentView, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-r", RefreshCurrentView, Some("ConsoleWindow")),
                KeyBinding::new("f5", RefreshCurrentView, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-1", NavTab1, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-2", NavTab2, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-3", NavTab3, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-4", NavTab4, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-5", NavTab5, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-6", NavTab6, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-7", NavTab7, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-8", NavTab8, Some("ConsoleWindow")),
                KeyBinding::new("ctrl-9", NavTab9, Some("ConsoleWindow")),
                KeyBinding::new("escape", DismissHudWindow, Some("HudWindow")),
            ]);

            let ctrl = cx.new(|cx| AppController::new(&args, tray_handle, cx));

            // Bridge Win32 tray events into GPUI main thread with zero polling.
            let ctrl_tray = ctrl.clone();
            cx.spawn(async move |cx| {
                while let Some(ev) = tray_channel.recv_async().await {
                    cx.update(|cx| {
                        handle_tray_event(ctrl_tray.clone(), ev, cx);
                    });
                }
            })
            .detach();

            if args.start_hud {
                open_hud_window(ctrl.clone(), cx);
            } else if !args.start_in_tray {
                open_console_window(ctrl.clone(), cx);
            }
            cx.activate(true);
        });
}

fn handle_tray_event(ctrl: Entity<AppController>, event: TrayEvent, cx: &mut App) {
    match event {
        TrayEvent::ToggleHud => toggle_hud_window(ctrl, cx),
        TrayEvent::OpenConsole => {
            open_console_window(ctrl, cx);
            cx.activate(true);
        }
        TrayEvent::RecheckNow => {
            ctrl.update(cx, |c, cx| {
                c.send_request(
                    PipeRequest::RecheckNow { target_id: None },
                    Some("已触发全量出口重检"),
                    cx,
                );
            });
        }
        TrayEvent::TogglePause => {
            ctrl.update(cx, |c, cx| c.toggle_pause_30m(cx));
        }
        TrayEvent::SweepOrphans => {
            ctrl.update(cx, |c, cx| {
                c.send_request(PipeRequest::SweepOrphans, Some("已清理孤儿进程"), cx);
            });
        }
        TrayEvent::PanicLockdown => {
            ctrl.update(cx, |c, cx| {
                if let Some(tray) = c.tray.as_ref() {
                    tray.show_balloon(
                        "ClaudeGuard 紧急防封锁死",
                        "已触发全局紧急防封锁死，所有 AI 客户端出站流量正在瞬间切断！",
                        true,
                    );
                }
                c.send_request(
                    PipeRequest::TriggerPanicLockdown,
                    Some("已触发紧急防封锁死，AI 出站流量已瞬间切断"),
                    cx,
                );
            });
        }
        TrayEvent::QuitGuiOnly => {
            ctrl.update(cx, |c, _| {
                if let Some(mut tray) = c.tray.take() {
                    tray.shutdown();
                }
            });
            cx.quit();
        }
        TrayEvent::SystemShuttingDown => {
            let client = ctrl.read(cx).client.clone();
            cx.background_executor()
                .spawn(async move {
                    let _ = client.exchange(PipeRequest::NotifySystemShutdown);
                })
                .detach();
        }
        TrayEvent::SafeExit => {
            if ctrl.read(cx).is_scope_busy(&ActionScope::Flow) {
                return;
            }
            let client = ctrl.read(cx).client.clone();
            ctrl.update(cx, |c, cx| {
                c.in_flight.insert(ActionScope::Flow);
                c.busy_action = true;
                cx.notify();
            });
            cx.spawn(async move |cx| {
                let res = cx
                    .background_executor()
                    .spawn(async move {
                        client.exchange(PipeRequest::DisarmAndRestoreFlowB {
                            reason: Some("用户通过托盘安全撤防并退出".into()),
                        })
                    })
                    .await;
                cx.update(|cx| {
                    let outcome: Result<(), String> = match res {
                        Ok(PipeResponse::Snapshot { snapshot }) => {
                            ctrl.update(cx, |c, cx| c.apply_snapshot(*snapshot, cx));
                            Ok(())
                        }
                        Ok(PipeResponse::Ack { receipt, snapshot }) => {
                            if let Some(snap) = snapshot {
                                ctrl.update(cx, |c, cx| c.apply_snapshot(*snap, cx));
                            }
                            if let Some(rc) = receipt
                                && rc.status == OperationStatus::Failed
                            {
                                let detail = rc.error.filter(|s| !s.is_empty()).unwrap_or_else(
                                    || format!("撤防未通过：{}", rc.verified_scope),
                                );
                                Err(detail)
                            } else {
                                Ok(())
                            }
                        }
                        Ok(PipeResponse::Error { message, .. }) => Err(message),
                        Ok(_) => Err("守护服务返回未知响应".into()),
                        Err(err) => Err(err.to_string()),
                    };

                    match outcome {
                        Ok(()) => {
                            ctrl.update(cx, |c, _| {
                                c.in_flight.remove(&ActionScope::Flow);
                                c.busy_action = !c.in_flight.is_empty();
                                if let Some(mut tray) = c.tray.take() {
                                    tray.shutdown();
                                }
                            });
                            cx.quit();
                        }
                        Err(err_detail) => {
                            let fallback_msg = format!(
                                "安全撤防失败（{err_detail}），已保留托盘以防残留隔离锁网；可执行 claudeguard-cli --restore 应急解封"
                            );
                            open_console_window(ctrl.clone(), cx);
                            cx.activate(true);
                            ctrl.update(cx, |c, cx| {
                                c.in_flight.remove(&ActionScope::Flow);
                                c.busy_action = !c.in_flight.is_empty();
                                if let Some(tray) = c.tray.as_ref() {
                                    tray.show_balloon(
                                        "ClaudeGuard 安全撤防未完成",
                                        &fallback_msg,
                                        true,
                                    );
                                }
                                c.set_toast_with_action(
                                    fallback_msg,
                                    false,
                                    Some(ToastAction::CopyText {
                                        label: "复制应急命令",
                                        text: "claudeguard-cli --restore".into(),
                                    }),
                                    cx,
                                );
                                cx.notify();
                            });
                        }
                    }
                });
            })
            .detach();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_args(items: &[&str]) -> std::vec::IntoIter<String> {
        items
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn parses_cli_flags_for_tray_hud_demo_and_pipe() {
        let tray = parse_args(vec_args(&["--tray"])).expect("tray args");
        assert!(tray.start_in_tray);
        assert!(!tray.start_hud);

        let hud_demo = parse_args(vec_args(&["--hud", "--demo", "trip"])).expect("hud demo");
        assert!(hud_demo.start_hud);
        assert_eq!(
            hud_demo.endpoint,
            TransportEndpoint::Demo(DemoScenario::Trip)
        );

        let piped = parse_args(vec_args(&["--guardian-pipe", r"\\.\pipe\test-v4"])).expect("pipe");
        assert_eq!(
            piped.endpoint,
            TransportEndpoint::Pipe(r"\\.\pipe\test-v4".to_string())
        );

        assert_eq!(parse_args(vec_args(&["--help"])), Err(USAGE.to_string()));
        assert!(parse_args(vec_args(&["--demo", "invalid"])).is_err());

        let vaults = parse_args(vec_args(&["--nav", "vaults"])).expect("nav vaults");
        assert_eq!(vaults.initial_nav, NavSection::Vaults);
        let cleanroom = parse_args(vec_args(&["--nav", "cleanroom"])).expect("nav cleanroom");
        assert_eq!(cleanroom.initial_nav, NavSection::CleanRoom);
    }

    #[test]
    fn scope_for_request_isolates_shield_feishu_env_and_per_component_updates() {
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::SyncLeakShield),
            Some(ActionScope::SyncLeakShield)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::TestFeishu {
                webhook: None,
                secret: None,
            }),
            Some(ActionScope::TestFeishu)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::ApplyEnvAlignment {
                align_tz: true,
                align_location: false,
            }),
            Some(ActionScope::EnvAlign)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::RollbackEnvAlignment),
            Some(ActionScope::EnvAlign)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::CheckUpdates {
                component: Some("ag_capsule".into()),
            }),
            Some(ActionScope::UpdatesComponent("ag_capsule".into()))
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::CheckUpdates { component: None }),
            Some(ActionScope::UpdatesAll)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::RunDeepRiskAudit),
            Some(ActionScope::DeepRiskAudit)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::ScanCleanRoom {
                scope: CleanRoomScope::default(),
            }),
            Some(ActionScope::CleanRoomScan)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::BuildHealthCard { export_png: true }),
            Some(ActionScope::BuildHealthCard)
        );
        assert_eq!(
            AppController::scope_for_request(&PipeRequest::TriggerPanicLockdown),
            Some(ActionScope::Flow)
        );
    }
}
