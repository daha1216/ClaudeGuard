//! Root GPUI application controller, Dual-Mode window manager (HUD + Console),
//! zero-VRAM lifecycle, background IPC polling, and Win32 tray integration.

use crate::assets::{EmbeddedAssets, ui_icon};
use crate::demo::DemoScenario;
use crate::ipc::{DaemonClient, TransportEndpoint, launch_agent_normal_user};
use crate::protocol::{
    ANCHOR_KINDS, AnchorKind, Config, DEFAULT_PIPE_NAME, GuardSnapshot, Lifecycle, LogEntry,
    LogLevel, OnboardingProbeResult, OperationStatus, POLICY_PRESETS, PipeRequest, PipeResponse,
    PolicyPreset, Target, UpdateCheckPhase,
};
use crate::state::{
    DraftStore, NavSection, TargetDraft, project_console, project_hud, split_tokens,
};
use crate::theme::{
    BadgeTone, ThemeMode, ThemePalette, layout, resolve_palette, system_prefers_light_theme,
};
use crate::tray_win::{
    LogicalRect, TrayChannel, TrayEvent, TrayHandle, TrayTone, apply_win11_round_corners,
    compute_hud_bounds, primary_work_area_logical, signal_existing_tray_instance,
};
use crate::views;
use crate::widgets::controls::{ButtonKind, action_button, bento_card, status_pill};
use crate::widgets::text_input::{self, ActivePaletteGlobal, DraftTextInput};
use gpui::{
    App, Bounds, BoxShadow, Context, Entity, FocusHandle, Focusable, KeyBinding, MouseButton,
    TitlebarOptions, UniformListScrollHandle, Window, WindowBounds, WindowControlArea, WindowKind,
    WindowOptions, actions, div, point, prelude::*, px, rgb, rgba, size,
};
use gpui_platform::application;
use std::collections::HashMap;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

actions!([FocusGlobalSearch, DismissHudWindow]);

/// Sub-tabs for Mode B `熔断` page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BreakerSubTab {
    #[default]
    Rules,
    Live,
}

/// Sub-tabs for Mode B `防漏` page (no Mihomo proxy-policy mutation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnvSubTab {
    #[default]
    Shield,
    Antigravity,
    Timezone,
}

/// Sub-tabs for Mode B `通知` page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NotifySubTab {
    #[default]
    Events,
    Feishu,
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
    "用法：claudeguard-gui [--tray | --hud] [--nav overview|targets|breaker|env|audit|updates|notify] [--subtab <name>] [--plugins] [--theme light|dark|auto] [--demo pass|trip|disarmed|wizard] [--pipe <端点>]\n",
    "\n",
    "  --tray                    启动后驻留系统托盘（0 窗口、0 VRAM），点击托盘呼出 HUD\n",
    "  --hud                     启动即打开 Mode A 快捷托盘 HUD (398x432)\n",
    "  --nav <section>           指定主控制台默认打开的页面（默认 overview）\n",
    "  --subtab <name>           指定子标签（rules|live|shield|antigravity|tz|events|feishu）\n",
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
}

/// Central controller entity managing daemon IPC, drafts, theme, tray, and dual windows.
pub struct AppController {
    pub client: DaemonClient,
    pub snapshot: Option<GuardSnapshot>,
    pub connected: bool,
    pub connection_err: Option<String>,
    pub theme_mode: ThemeMode,
    pub system_prefers_light: bool,
    pub privacy_mask: bool,
    pub nav_section: NavSection,
    pub policy_menu_open: bool,
    pub breaker_tab: BreakerSubTab,
    pub env_tab: EnvSubTab,
    pub notify_tab: NotifySubTab,
    pub open_region_picker_for: Option<String>,
    pub show_add_target_drawer: bool,
    pub audit_level_filter: Option<LogLevel>,
    pub show_plugins_modal: bool,
    pub plugin_category: PluginCategory,
    pub selected_bucket: Option<usize>,
    pub drafts: DraftStore,
    pub inputs: InputHandles,
    pub audit_list_scroll: UniformListScrollHandle,
    pub show_onboarding: bool,
    pub onboarding_dismissed: bool,
    pub onboarding_probe: Option<OnboardingProbeResult>,
    pub onboarding_loading: bool,
    pub onboarding_submitting: bool,
    pub onboarding_error: Option<String>,
    pub onboarding_proxy_off_sim: bool,
    pub toast: Option<(String, bool)>,
    pub toast_seq: u64,
    pub busy_action: bool,
    pub queried_logs: Option<Vec<LogEntry>>,
    pub queried_logs_total: usize,
    pub logs_loading: bool,
    pub pending_ui_prefs: bool,
    pub leak_scan_note: Option<String>,
    pub env_action_note: Option<String>,
    pub update_status_note: Option<String>,
    pub feishu_status_note: Option<String>,
    pub feishu_initialized: bool,
    pub last_seen_toast_seq: Option<u64>,
    pub hud_window: Option<gpui::WindowHandle<HudWindowView>>,
    pub console_window: Option<gpui::WindowHandle<ConsoleWindowView>>,
    pub tray: Option<TrayHandle>,
}

impl AppController {
    pub fn new(args: &LaunchArgs, tray: Option<TrayHandle>, cx: &mut Context<Self>) -> Self {
        let client = DaemonClient::new(args.endpoint.clone());
        let weak = cx.entity().downgrade();

        let make_input = |placeholder: &'static str,
                          compact: bool,
                          masked: bool,
                          mono: bool,
                          on_edit: fn(&mut AppController, &str),
                          cx: &mut Context<Self>|
         -> Entity<DraftTextInput> {
            let weak_cb = weak.clone();
            cx.new(|cx| {
                DraftTextInput::new(cx)
                    .with_placeholder(placeholder)
                    .with_compact(compact)
                    .with_masked(masked)
                    .with_monospace(mono)
                    .with_on_change(move |text, _window, cx| {
                        let _ = weak_cb.update(cx, |ctrl, cx| {
                            on_edit(ctrl, text);
                            cx.notify();
                        });
                    })
            })
        };

        let inputs = InputHandles {
            search: make_input(
                "Ctrl+K 搜索日志 / 规则…",
                true,
                false,
                false,
                |ctrl, text| {
                    ctrl.drafts.search_query = text.to_string();
                },
                cx,
            ),
            proxy_port: make_input(
                "7890",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.proxy_port = text.to_string();
                    ctrl.drafts.mark_dirty();
                },
                cx,
            ),
            interval_secs: make_input(
                "15",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.interval_secs = text.to_string();
                    ctrl.drafts.mark_dirty();
                },
                cx,
            ),
            trip_threshold: make_input(
                "2",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.trip_threshold = text.to_string();
                    ctrl.drafts.mark_dirty();
                },
                cx,
            ),
            new_target_name: make_input(
                "例如：OpenAI API",
                true,
                false,
                false,
                |ctrl, text| {
                    ctrl.drafts.new_target_name = text.to_string();
                },
                cx,
            ),
            new_target_url: make_input(
                "https://api.openai.com/cdn-cgi/trace",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.new_target_url = text.to_string();
                },
                cx,
            ),
            new_target_ips: make_input(
                "198.51.100.0/24（可选）",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.new_target_ips = text.to_string();
                },
                cx,
            ),
            new_target_regions: make_input(
                "US, SG（两字母代码）",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.new_target_regions = text.to_string();
                },
                cx,
            ),
            target_ips: HashMap::new(),
            target_regions: HashMap::new(),
            feishu_webhook: make_input(
                "https://open.feishu.cn/open-apis/bot/v2/hook/...",
                false,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.feishu_webhook = text.to_string();
                },
                cx,
            ),
            feishu_secret: make_input(
                "可选：机器人加签密钥（留空则不修改）",
                false,
                true,
                true,
                |ctrl, text| {
                    ctrl.drafts.feishu_secret = text.to_string();
                },
                cx,
            ),
            onboarding_cidr: make_input(
                "198.51.100.0/24",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.onboarding_custom_cidr = text.to_string();
                },
                cx,
            ),
            onboarding_regions: make_input(
                "US, JP, SG",
                true,
                false,
                true,
                |ctrl, text| {
                    ctrl.drafts.onboarding_custom_regions = text.to_string();
                },
                cx,
            ),
        };

        inputs.onboarding_cidr.update(cx, |input, cx| {
            input.set_text_silent("198.51.100.0/24", cx);
        });
        inputs.onboarding_regions.update(cx, |input, cx| {
            input.set_text_silent("US, JP", cx);
        });

        let system_prefers_light = system_prefers_light_theme();
        let initial_theme_mode = args.initial_theme.unwrap_or(ThemeMode::Auto);
        let initial_palette = resolve_palette(initial_theme_mode, system_prefers_light);
        cx.set_global(ActivePaletteGlobal(initial_palette));

        let breaker_tab = match args.initial_subtab.as_deref() {
            Some("live") => BreakerSubTab::Live,
            _ => BreakerSubTab::Rules,
        };
        let env_tab = match args.initial_subtab.as_deref() {
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
            connected: false,
            connection_err: None,
            theme_mode: initial_theme_mode,
            system_prefers_light,
            privacy_mask: false,
            nav_section: args.initial_nav,
            policy_menu_open: false,
            breaker_tab,
            env_tab,
            notify_tab,
            open_region_picker_for: None,
            show_add_target_drawer: false,
            audit_level_filter: None,
            show_plugins_modal: args.initial_plugins_modal,
            plugin_category: PluginCategory::All,
            selected_bucket: None,
            drafts: DraftStore::default(),
            inputs,
            audit_list_scroll: UniformListScrollHandle::default(),
            show_onboarding: false,
            onboarding_dismissed: false,
            onboarding_probe: None,
            onboarding_loading: false,
            onboarding_submitting: false,
            onboarding_error: None,
            onboarding_proxy_off_sim: false,
            toast: None,
            toast_seq: 0,
            busy_action: false,
            queried_logs: None,
            queried_logs_total: 0,
            logs_loading: false,
            pending_ui_prefs: false,
            leak_scan_note: None,
            env_action_note: None,
            update_status_note: None,
            feishu_status_note: None,
            feishu_initialized: false,
            last_seen_toast_seq: None,
            hud_window: None,
            console_window: None,
            tray,
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
        resolve_palette(self.theme_mode, self.system_prefers_light)
    }

    pub fn refresh_global_palette(&mut self, cx: &mut App) {
        self.system_prefers_light = system_prefers_light_theme();
        let palette = self.palette();
        cx.set_global(ActivePaletteGlobal(palette));
    }

    pub fn set_theme_mode(&mut self, mode: ThemeMode, cx: &mut Context<Self>) {
        self.theme_mode = mode;
        self.refresh_global_palette(cx);
        let border_rgb = self.palette().frame_border;
        apply_win11_round_corners("ClaudeGuard Quick HUD", border_rgb);
        apply_win11_round_corners("ClaudeGuard v4", border_rgb);
        if self.connected {
            self.pending_ui_prefs = true;
            self.save_config_patch(move |cfg| cfg.theme_mode = mode, "主题已切换", cx);
        }
        cx.notify();
    }

    pub fn toggle_privacy_mask(&mut self, cx: &mut Context<Self>) {
        let next = !self.privacy_mask;
        self.privacy_mask = next;
        if self.connected {
            self.pending_ui_prefs = true;
            self.save_config_patch(
                move |cfg| cfg.privacy_mask_ip = next,
                if next {
                    "已开启 IP 隐私打码"
                } else {
                    "已关闭 IP 隐私打码"
                },
                cx,
            );
        }
        cx.notify();
    }

    pub fn set_nav(&mut self, section: NavSection, cx: &mut Context<Self>) {
        self.nav_section = section;
        self.policy_menu_open = false;
        self.open_region_picker_for = None;
        if section == NavSection::Audit && self.connected {
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
        if self.open_region_picker_for.is_some() {
            self.open_region_picker_for = None;
            changed = true;
        }
        if changed {
            cx.notify();
        }
    }

    /// Toggles a 2-letter ISO region code in a target's visual allowlist draft (or `__new__` drawer).
    pub fn toggle_target_region(
        &mut self,
        target_id: &str,
        code: &str,
        cx: &mut Context<Self>,
    ) {
        let upper = code.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return;
        }
        if target_id == "__new__" {
            let mut list: Vec<String> = split_tokens(&self.drafts.new_target_regions)
                .into_iter()
                .map(|s| s.to_ascii_uppercase())
                .collect();
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
            let mut list: Vec<String> = split_tokens(&t.expect_regions_text)
                .into_iter()
                .map(|s| s.to_ascii_uppercase())
                .collect();
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
                        ctrl.queried_logs = Some(entries);
                        ctrl.queried_logs_total = total;
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        ctrl.set_toast(message, false, cx);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        ctrl.connected = false;
                        ctrl.connection_err = Some(err.to_string());
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
                let client = match this.read_with(cx, |ctrl, _| ctrl.client.clone()) {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let res = cx
                    .background_executor()
                    .spawn(async move { client.exchange(PipeRequest::GetSnapshot) })
                    .await;

                let updated = this.update(cx, |ctrl, cx| {
                    ctrl.system_prefers_light = system_prefers_light_theme();
                    ctrl.refresh_global_palette(cx);
                    match res {
                        Ok(PipeResponse::Snapshot { snapshot }) => {
                            ctrl.apply_snapshot(*snapshot, cx);
                        }
                        Ok(PipeResponse::Error { message, .. }) => {
                            ctrl.connected = false;
                            ctrl.connection_err = Some(message);
                        }
                        Ok(_) => {}
                        Err(err) => {
                            ctrl.connected = false;
                            ctrl.connection_err = Some(err.to_string());
                        }
                    }
                    ctrl.sync_tray_status();
                    cx.notify();
                });
                if updated.is_err() {
                    break;
                }
                cx.background_executor().timer(POLL_INTERVAL).await;
            }
        })
        .detach();
    }

    pub fn apply_snapshot(&mut self, snapshot: GuardSnapshot, cx: &mut Context<Self>) {
        let prev_cfg_rev = self.snapshot.as_ref().map(|s| s.cfg_rev);
        self.connected = true;
        self.connection_err = None;
        if !self.pending_ui_prefs && prev_cfg_rev != Some(snapshot.cfg_rev) {
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
        if !self.feishu_initialized {
            self.drafts.feishu_enabled = snapshot.feishu.enabled;
            self.feishu_initialized = true;
        }
        self.snapshot = Some(snapshot);
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
            let ip_entity = self
                .inputs
                .target_ips
                .entry(td.id.clone())
                .or_insert_with(|| {
                    cx.new(|cx| {
                        DraftTextInput::new(cx)
                            .with_placeholder("允许 IP 或 CIDR，例如 198.51.100.0/24")
                            .with_compact(true)
                            .with_monospace(true)
                            .with_on_change(move |text, _window, cx| {
                                let _ = weak_ip.update(cx, |ctrl, cx| {
                                    if let Some(row) =
                                        ctrl.drafts.targets.iter_mut().find(|r| r.id == id_ip)
                                    {
                                        row.expect_ips_text = text.to_string();
                                        ctrl.drafts.mark_dirty();
                                        cx.notify();
                                    }
                                });
                            })
                    })
                });
            ip_entity.update(cx, |i, cx| i.set_text_silent(&td.expect_ips_text, cx));

            let id_reg = td.id.clone();
            let weak_reg = weak.clone();
            let reg_entity = self
                .inputs
                .target_regions
                .entry(td.id.clone())
                .or_insert_with(|| {
                    cx.new(|cx| {
                        DraftTextInput::new(cx)
                            .with_placeholder("国家代码，如 US, SG")
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
                    })
                });
            reg_entity.update(cx, |i, cx| i.set_text_silent(&td.expect_regions_text, cx));
        }
    }

    fn sync_tray_status(&self) {
        let Some(tray) = self.tray.as_ref() else {
            return;
        };
        let now = crate::demo::now_unix_secs();
        let proj = project_hud(
            self.snapshot.as_ref(),
            self.connected,
            self.connection_err.as_deref(),
            self.privacy_mask,
        );
        let paused = self.snapshot.as_ref().is_some_and(|s| s.is_paused_at(now));
        let tip = format!("ClaudeGuard v4 · {}", proj.hero.title);
        tray.set_status(TrayTone::from(proj.hero.tone), paused, &tip);
    }

    pub fn set_toast(&mut self, msg: impl Into<String>, ok: bool, cx: &mut Context<Self>) {
        self.toast_seq = self.toast_seq.wrapping_add(1);
        let seq = self.toast_seq;
        self.toast = Some((msg.into(), ok));
        cx.notify();

        let timeout = if ok {
            Duration::from_millis(3500)
        } else {
            Duration::from_millis(6000)
        };
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(timeout).await;
            let _ = this.update(cx, |ctrl, cx| {
                if ctrl.toast_seq == seq {
                    ctrl.toast = None;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub fn send_request(
        &mut self,
        req: PipeRequest,
        ok_msg: Option<&'static str>,
        cx: &mut Context<Self>,
    ) {
        let client = self.client.clone();
        self.busy_action = true;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let res = cx
                .background_executor()
                .spawn(async move { client.exchange(req) })
                .await;

            let _ = this.update(cx, |ctrl, cx| {
                ctrl.busy_action = false;
                ctrl.pending_ui_prefs = false;
                match res {
                    Ok(PipeResponse::Snapshot { snapshot }) => {
                        ctrl.apply_snapshot(*snapshot, cx);
                        if let Some(msg) = ok_msg {
                            ctrl.set_toast(msg, true, cx);
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
                                format!("操作未完全通过：{}", rc.verified_scope)
                            });
                            ctrl.set_toast(detail, false, cx);
                        } else if let Some(msg) = ok_msg {
                            ctrl.set_toast(msg, true, cx);
                        }
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        ctrl.set_toast(message, false, cx);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        ctrl.connected = false;
                        ctrl.connection_err = Some(err.to_string());
                        ctrl.set_toast(err.to_string(), false, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn save_config_patch(
        &mut self,
        mutate: impl FnOnce(&mut Config) + Send + 'static,
        ok_msg: &'static str,
        cx: &mut Context<Self>,
    ) {
        let Some(mut cfg) = self.snapshot.as_ref().map(|s| s.config.clone()) else {
            return;
        };
        mutate(&mut cfg);
        self.send_request(PipeRequest::SaveConfig { config: cfg }, Some(ok_msg), cx);
    }

    pub fn save_target_drafts(&mut self, cx: &mut Context<Self>) {
        let Some(base) = self.snapshot.as_ref().map(|s| s.config.clone()) else {
            self.set_toast("尚未收到守护快照，无法保存", false, cx);
            return;
        };
        match self.drafts.build_updated_config(&base) {
            Ok(next_cfg) => {
                self.drafts.dirty = false;
                self.drafts.validation_error = None;
                self.send_request(
                    PipeRequest::SaveConfig { config: next_cfg },
                    Some("目标与白名单配置已保存"),
                    cx,
                );
            }
            Err(err) => {
                self.drafts.validation_error = Some(err.clone());
                self.set_toast(err, false, cx);
            }
        }
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
        let ips = split_tokens(&self.drafts.new_target_ips);
        let regions: Vec<String> = split_tokens(&self.drafts.new_target_regions)
            .into_iter()
            .map(|r| r.to_ascii_uppercase())
            .collect();

        if name.is_empty() {
            self.drafts.validation_error = Some("请填写新目标名称".into());
            cx.notify();
            return;
        }
        if !url.starts_with("https://") && !url.starts_with("http://") {
            self.drafts.validation_error =
                Some("新目标探测 URL 必须以 https:// 或 http:// 开头".into());
            cx.notify();
            return;
        }
        if ips.is_empty() && regions.is_empty() {
            self.drafts.validation_error =
                Some("请至少填写一个允许 IP/CIDR 或两字母国家代码".into());
            cx.notify();
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
        self.drafts.mark_dirty();
        self.sync_input_entities_from_drafts(cx);
        self.set_toast("已添加目标到草稿（请点「保存目标配置」生效）", true, cx);
    }

    pub fn delete_target_draft(&mut self, id: &str, cx: &mut Context<Self>) {
        let before = self.drafts.targets.len();
        self.drafts.targets.retain(|t| t.builtin || t.id != id);
        if self.drafts.targets.len() < before {
            self.drafts.mark_dirty();
            self.sync_input_entities_from_drafts(cx);
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
            self.set_toast(
                "守护服务未连接：出于安全闭锁原则禁止启动 AI 应用",
                false,
                cx,
            );
            return;
        }
        let client = self.client.clone();
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
                ctrl.busy_action = false;
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
                                ctrl.set_toast(
                                    format!("[演示] 门禁放行：将以普通用户权限启动 {agent_id}"),
                                    true,
                                    cx,
                                );
                            } else {
                                match launch_agent_normal_user(&agent_id, &install_paths) {
                                    Ok(msg) => ctrl.set_toast(msg, true, cx),
                                    Err(err) => ctrl.set_toast(err, false, cx),
                                }
                            }
                        } else {
                            ctrl.set_toast(format!("启动门禁拦截：{reason}"), false, cx);
                        }
                    }
                    Ok(PipeResponse::Error { message, .. }) => {
                        ctrl.set_toast(message, false, cx);
                    }
                    Ok(_) => {}
                    Err(err) => ctrl.set_toast(err.to_string(), false, cx),
                }
                cx.notify();
            });
        })
        .detach();
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
                        ctrl.connected = false;
                        ctrl.connection_err = Some(msg.clone());
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
                .spawn(async move { client.exchange(PipeRequest::CompleteOnboarding { config: cfg }) })
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
                            ctrl.onboarding_error = Some("配置尚未生效，请检查白名单配置后重试".into());
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
                            ctrl.onboarding_error =
                                Some("守护服务尚未退出未配置态，请检查配置后重试".into());
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
                        ctrl.onboarding_error = Some("守护服务返回了非预期的响应，请重试".into());
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        ctrl.connected = false;
                        ctrl.connection_err = Some(msg.clone());
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
        self.set_toast("已进入只读未配置态，随时可在顶栏重新打开向导", true, cx);
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
        self.send_request(
            PipeRequest::SetPolicyPreset { preset },
            Some("守护策略档位已切换"),
            cx,
        );
    }
}

/// Opens or focuses Mode A Tray Quick HUD (`368x452` logical px), anchored bottom-right above taskbar.
pub fn open_hud_window(ctrl: Entity<AppController>, cx: &mut App) {
    let existing = ctrl.read(cx).hud_window;
    if let Some(handle) = existing
        && handle
            .update(cx, |_, window, _| {
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
        ctrl.update(cx, |c, _| c.hud_window = Some(handle));
    }
}

/// Toggles Mode A Tray Quick HUD (`window.remove_window()` drops SwapChain & VRAM to 0).
pub fn toggle_hud_window(ctrl: Entity<AppController>, cx: &mut App) {
    let existing = ctrl.read(cx).hud_window;
    if let Some(handle) = existing {
        let removed = handle
            .update(cx, |_, window, _| {
                window.remove_window();
            })
            .is_ok();
        ctrl.update(cx, |c, _| c.hud_window = None);
        if removed {
            return;
        }
    }
    open_hud_window(ctrl, cx);
}

/// Opens or focuses Mode B Wide Bento Main Console (`1020x720`, auto-clamped to DPI work area).
pub fn open_console_window(ctrl: Entity<AppController>, cx: &mut App) {
    let existing = ctrl.read(cx).console_window;
    if let Some(handle) = existing
        && handle
            .update(cx, |_, window, _| {
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
        ctrl.update(cx, |c, _| c.console_window = Some(handle));
    }
}

/// Root view for Mode A — Tray Quick HUD (`416 × 636`).
pub struct HudWindowView {
    pub ctrl: Entity<AppController>,
    focus_handle: FocusHandle,
    was_activated: bool,
    _obs_sub: gpui::Subscription,
    _act_sub: gpui::Subscription,
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
                ctrl_act.update(cx, |c, _| c.hud_window = None);
                window.remove_window();
            }
        });
        let ctrl_close = ctrl.clone();
        window.on_window_should_close(cx, move |_window, cx| {
            ctrl_close.update(cx, |c, _| c.hud_window = None);
            true
        });
        window.focus(&focus_handle, cx);
        Self {
            ctrl,
            focus_handle,
            was_activated: false,
            _obs_sub,
            _act_sub,
        }
    }

    fn on_dismiss(&mut self, _: &DismissHudWindow, window: &mut Window, cx: &mut Context<Self>) {
        self.ctrl.update(cx, |c, _| c.hud_window = None);
        window.remove_window();
    }
}

impl Focusable for HudWindowView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for HudWindowView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let ctrl_ref = self.ctrl.read(cx);
        let p = ctrl_ref.palette();
        let proj = project_hud(
            ctrl_ref.snapshot.as_ref(),
            ctrl_ref.connected,
            ctrl_ref.connection_err.as_deref(),
            ctrl_ref.privacy_mask,
        );
        let toast = ctrl_ref.toast.clone();
        let busy = ctrl_ref.busy_action;

        div()
            .id("hud-root")
            .key_context("HudWindow")
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(Self::on_dismiss))
            .size_full()
            .bg(rgb(p.frame_bg))
            .border_1()
            .border_color(rgb(p.frame_border))
            .font_family("Segoe UI Variable Text")
            .text_color(rgb(p.text_primary))
            .child(views::hud::render_hud(
                self.ctrl.clone(),
                &proj,
                toast.as_ref(),
                busy,
                p,
                cx,
            ))
    }
}

/// Root view for Mode B — Wide Bento Main Console (`1068 × 834`).
pub struct ConsoleWindowView {
    pub ctrl: Entity<AppController>,
    focus_handle: FocusHandle,
    _obs_sub: gpui::Subscription,
}

impl ConsoleWindowView {
    pub fn new(ctrl: Entity<AppController>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();
        let _obs_sub = cx.observe(&ctrl, |_, _, cx| cx.notify());
        let ctrl_close = ctrl.clone();
        window.on_window_should_close(cx, move |_window, cx| {
            let close_to_tray = ctrl_close
                .read(cx)
                .snapshot
                .as_ref()
                .map(|s| s.config.close_to_tray)
                .unwrap_or(true);
            ctrl_close.update(cx, |c, _| c.console_window = None);
            if !close_to_tray {
                cx.quit();
            }
            true
        });
        Self {
            ctrl,
            focus_handle,
            _obs_sub,
        }
    }

    fn on_focus_search(
        &mut self,
        _: &FocusGlobalSearch,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let handle = self.ctrl.read(cx).inputs.search.read(cx).focus_handle(cx);
        window.focus(&handle, cx);
        cx.notify();
    }
}

impl Focusable for ConsoleWindowView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for ConsoleWindowView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let ctrl_snap = self.ctrl.read(cx);
        let p = ctrl_snap.palette();
        let nav = ctrl_snap.nav_section;
        let privacy_mask = ctrl_snap.privacy_mask;
        let show_onboarding = ctrl_snap.show_onboarding;
        let show_plugins = ctrl_snap.show_plugins_modal;
        let policy_menu_open = ctrl_snap.policy_menu_open;
        let snapshot_opt = ctrl_snap.snapshot.clone();
        let connected = ctrl_snap.connected;
        let conn_err = ctrl_snap.connection_err.clone();
        let selected_bucket = ctrl_snap.selected_bucket;
        let search_query = ctrl_snap.drafts.search_query.clone();
        let queried_logs = ctrl_snap.queried_logs.clone();
        let toast = ctrl_snap.toast.clone();
        let busy = ctrl_snap.busy_action;

        let proj = project_console(
            snapshot_opt.as_ref(),
            connected,
            conn_err.as_deref(),
            privacy_mask,
            selected_bucket,
            &search_query,
            queried_logs.as_deref(),
        );

        let is_maximized = window.is_maximized();
        let ctrl_entity = self.ctrl.clone();
        let tripped = snapshot_opt.as_ref().is_some_and(|s| s.is_tripped());
        let ag_issue = snapshot_opt.as_ref().is_some_and(|s| {
            s.antigravity_proxy.installed && !s.antigravity_proxy.is_ready_for_launch()
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
            ]
            .iter()
            .any(|slot| slot.phase == UpdateCheckPhase::UpdateAvailable)
        });

        let header = render_ceramic_header(ctrl_entity.clone(), tripped, is_maximized, p, cx);
        let dock = render_ceramic_dock(
            ctrl_entity.clone(),
            nav,
            tripped,
            tripped || ag_issue,
            has_any_update,
            p,
            cx,
        );

        let body_scroll = div()
            .id("console-scroll")
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.))
            .min_h(px(0.))
            .overflow_y_scroll()
            .gap(px(11.))
            .when_some(proj.connection_banner.clone(), |root, banner| {
                let _ = ctrl_entity.read(cx).client.endpoint();
                root.child(
                    bento_card(p)
                        .w_full()
                        .flex_shrink_0()
                        .px(px(14.))
                        .py(px(10.))
                        .gap(px(6.))
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap(px(10.))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(8.))
                                        .child(status_pill("未连接 · 安全闭锁", BadgeTone::Warn, p))
                                        .child(
                                            div()
                                                .text_size(px(12.5))
                                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary))
                                                .child(format!("后台守护服务未连接：{banner}")),
                                        ),
                                )
                                .child(
                                    action_button(
                                        "banner-retry-conn",
                                        if busy { "重连中…" } else { "立即重连" },
                                        ButtonKind::Primary,
                                        !busy,
                                        p,
                                    )
                                    .h(px(27.))
                                    .when(!busy, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |view, _, _, cx| {
                                                view.ctrl.update(cx, |ctrl, cx| {
                                                    ctrl.send_request(
                                                        PipeRequest::GetSnapshot,
                                                        Some("已重新连接到后台守护服务"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                )
            })
            .when_some(toast, |root, (msg, ok)| {
                let b = if ok { p.badge_pass } else { p.badge_fail };
                root.child(
                    div()
                        .flex()
                        .flex_shrink_0()
                        .items_center()
                        .justify_between()
                        .px(px(12.))
                        .py(px(7.))
                        .rounded(px(10.))
                        .bg(rgba(b.bg))
                        .text_size(px(11.5))
                        .text_color(rgb(b.text))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .child(div().w(px(6.)).h(px(6.)).rounded(px(999.)).bg(rgb(b.dot)))
                                .child(msg),
                        )
                        .child(
                            div()
                                .id("toast-dismiss")
                                .text_size(px(11.))
                                .cursor_pointer()
                                .child("关闭")
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(|view, _, _, cx| {
                                        view.ctrl.update(cx, |ctrl, cx| {
                                            ctrl.toast = None;
                                            cx.notify();
                                        });
                                    }),
                                ),
                        ),
                )
            })
            .child(match nav {
                NavSection::Overview => {
                    views::overview::render_overview(ctrl_entity.clone(), &proj, p, cx)
                }
                NavSection::Targets => {
                    views::targets::render_targets_page(ctrl_entity.clone(), p, cx)
                }
                NavSection::Breaker => {
                    views::breaker::render_breaker_page(ctrl_entity.clone(), &proj, p, cx)
                }
                NavSection::Environment => {
                    views::environment::render_environment_page(ctrl_entity.clone(), p, cx)
                }
                NavSection::Audit => {
                    views::audit::render_audit_page(ctrl_entity.clone(), &proj, p, cx)
                }
                NavSection::Updates => {
                    views::updates::render_updates_page(ctrl_entity.clone(), p, cx)
                }
                NavSection::Notify => {
                    views::notify::render_notify_page(ctrl_entity.clone(), p, cx)
                }
            });

        let ctrl_root_click = ctrl_entity.clone();
        let mut root = div()
            .id("console-root")
            .key_context("ConsoleWindow")
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(Self::on_focus_search))
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

        if policy_menu_open {
            root = root.child(render_policy_dropdown_overlay(ctrl_entity.clone(), p, cx));
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
                ctrl_entity,
                p,
                cx,
            ));
        }
        root
    }
}

fn policy_preset_display(preset: PolicyPreset) -> (&'static str, &'static str) {
    match preset {
        PolicyPreset::LooseAntiDirect => (
            "宽松防直连",
            "仅拦截本地直连，不校验出口国家/地区",
        ),
        PolicyPreset::StandardRegion => (
            "标准地区白名单",
            "出口必须落在允许国家列表，越界立即熔断",
        ),
        PolicyPreset::StrictStaticIp => (
            "严格锁定静态 IP",
            "仅放行已绑定的专属静态出口 IP 或网段",
        ),
    }
}

fn render_ceramic_header(
    ctrl: Entity<AppController>,
    tripped: bool,
    is_maximized: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Div {
    let ctrl_r = ctrl.read(cx);
    let current_preset = ctrl_r
        .snapshot
        .as_ref()
        .map(|s| s.preset)
        .unwrap_or(PolicyPreset::StandardRegion);
    let (preset_name, _) = policy_preset_display(current_preset);
    let policy_open = ctrl_r.policy_menu_open;
    let privacy_mask = ctrl_r.privacy_mask;
    let hud_open = ctrl_r.hud_window.is_some();
    let is_dark = p.is_dark;

    let ctrl_pol = ctrl.clone();
    let ctrl_priv = ctrl.clone();
    let ctrl_hud = ctrl.clone();
    let ctrl_theme = ctrl.clone();
    let ctrl_close = ctrl;

    let hover_tile = p.sidebar_hover_bg;

    div()
        .flex()
        .flex_shrink_0()
        .items_center()
        .justify_between()
        .h(px(32.))
        .px(px(2.))
        .gap(px(10.))
        // Left: Brand + Policy selector button
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(9.))
                .child(
                    div()
                        .w(px(26.))
                        .h(px(26.))
                        .rounded(px(8.))
                        .bg(rgb(p.primary_btn_bg))
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(ui_icon(
                            if tripped {
                                "icons/ui/shield_alert.svg"
                            } else {
                                "icons/ui/shield.svg"
                            },
                            15.0,
                            p.primary_btn_text,
                        )),
                )
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
                        .child(ui_icon("icons/ui/chevrons.svg", 12.5, p.text_muted))
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                cx.stop_propagation();
                                ctrl_pol.update(cx, |c, cx| {
                                    c.policy_menu_open = !c.policy_menu_open;
                                    c.open_region_picker_for = None;
                                    cx.notify();
                                });
                            }),
                        ),
                ),
        )
        // Center draggable window titlebar area
        .child(
            div()
                .flex_1()
                .h_full()
                .window_control_area(WindowControlArea::Drag),
        )
        // Right utility chips + theme icon + compact window controls
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
                        .bg(rgb(p.card_bg))
                        .border_1()
                        .border_color(rgb(if privacy_mask {
                            p.line_strong
                        } else {
                            p.card_border
                        }))
                        .cursor_pointer()
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .text_size(px(11.5))
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_color(rgb(if privacy_mask {
                            p.text_primary
                        } else {
                            p.text_secondary
                        }))
                        .child(ui_icon(
                            "icons/ui/eye.svg",
                            13.0,
                            if privacy_mask {
                                p.text_primary
                            } else {
                                p.text_secondary
                            },
                        ))
                        .child(if privacy_mask { "已脱敏" } else { "隐私打码" })
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
                        .bg(rgb(p.card_bg))
                        .border_1()
                        .border_color(rgb(if hud_open {
                            p.line_strong
                        } else {
                            p.card_border
                        }))
                        .cursor_pointer()
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .text_size(px(11.5))
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_color(rgb(if hud_open {
                            p.text_primary
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
                        .w(px(28.))
                        .h(px(28.))
                        .rounded(px(999.))
                        .bg(rgb(p.card_bg))
                        .border_1()
                        .border_color(rgb(p.card_border))
                        .cursor_pointer()
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .child(ui_icon(
                            if is_dark {
                                "icons/ui/sun.svg"
                            } else {
                                "icons/ui/moon.svg"
                            },
                            14.0,
                            p.text_secondary,
                        ))
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                let next = if is_dark {
                                    ThemeMode::Light
                                } else {
                                    ThemeMode::Dark
                                };
                                ctrl_theme.update(cx, |c, cx| c.set_theme_mode(next, cx));
                            }),
                        ),
                )
                .child(div().w(px(1.)).h(px(14.)).bg(rgb(p.card_border)).mx(px(2.)))
                .child(win_ctrl_btn("win-min", "icons/ui/win_min.svg", false, p).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|_, _, window, _| {
                        window.minimize_window();
                    }),
                ))
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
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|_, _, window, _| {
                            window.zoom_window();
                        }),
                    ),
                )
                .child(win_ctrl_btn("win-close", "icons/ui/close.svg", true, p).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, window, cx| {
                        let close_to_tray = ctrl_close
                            .read(cx)
                            .snapshot
                            .as_ref()
                            .map(|s| s.config.close_to_tray)
                            .unwrap_or(true);
                        ctrl_close.update(cx, |c, _| c.console_window = None);
                        window.remove_window();
                        if !close_to_tray {
                            cx.quit();
                        }
                    }),
                )),
        )
}

fn render_policy_dropdown_overlay(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Stateful<gpui::Div> {
    let ctrl_r = ctrl.read(cx);
    let current_preset = ctrl_r
        .snapshot
        .as_ref()
        .map(|s| s.preset)
        .unwrap_or(PolicyPreset::StandardRegion);
    let can_switch = ctrl_r.connected && !ctrl_r.busy_action;

    let options: Vec<_> = POLICY_PRESETS.into_iter().map(|preset| {
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
            .bg(rgb(if active { p.inset_bg } else { p.card_bg }))
            .hover(move |s| s.bg(rgb(hover)))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w(px(0.))
                    .gap(px(2.))
                    .child(
                        div()
                            .text_size(px(12.5))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_color(rgb(p.text_primary))
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
                    p.text_primary,
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
    }).collect();

    let ctrl_bg = ctrl;
    div()
        .id("policy-dropdown-backdrop")
        .absolute()
        .inset_0()
        .on_mouse_up(
            MouseButton::Left,
            cx.listener(move |_, _, _, cx| {
                ctrl_bg.update(cx, |c, cx| {
                    c.policy_menu_open = false;
                    cx.notify();
                });
            }),
        )
        .child(
            div()
                .id("policy-dropdown-menu")
                .absolute()
                .top(px(52.))
                .left(px(140.))
                .w(px(296.))
                .p(px(5.))
                .gap(px(2.))
                .flex()
                .flex_col()
                .rounded(px(13.))
                .bg(rgb(p.card_bg))
                .border_1()
                .border_color(rgb(p.line_strong))
                .shadow(vec![
                    BoxShadow::new(px(0.), px(14.), rgba(0x0F172A2B).into()).blur_radius(px(34.)),
                ])
                .on_mouse_up(MouseButton::Left, |_, _, cx| {
                    cx.stop_propagation();
                })
                .children(options),
        )
}

fn render_ceramic_dock(
    ctrl: Entity<AppController>,
    active_nav: NavSection,
    targets_alert: bool,
    env_alert: bool,
    has_update: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Div {
    let items: [(NavSection, &'static str, &'static str, Option<u32>); 7] = [
        (NavSection::Overview, "总览", "icons/ui/home.svg", None),
        (
            NavSection::Targets,
            "目标",
            "icons/ui/globe.svg",
            targets_alert.then_some(p.badge_fail.dot),
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

    let dock_btns = items.into_iter().map(|(sec, label, icon_path, dot)| {
        let active = sec == active_nav;
        let ctrl_n = ctrl.clone();
        let fg = if active {
            p.sidebar_active_text
        } else {
            p.text_secondary
        };
        let hover_bg = p.sidebar_hover_bg;
        let hover_txt = p.text_primary;

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
            .child(ui_icon(icon_path, 14.0, fg))
            .child(label);

        if active {
            btn = btn.bg(rgb(p.sidebar_active_bg));
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
                .gap(px(3.))
                .p(px(4.))
                .rounded(px(14.5))
                .bg(rgb(p.sidebar_bg))
                .border_1()
                .border_color(rgb(p.card_border))
                .shadow(vec![
                    BoxShadow::new(px(0.), px(6.), rgba(p.shadow_rgba).into()).blur_radius(px(20.)),
                ])
                .children(dock_btns),
        )
}

fn win_ctrl_btn(
    id: &'static str,
    icon_path: &'static str,
    danger: bool,
    p: &'static ThemePalette,
) -> gpui::Stateful<gpui::Div> {
    let icon_color = if danger {
        p.badge_fail.text
    } else {
        p.text_secondary
    };
    let hover_bg = if danger {
        rgba(p.badge_fail.bg)
    } else {
        rgb(p.sidebar_hover_bg)
    };
    div()
        .id(id)
        .flex()
        .items_center()
        .justify_center()
        .w(px(26.))
        .h(px(26.))
        .rounded(px(7.))
        .bg(rgb(p.card_bg))
        .border_1()
        .border_color(rgb(p.card_border))
        .cursor_pointer()
        .hover(move |s| s.bg(hover_bg))
        .child(ui_icon(icon_path, 12.0, icon_color))
}

/// Launches the GPUI desktop application + Win32 tray loop.
pub fn run(args: LaunchArgs) {
    let is_demo = matches!(args.endpoint, TransportEndpoint::Demo(_));
    if signal_existing_tray_instance(is_demo, args.start_hud, args.start_in_tray) {
        return;
    }

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
            text_input::bind_keys(cx);
            cx.bind_keys([
                KeyBinding::new("ctrl-k", FocusGlobalSearch, Some("ConsoleWindow")),
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
        TrayEvent::QuitGuiOnly => {
            ctrl.update(cx, |c, _| {
                if let Some(mut tray) = c.tray.take() {
                    tray.shutdown();
                }
            });
            cx.quit();
        }
        TrayEvent::SafeExit => {
            let client = ctrl.read(cx).client.clone();
            ctrl.update(cx, |c, _| {
                if let Some(mut tray) = c.tray.take() {
                    tray.shutdown();
                }
            });
            cx.spawn(async move |cx| {
                let _ = cx
                    .background_executor()
                    .spawn(async move {
                        client.exchange(PipeRequest::DisarmAndRestoreFlowB {
                            reason: Some("用户通过托盘安全撤防并退出".into()),
                        })
                    })
                    .await;
                cx.update(|cx| cx.quit());
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
    }
}
