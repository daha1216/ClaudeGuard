//! Multi-theme Apple Studio White & Refined Cool Gray visual design system
//! (`ThemeStyle` × `Light` / `Dark` / `Auto`).
//!
//! All five curated styles share the exact same pure optical ceramic white & crisp cool
//! studio-gray neutral canvas in Light mode (zero warm beige, zero greenish cast) and the
//! exact same Apple Pro Studio Graphite neutral canvas in Dark mode, paired with five
//! distinct accent personalities:
//! - [`ThemeStyle::CrystalGlass`] ("琉璃冰晶", default): Apple Tahoe frosted crystal-ice liquid glass
//! - [`ThemeStyle::LinearIndigo`] ("线性星靛"): Silicon Valley Linear / Stripe precision periwinkle-indigo
//! - [`ThemeStyle::MinimalMist`] ("莫兰迪雾"): Quiet low-saturation Giorgio Morandi chalk slate-blue
//! - [`ThemeStyle::AlpineSapphire`] ("深海蓝宝"): Swiss horology deep sapphire
//! - [`ThemeStyle::ObsidianInk`] ("曜石极黑"): Classic editorial monochrome obsidian

pub use cg_protocol::ThemeMode;
use gpui::{Hsla, Rgba, rgb, rgba};
use std::path::PathBuf;

/// All user-selectable [`ThemeMode`] options in display order.
pub const THEME_MODES: [ThemeMode; 3] = [ThemeMode::Light, ThemeMode::Dark, ThemeMode::Auto];

/// Localized UI label for [`ThemeMode`].
pub fn theme_mode_label(mode: ThemeMode) -> &'static str {
    match mode {
        ThemeMode::Light => "浅色",
        ThemeMode::Dark => "暗夜",
        ThemeMode::Auto => "自动",
    }
}

/// Orthogonal visual theme style selectable independently of Light / Dark / Auto polarity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ThemeStyle {
    /// "琉璃冰晶" — Default: Apple Tahoe frosted crystal-ice liquid glass matching the Celestial Origami Shield.
    #[default]
    CrystalGlass,
    /// "线性星靛" — Silicon Valley Linear / Stripe precision periwinkle-indigo (`#5B69D0`).
    LinearIndigo,
    /// "莫兰迪雾" — Preserved Morandi dusty chalk slate-blue (`#6D839B`) on pure crisp White/Gray canvas.
    MinimalMist,
    /// "深海蓝宝" — Preserved Swiss horology deep sapphire (`#2B4F8D`) on pure crisp White/Gray canvas.
    AlpineSapphire,
    /// "曜石极黑" — Classic v4 monochrome obsidian (`#1E222C`) on pure crisp White/Gray canvas.
    ObsidianInk,
}

/// All user-selectable [`ThemeStyle`] options in display order.
pub const THEME_STYLES: [ThemeStyle; 5] = [
    ThemeStyle::CrystalGlass,
    ThemeStyle::LinearIndigo,
    ThemeStyle::MinimalMist,
    ThemeStyle::AlpineSapphire,
    ThemeStyle::ObsidianInk,
];

impl ThemeStyle {
    /// Stable serialization key persisted in `ui_style.json`.
    pub const fn key(self) -> &'static str {
        match self {
            Self::CrystalGlass => "crystal_glass",
            Self::LinearIndigo => "linear_indigo",
            Self::MinimalMist => "minimal_mist",
            Self::AlpineSapphire => "alpine_sapphire",
            Self::ObsidianInk => "obsidian_ink",
        }
    }

    /// Parses a persisted style key back into a [`ThemeStyle`].
    pub fn from_key(s: &str) -> Option<Self> {
        match s.trim() {
            "crystal_glass" => Some(Self::CrystalGlass),
            "linear_indigo" => Some(Self::LinearIndigo),
            "minimal_mist" => Some(Self::MinimalMist),
            "alpine_sapphire" => Some(Self::AlpineSapphire),
            "obsidian_ink" => Some(Self::ObsidianInk),
            _ => None,
        }
    }

    /// Localized display label for theme switchers and popovers.
    pub const fn label(self) -> &'static str {
        match self {
            Self::CrystalGlass => "琉璃冰晶",
            Self::LinearIndigo => "线性星靛",
            Self::MinimalMist => "莫兰迪雾",
            Self::AlpineSapphire => "深海蓝宝",
            Self::ObsidianInk => "曜石极黑",
        }
    }

    /// Concise localized tagline summarizing the aesthetic mood of the style.
    pub const fn tagline(self) -> &'static str {
        match self {
            Self::CrystalGlass => "默认 · 苹果液态冰晶质感",
            Self::LinearIndigo => "精工 · Linear 星靛紫蓝",
            Self::MinimalMist => "柔雅 · 低饱和莫兰迪雾蓝",
            Self::AlpineSapphire => "典藏 · 瑞士腕表深海蓝",
            Self::ObsidianInk => "经典 · 极简曜石纯黑",
        }
    }

    /// Primary accent swatch color (`0xRRGGBB`) for theme preview dots.
    pub const fn swatch_accent(self, is_dark: bool) -> u32 {
        match (self, is_dark) {
            (Self::CrystalGlass, false) => 0x527CC4,
            (Self::CrystalGlass, true) => 0x7AA3E8,
            (Self::LinearIndigo, false) => 0x5B69D0,
            (Self::LinearIndigo, true) => 0x7E8BF0,
            (Self::MinimalMist, false) => 0x6E849C,
            (Self::MinimalMist, true) => 0x8EA6BF,
            (Self::AlpineSapphire, false) => 0x2B4F8D,
            (Self::AlpineSapphire, true) => 0x5A83C9,
            (Self::ObsidianInk, false) => 0x1E222C,
            (Self::ObsidianInk, true) => 0xDCE1EB,
        }
    }

    /// Surface preview swatch color (`0xRRGGBB`) for theme preview cards.
    pub const fn swatch_surface(self, is_dark: bool) -> u32 {
        match (self, is_dark) {
            (Self::CrystalGlass, false) => 0xEAF1FC,
            (Self::CrystalGlass, true) => 0x1D2B46,
            (Self::LinearIndigo, false) => 0xF0F1FD,
            (Self::LinearIndigo, true) => 0x1F2242,
            (Self::MinimalMist, false) => 0xEEF2F6,
            (Self::MinimalMist, true) => 0x1E2530,
            (Self::AlpineSapphire, false) => 0xEDF2FA,
            (Self::AlpineSapphire, true) => 0x1B2842,
            (Self::ObsidianInk, false) => 0xEEF0F4,
            (Self::ObsidianInk, true) => 0x1E2129,
        }
    }
}

/// Path to the local GUI style preference file (`<LOCALAPPDATA>\ClaudeGuard\ui_style.json`).
pub fn ui_style_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("APPDATA").filter(|v| !v.is_empty()))?;
    Some(
        PathBuf::from(base)
            .join("ClaudeGuard")
            .join("ui_style.json"),
    )
}

/// Checks whether a persisted `ui_style.json` payload carries schema version 2 (`"v":2`).
///
/// Legacy v1 files (missing `"v":2`) are intentionally ignored so existing trial users
/// automatically upgrade to the new [`ThemeStyle::CrystalGlass`] default on launch.
fn has_schema_v2(raw: &str) -> bool {
    if raw.contains("\"v\":2") {
        // Reject `"v":20` etc. by verifying the character following `"v":2` is not a digit.
        for (idx, _) in raw.match_indices("\"v\":2") {
            let tail = &raw[idx + "\"v\":2".len()..];
            if tail.is_empty() || !tail.as_bytes()[0].is_ascii_digit() {
                return true;
            }
        }
        return false;
    }
    let Some(v_pos) = raw.find("\"v\"") else {
        return false;
    };
    let after_v = &raw[v_pos + "\"v\"".len()..];
    let Some(colon_pos) = after_v.find(':') else {
        return false;
    };
    let rest = after_v[colon_pos + 1..].trim_start();
    rest.strip_prefix('2')
        .is_some_and(|tail| tail.is_empty() || !tail.as_bytes()[0].is_ascii_digit())
}

fn parse_theme_style_json(raw: &str) -> ThemeStyle {
    if !has_schema_v2(raw) {
        return ThemeStyle::CrystalGlass;
    }
    let Some(key_pos) = raw.find("\"style\"") else {
        return ThemeStyle::CrystalGlass;
    };
    let after_key = &raw[key_pos + "\"style\"".len()..];
    let Some(colon_pos) = after_key.find(':') else {
        return ThemeStyle::CrystalGlass;
    };
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let Some(rest) = after_colon.strip_prefix('"') else {
        return ThemeStyle::CrystalGlass;
    };
    let Some(end_quote) = rest.find('"') else {
        return ThemeStyle::CrystalGlass;
    };
    ThemeStyle::from_key(&rest[..end_quote]).unwrap_or(ThemeStyle::CrystalGlass)
}

/// Loads the user's locally persisted [`ThemeStyle`], falling back to [`ThemeStyle::CrystalGlass`].
pub fn load_saved_theme_style() -> ThemeStyle {
    let Some(path) = ui_style_config_path() else {
        return ThemeStyle::CrystalGlass;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return ThemeStyle::CrystalGlass;
    };
    parse_theme_style_json(&raw)
}

/// Persists the chosen [`ThemeStyle`] locally as schema-v2 JSON (best-effort, ignores IO errors).
pub fn save_theme_style(style: ThemeStyle) {
    let Some(path) = ui_style_config_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let payload = format!("{{\"v\":2,\"style\":\"{}\"}}\n", style.key());
    let _ = std::fs::write(path, payload);
}

/// Visual tone for the Hero card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeroTone {
    Healthy,
    Tripped,
    DisarmedOrPaused,
}

/// Visual tone for status pills and badges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadgeTone {
    Pass,
    Fail,
    Warn,
    Muted,
}

/// Hero card surface tokens for a given [`HeroTone`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeroSurface {
    pub bg: u32,
    pub border: u32,
    pub title: u32,
    pub subtitle: u32,
    pub pill_bg: u32,
    pub pill_text: u32,
    pub ring: u32,
}

/// Pill/badge surface tokens (`0xRRGGBBAA` with alpha).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadgeSurface {
    pub bg: u32,
    pub text: u32,
    pub dot: u32,
}

/// Timeline 48-bar palette tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimelinePalette {
    pub pass: u32,
    pub warn: u32,
    pub fail: u32,
    pub empty: u32,
}

/// Complete resolved color palette (`0xRRGGBB`, or `0xRRGGBBAA` for alpha surfaces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThemePalette {
    pub is_dark: bool,
    pub name: &'static str,

    // Outer shell & ceramic surfaces (0xRRGGBB)
    pub frame_bg: u32,
    pub frame_border: u32,
    pub card_bg: u32,
    pub card_border: u32,
    pub card_hover_border: u32,
    pub inset_bg: u32,
    pub inset_border: u32,
    pub guide_bg: u32,
    pub line_strong: u32,

    // Typography (0xRRGGBB)
    pub text_primary: u32,
    pub text_secondary: u32,
    pub text_muted: u32,

    // Navigation Dock & Liquid Glass active pill (0xRRGGBB)
    pub sidebar_bg: u32,
    pub sidebar_active_bg: u32,
    pub sidebar_active_text: u32,
    pub sidebar_active_border: u32,
    pub sidebar_hover_bg: u32,
    pub dock_pill_top: u32,
    pub dock_pill_bottom: u32,

    // Switchers & Segmented Capsules (0xRRGGBB)
    pub switcher_track_bg: u32,
    pub switcher_active_bg: u32,
    pub switcher_active_text: u32,
    pub capsule_track_bg: u32,
    pub capsule_active_bg: u32,
    pub capsule_active_text: u32,

    // Interactive buttons & theme accents (0xRRGGBB)
    pub primary_btn_bg: u32,
    pub primary_btn_top: u32,
    pub primary_btn_bottom: u32,
    pub primary_btn_hover_bg: u32,
    pub primary_btn_hover_top: u32,
    pub primary_btn_hover_bottom: u32,
    pub primary_btn_text: u32,
    pub primary_shadow_rgba: u32,
    pub primary_specular_rgba: u32,
    pub specular_top_rgba: u32,
    pub accent_soft_bg: u32,
    pub accent_soft_border: u32,
    pub accent_soft_text: u32,
    pub secondary_btn_bg: u32,
    pub secondary_btn_border: u32,
    pub secondary_btn_text: u32,
    pub danger_btn_bg: u32,
    pub danger_btn_hover_bg: u32,
    pub danger_btn_text: u32,
    pub danger_soft_bg: u32,
    pub danger_soft_border: u32,
    pub danger_soft_text: u32,
    pub link_text: u32,
    pub link_hover_text: u32,

    // Inputs & toggles (0xRRGGBB)
    pub input_bg: u32,
    pub input_border: u32,
    pub input_focus_border: u32,
    pub input_selection_rgba: u32,
    pub toggle_track_off: u32,
    pub toggle_track_on: u32,
    pub toggle_knob: u32,

    // Country `.cc` pill (0xRRGGBB)
    pub cc_pill_bg: u32,
    pub cc_pill_text: u32,

    // Semantic hero cards (`bg`, `border`, `pill_bg`, `ring` use `0xRRGGBBAA`)
    pub hero_healthy: HeroSurface,
    pub hero_tripped: HeroSurface,
    pub hero_disarmed: HeroSurface,

    // Semantic status pills (`bg` uses `0xRRGGBBAA`)
    pub badge_pass: BadgeSurface,
    pub badge_fail: BadgeSurface,
    pub badge_warn: BadgeSurface,
    pub badge_muted: BadgeSurface,

    // 24h timeline bar colors (`0xRRGGBB`)
    pub timeline: TimelinePalette,

    // Floating Dynamic-Island toast surfaces (`0xRRGGBBAA`)
    pub toast_bg_rgba: u32,
    pub toast_border_rgba: u32,

    // Ambient & floating elevation shadows (`0xRRGGBBAA`)
    pub shadow_rgba: u32,
    pub shadow_float_rgba: u32,
    // Modal / HUD overlay scrim (`0xRRGGBBAA`)
    pub scrim_rgba: u32,
}

/// Per-style Light accent tokens layered onto the unified Pure Crisp White & Cool Silver-Gray canvas.
struct LightAccent {
    name: &'static str,
    sidebar_active_text: u32,
    sidebar_active_border: u32,
    primary_btn_bg: u32,
    primary_btn_top: u32,
    primary_btn_bottom: u32,
    primary_btn_hover_bg: u32,
    primary_btn_hover_top: u32,
    primary_btn_hover_bottom: u32,
    primary_btn_text: u32,
    primary_shadow_rgba: u32,
    primary_specular_rgba: u32,
    accent_soft_bg: u32,
    accent_soft_border: u32,
    accent_soft_text: u32,
    link_text: u32,
    link_hover_text: u32,
    input_focus_border: u32,
    input_selection_rgba: u32,
    toggle_track_on: u32,
}

/// Per-style Dark accent tokens layered onto the unified Apple Pro Studio Graphite canvas.
struct DarkAccent {
    name: &'static str,
    sidebar_active_bg: u32,
    sidebar_active_text: u32,
    sidebar_active_border: u32,
    dock_pill_top: u32,
    dock_pill_bottom: u32,
    primary_btn_bg: u32,
    primary_btn_top: u32,
    primary_btn_bottom: u32,
    primary_btn_hover_bg: u32,
    primary_btn_hover_top: u32,
    primary_btn_hover_bottom: u32,
    primary_btn_text: u32,
    primary_shadow_rgba: u32,
    primary_specular_rgba: u32,
    accent_soft_bg: u32,
    accent_soft_border: u32,
    accent_soft_text: u32,
    link_text: u32,
    link_hover_text: u32,
    input_focus_border: u32,
    input_selection_rgba: u32,
    toggle_track_on: u32,
}

/// Builds a Light [`ThemePalette`] anchored on the exact unified Apple Studio White & Cool Gray canvas.
const fn build_light_palette(a: LightAccent) -> ThemePalette {
    ThemePalette {
        is_dark: false,
        name: a.name,

        frame_bg: 0xF3F5F8,
        frame_border: 0xDFE3EC,
        card_bg: 0xFFFFFF,
        card_border: 0xE6E9F0,
        card_hover_border: 0xCFD6E4,
        inset_bg: 0xF6F8FB,
        inset_border: 0xE9EDF4,
        guide_bg: 0xF7F9FC,
        line_strong: 0xCFD6E4,

        text_primary: 0x161B24,
        text_secondary: 0x4C5566,
        text_muted: 0x828B9C,

        sidebar_bg: 0xF8F9FC,
        sidebar_active_bg: 0xFFFFFF,
        sidebar_active_text: a.sidebar_active_text,
        sidebar_active_border: a.sidebar_active_border,
        sidebar_hover_bg: 0xEDF0F6,
        dock_pill_top: 0xFFFFFF,
        dock_pill_bottom: 0xF6F8FC,

        switcher_track_bg: 0xEEF1F6,
        switcher_active_bg: 0xFFFFFF,
        switcher_active_text: 0x161B24,
        capsule_track_bg: 0xEFF2F7,
        capsule_active_bg: 0xFFFFFF,
        capsule_active_text: 0x161B24,

        primary_btn_bg: a.primary_btn_bg,
        primary_btn_top: a.primary_btn_top,
        primary_btn_bottom: a.primary_btn_bottom,
        primary_btn_hover_bg: a.primary_btn_hover_bg,
        primary_btn_hover_top: a.primary_btn_hover_top,
        primary_btn_hover_bottom: a.primary_btn_hover_bottom,
        primary_btn_text: a.primary_btn_text,
        primary_shadow_rgba: a.primary_shadow_rgba,
        primary_specular_rgba: a.primary_specular_rgba,
        specular_top_rgba: 0xFFFFFFE6,
        accent_soft_bg: a.accent_soft_bg,
        accent_soft_border: a.accent_soft_border,
        accent_soft_text: a.accent_soft_text,
        secondary_btn_bg: 0xFFFFFF,
        secondary_btn_border: 0xDCE1EB,
        secondary_btn_text: 0x1E2532,
        danger_btn_bg: 0xBE424F,
        danger_btn_hover_bg: 0xA83642,
        danger_btn_text: 0xFFFFFF,
        danger_soft_bg: 0xFEF6F7,
        danger_soft_border: 0xECCDD1,
        danger_soft_text: 0x9C303C,
        link_text: a.link_text,
        link_hover_text: a.link_hover_text,

        input_bg: 0xFFFFFF,
        input_border: 0xD8DEE9,
        input_focus_border: a.input_focus_border,
        input_selection_rgba: a.input_selection_rgba,
        toggle_track_off: 0xD7DCE6,
        toggle_track_on: a.toggle_track_on,
        toggle_knob: 0xFFFFFF,

        cc_pill_bg: 0xEFF2F7,
        cc_pill_text: 0x1E2532,

        hero_healthy: HeroSurface {
            bg: 0xFFFFFFFF,
            border: 0xE5E9F1FF,
            title: 0x161B24,
            subtitle: 0x4C5566,
            pill_bg: 0x28846214,
            pill_text: 0x1F6E50,
            ring: 0x2F946EFF,
        },
        hero_tripped: HeroSurface {
            bg: 0xFEF9FAFF,
            border: 0xC44B5836,
            title: 0x161B24,
            subtitle: 0x9C303C,
            pill_bg: 0xBE424F14,
            pill_text: 0x9C303C,
            ring: 0xC64956FF,
        },
        hero_disarmed: HeroSurface {
            bg: 0xFFFFFFFF,
            border: 0xE5E8F0FF,
            title: 0x161B24,
            subtitle: 0x4C5566,
            pill_bg: 0xAD7B2E14,
            pill_text: 0x8A5F1E,
            ring: 0xBA8634FF,
        },

        badge_pass: BadgeSurface {
            bg: 0x28846214,
            text: 0x1F6E50,
            dot: 0x2F946E,
        },
        badge_fail: BadgeSurface {
            bg: 0xBE424F14,
            text: 0x9C303C,
            dot: 0xC64956,
        },
        badge_warn: BadgeSurface {
            bg: 0xAD7B2E14,
            text: 0x8A5F1E,
            dot: 0xBA8634,
        },
        badge_muted: BadgeSurface {
            bg: 0x161B240D,
            text: 0x4C5566,
            dot: 0x828B9C,
        },

        timeline: TimelinePalette {
            pass: 0x56A382,
            warn: 0xCFA05A,
            fail: 0xCC6872,
            empty: 0xE7EAF1,
        },

        toast_bg_rgba: 0xFFFFFFF8,
        toast_border_rgba: 0xDCE2EEFF,

        shadow_rgba: 0x0F172A0E,
        shadow_float_rgba: 0x0F172A1E,
        scrim_rgba: 0x0F172A42,
    }
}

/// Builds a Dark [`ThemePalette`] anchored on the exact unified Apple Pro Studio Graphite canvas.
const fn build_dark_palette(a: DarkAccent) -> ThemePalette {
    ThemePalette {
        is_dark: true,
        name: a.name,

        frame_bg: 0x0E1015,
        frame_border: 0x212633,
        card_bg: 0x151820,
        card_border: 0x232836,
        card_hover_border: 0x343C4F,
        inset_bg: 0x1A1E28,
        inset_border: 0x282F3E,
        guide_bg: 0x13161E,
        line_strong: 0x333B4D,

        text_primary: 0xEEF2F9,
        text_secondary: 0x9BA6B8,
        text_muted: 0x6D778A,

        sidebar_bg: 0x13161E,
        sidebar_active_bg: a.sidebar_active_bg,
        sidebar_active_text: a.sidebar_active_text,
        sidebar_active_border: a.sidebar_active_border,
        sidebar_hover_bg: 0x1D222E,
        dock_pill_top: a.dock_pill_top,
        dock_pill_bottom: a.dock_pill_bottom,

        switcher_track_bg: 0x181C26,
        switcher_active_bg: 0x242A38,
        switcher_active_text: 0xEEF2F9,
        capsule_track_bg: 0x181C26,
        capsule_active_bg: 0x242A38,
        capsule_active_text: 0xEEF2F9,

        primary_btn_bg: a.primary_btn_bg,
        primary_btn_top: a.primary_btn_top,
        primary_btn_bottom: a.primary_btn_bottom,
        primary_btn_hover_bg: a.primary_btn_hover_bg,
        primary_btn_hover_top: a.primary_btn_hover_top,
        primary_btn_hover_bottom: a.primary_btn_hover_bottom,
        primary_btn_text: a.primary_btn_text,
        primary_shadow_rgba: a.primary_shadow_rgba,
        primary_specular_rgba: a.primary_specular_rgba,
        specular_top_rgba: 0xFFFFFF14,
        accent_soft_bg: a.accent_soft_bg,
        accent_soft_border: a.accent_soft_border,
        accent_soft_text: a.accent_soft_text,
        secondary_btn_bg: 0x1B1F2A,
        secondary_btn_border: 0x2C3344,
        secondary_btn_text: 0xE6ECF6,
        danger_btn_bg: 0xC64D5A,
        danger_btn_hover_bg: 0xD65B68,
        danger_btn_text: 0xFFFFFF,
        danger_soft_bg: 0x26171C,
        danger_soft_border: 0x4E2B34,
        danger_soft_text: 0xEA9CA4,
        link_text: a.link_text,
        link_hover_text: a.link_hover_text,

        input_bg: 0x11141B,
        input_border: 0x293040,
        input_focus_border: a.input_focus_border,
        input_selection_rgba: a.input_selection_rgba,
        toggle_track_off: 0x293040,
        toggle_track_on: a.toggle_track_on,
        toggle_knob: 0xF4F7FC,

        cc_pill_bg: 0x1E2330,
        cc_pill_text: 0xE6ECF6,

        hero_healthy: HeroSurface {
            bg: 0x151820FF,
            border: 0x252B3AFF,
            title: 0xEEF2F9,
            subtitle: 0x9BA6B8,
            pill_bg: 0x48B58A1A,
            pill_text: 0x7AD4B0,
            ring: 0x48B58AFF,
        },
        hero_tripped: HeroSurface {
            bg: 0x1E1519FF,
            border: 0xD463703C,
            title: 0xEEF2F9,
            subtitle: 0xE6A1A9,
            pill_bg: 0xD463701C,
            pill_text: 0xEA9CA4,
            ring: 0xD86874FF,
        },
        hero_disarmed: HeroSurface {
            bg: 0x151820FF,
            border: 0x2B3140FF,
            title: 0xEEF2F9,
            subtitle: 0x9BA6B8,
            pill_bg: 0xD4A14E1A,
            pill_text: 0xE0B976,
            ring: 0xD4A14EFF,
        },

        badge_pass: BadgeSurface {
            bg: 0x48B58A1A,
            text: 0x7AD4B0,
            dot: 0x48B58A,
        },
        badge_fail: BadgeSurface {
            bg: 0xD463701C,
            text: 0xEA9CA4,
            dot: 0xD86874,
        },
        badge_warn: BadgeSurface {
            bg: 0xD4A14E1A,
            text: 0xE0B976,
            dot: 0xD4A14E,
        },
        badge_muted: BadgeSurface {
            bg: 0xFFFFFF10,
            text: 0x9BA6B8,
            dot: 0x6D778A,
        },

        timeline: TimelinePalette {
            pass: 0x52B08A,
            warn: 0xCFA05A,
            fail: 0xD16B76,
            empty: 0x232836,
        },

        toast_bg_rgba: 0x171B24F6,
        toast_border_rgba: 0x2E3648FF,

        shadow_rgba: 0x0204084C,
        shadow_float_rgba: 0x0102067A,
        scrim_rgba: 0x02040A88,
    }
}

/// Crystal Glass (Light — Default, "琉璃冰晶"): Pure Apple Studio White & Cool Silver-Gray canvas
/// paired with airy sculpted frosted crystal-ice Liquid Glass controls matching the Celestial Origami Shield.
pub const CRYSTAL_GLASS_LIGHT: ThemePalette = build_light_palette(LightAccent {
    name: "Crystal Glass Light",
    sidebar_active_text: 0x1E3D75,
    sidebar_active_border: 0xCDDDF4,
    primary_btn_bg: 0xE5EEFC,
    primary_btn_top: 0xEEF4FE,
    primary_btn_bottom: 0xDAE6FA,
    primary_btn_hover_bg: 0xDAE7FB,
    primary_btn_hover_top: 0xE4EDFD,
    primary_btn_hover_bottom: 0xCEE0FA,
    primary_btn_text: 0x1E3D75,
    primary_shadow_rgba: 0x244A8A1A,
    primary_specular_rgba: 0xFFFFFFF0,
    accent_soft_bg: 0xEEF4FD,
    accent_soft_border: 0xB8CEEF,
    accent_soft_text: 0x1E3D75,
    link_text: 0x486492,
    link_hover_text: 0x1E3D75,
    input_focus_border: 0x5B84CC,
    input_selection_rgba: 0x5B84CC24,
    toggle_track_on: 0x4E78C2,
});

/// Crystal Glass (Dark — Default, "琉璃冰晶"): Pure Apple Pro Studio Graphite canvas paired with
/// sculpted frosted dark-crystal Liquid Glass controls and crisp ice-white ink.
pub const CRYSTAL_GLASS_DARK: ThemePalette = build_dark_palette(DarkAccent {
    name: "Crystal Glass Dark",
    sidebar_active_bg: 0x1D283D,
    sidebar_active_text: 0xD7E6FF,
    sidebar_active_border: 0x354E7A,
    dock_pill_top: 0x253452,
    dock_pill_bottom: 0x1B263D,
    primary_btn_bg: 0x233659,
    primary_btn_top: 0x2B4068,
    primary_btn_bottom: 0x1D2D4C,
    primary_btn_hover_bg: 0x2C436E,
    primary_btn_hover_top: 0x344D7D,
    primary_btn_hover_bottom: 0x253A61,
    primary_btn_text: 0xECF3FF,
    primary_shadow_rgba: 0x050D1E5A,
    primary_specular_rgba: 0xA8C8FF38,
    accent_soft_bg: 0x1C2840,
    accent_soft_border: 0x3D5D96,
    accent_soft_text: 0xC4DCFF,
    link_text: 0x90B5EE,
    link_hover_text: 0xD7E6FF,
    input_focus_border: 0x5B88D4,
    input_selection_rgba: 0x5B88D438,
    toggle_track_on: 0x5B88D4,
});

/// Linear Indigo (Light — "线性星靛"): Pure Apple Studio White & Cool Gray canvas paired with
/// Silicon Valley Linear / Stripe precision periwinkle-indigo (`#5B69D0`) controls.
pub const LINEAR_INDIGO_LIGHT: ThemePalette = build_light_palette(LightAccent {
    name: "Linear Indigo Light",
    sidebar_active_text: 0x424EB5,
    sidebar_active_border: 0xD2D6F5,
    primary_btn_bg: 0x5B69D0,
    primary_btn_top: 0x6A78DE,
    primary_btn_bottom: 0x4D5AC0,
    primary_btn_hover_bg: 0x6674D9,
    primary_btn_hover_top: 0x7583E6,
    primary_btn_hover_bottom: 0x5765CC,
    primary_btn_text: 0xFFFFFF,
    primary_shadow_rgba: 0x3E4AA828,
    primary_specular_rgba: 0xFFFFFF40,
    accent_soft_bg: 0xF0F1FD,
    accent_soft_border: 0xCED2F5,
    accent_soft_text: 0x424EB5,
    link_text: 0x5460B8,
    link_hover_text: 0x3E49A8,
    input_focus_border: 0x5B69D0,
    input_selection_rgba: 0x5B69D026,
    toggle_track_on: 0x5B69D0,
});

/// Linear Indigo (Dark — "线性星靛"): Pure Apple Pro Studio Graphite canvas paired with
/// luminous periwinkle-indigo controls and refined mineral semantics.
pub const LINEAR_INDIGO_DARK: ThemePalette = build_dark_palette(DarkAccent {
    name: "Linear Indigo Dark",
    sidebar_active_bg: 0x202440,
    sidebar_active_text: 0xD2D8FF,
    sidebar_active_border: 0x3C437A,
    dock_pill_top: 0x282D4F,
    dock_pill_bottom: 0x1E223D,
    primary_btn_bg: 0x6876DE,
    primary_btn_top: 0x7A87EA,
    primary_btn_bottom: 0x5866CC,
    primary_btn_hover_bg: 0x7481E5,
    primary_btn_hover_top: 0x8692F0,
    primary_btn_hover_bottom: 0x6471D4,
    primary_btn_text: 0xF8F9FF,
    primary_shadow_rgba: 0x0B0E2E5C,
    primary_specular_rgba: 0xFFFFFF38,
    accent_soft_bg: 0x1F2342,
    accent_soft_border: 0x39407A,
    accent_soft_text: 0xB8C0FF,
    link_text: 0x9BA6F2,
    link_hover_text: 0xD2D8FF,
    input_focus_border: 0x7481E5,
    input_selection_rgba: 0x7481E53A,
    toggle_track_on: 0x6C7AE2,
});

/// Minimal Mist (Light — "莫兰迪雾"): Preserved low-saturation Morandi chalk slate-blue (`#6D839B`)
/// accents unified onto the pure crisp White & Cool Gray studio canvas.
pub const MINIMAL_MIST_LIGHT: ThemePalette = build_light_palette(LightAccent {
    name: "Minimal Mist Light",
    sidebar_active_text: 0x3D536B,
    sidebar_active_border: 0xD5DFE9,
    primary_btn_bg: 0x6D839B,
    primary_btn_top: 0x798FA7,
    primary_btn_bottom: 0x60768E,
    primary_btn_hover_bg: 0x778DA6,
    primary_btn_hover_top: 0x849AB2,
    primary_btn_hover_bottom: 0x6A8098,
    primary_btn_text: 0xFFFFFF,
    primary_shadow_rgba: 0x4E657D24,
    primary_specular_rgba: 0xFFFFFF44,
    accent_soft_bg: 0xEEF2F6,
    accent_soft_border: 0xD5DFEA,
    accent_soft_text: 0x496078,
    link_text: 0x5C7187,
    link_hover_text: 0x3D536B,
    input_focus_border: 0x788EA6,
    input_selection_rgba: 0x6D839B28,
    toggle_track_on: 0x788EA6,
});

/// Minimal Mist (Dark — "莫兰迪雾"): Unified Apple Pro Studio Graphite canvas paired with
/// luminous chalk slate-blue primary controls.
pub const MINIMAL_MIST_DARK: ThemePalette = build_dark_palette(DarkAccent {
    name: "Minimal Mist Dark",
    sidebar_active_bg: 0x202631,
    sidebar_active_text: 0xC6D6E8,
    sidebar_active_border: 0x384355,
    dock_pill_top: 0x272E3B,
    dock_pill_bottom: 0x1E232E,
    primary_btn_bg: 0x849DB7,
    primary_btn_top: 0x8FA7C0,
    primary_btn_bottom: 0x7A93AD,
    primary_btn_hover_bg: 0x90A8C1,
    primary_btn_hover_top: 0x9BB2CA,
    primary_btn_hover_bottom: 0x859EB8,
    primary_btn_text: 0x12161D,
    primary_shadow_rgba: 0x05070B50,
    primary_specular_rgba: 0xFFFFFF44,
    accent_soft_bg: 0x1D2430,
    accent_soft_border: 0x334054,
    accent_soft_text: 0xB8CBE0,
    link_text: 0x9FB5CC,
    link_hover_text: 0xC6D8EB,
    input_focus_border: 0x849DB7,
    input_selection_rgba: 0x849DB736,
    toggle_track_on: 0x7890A9,
});

/// Alpine Sapphire (Light — "深海蓝宝"): Preserved Swiss horology deep sapphire (`#2B4F8D`)
/// accents unified onto the pure crisp White & Cool Gray studio canvas.
pub const ALPINE_SAPPHIRE_LIGHT: ThemePalette = build_light_palette(LightAccent {
    name: "Alpine Sapphire Light",
    sidebar_active_text: 0x1F3D73,
    sidebar_active_border: 0xCDD8EB,
    primary_btn_bg: 0x203E72,
    primary_btn_top: 0x2B4F8D,
    primary_btn_bottom: 0x1B3563,
    primary_btn_hover_bg: 0x284B87,
    primary_btn_hover_top: 0x345DA3,
    primary_btn_hover_bottom: 0x224178,
    primary_btn_text: 0xFFFFFF,
    primary_shadow_rgba: 0x142A5230,
    primary_specular_rgba: 0xFFFFFF3A,
    accent_soft_bg: 0xEDF2FA,
    accent_soft_border: 0xCFDCEF,
    accent_soft_text: 0x1F3D73,
    link_text: 0x465875,
    link_hover_text: 0x1F3D73,
    input_focus_border: 0x2B4F8D,
    input_selection_rgba: 0x2B4F8D26,
    toggle_track_on: 0x2B4F8D,
});

/// Alpine Sapphire (Dark — "深海蓝宝"): Unified Apple Pro Studio Graphite canvas paired with
/// luminous steel-sapphire primary accents.
pub const ALPINE_SAPPHIRE_DARK: ThemePalette = build_dark_palette(DarkAccent {
    name: "Alpine Sapphire Dark",
    sidebar_active_bg: 0x1D283E,
    sidebar_active_text: 0xD8E7FF,
    sidebar_active_border: 0x384B6E,
    dock_pill_top: 0x25334D,
    dock_pill_bottom: 0x1B253A,
    primary_btn_bg: 0x4A72B5,
    primary_btn_top: 0x5A83C9,
    primary_btn_bottom: 0x3E62A1,
    primary_btn_hover_bg: 0x5881C4,
    primary_btn_hover_top: 0x6891D6,
    primary_btn_hover_bottom: 0x4A70B2,
    primary_btn_text: 0xF7FAFF,
    primary_shadow_rgba: 0x04091660,
    primary_specular_rgba: 0xFFFFFF30,
    accent_soft_bg: 0x1B2842,
    accent_soft_border: 0x304770,
    accent_soft_text: 0xAEC9F5,
    link_text: 0x9BB3D8,
    link_hover_text: 0xCBE0FF,
    input_focus_border: 0x5A83C9,
    input_selection_rgba: 0x5A83C938,
    toggle_track_on: 0x4C75B8,
});

/// Obsidian Ink (Light — "曜石极黑"): Classic v4 monochrome obsidian (`#1E222C`) accents unified
/// onto the pure crisp White & Cool Gray studio canvas.
pub const OBSIDIAN_INK_LIGHT: ThemePalette = build_light_palette(LightAccent {
    name: "Obsidian Ink Light",
    sidebar_active_text: 0x1B1F27,
    sidebar_active_border: 0xD4D7DF,
    primary_btn_bg: 0x1E222C,
    primary_btn_top: 0x2A2F3B,
    primary_btn_bottom: 0x171A22,
    primary_btn_hover_bg: 0x2B303C,
    primary_btn_hover_top: 0x353B49,
    primary_btn_hover_bottom: 0x212631,
    primary_btn_text: 0xFFFFFF,
    primary_shadow_rgba: 0x0B0D122C,
    primary_specular_rgba: 0xFFFFFF32,
    accent_soft_bg: 0xEEF0F4,
    accent_soft_border: 0xD6D9E0,
    accent_soft_text: 0x1E222C,
    link_text: 0x4E5563,
    link_hover_text: 0x161B24,
    input_focus_border: 0x2A2F3B,
    input_selection_rgba: 0x2A2F3B20,
    toggle_track_on: 0x1E222C,
});

/// Obsidian Ink (Dark — "曜石极黑"): Unified Apple Pro Studio Graphite canvas paired with
/// luminous ivory-platinum monochrome CTA.
pub const OBSIDIAN_INK_DARK: ThemePalette = build_dark_palette(DarkAccent {
    name: "Obsidian Ink Dark",
    sidebar_active_bg: 0x1E222C,
    sidebar_active_text: 0xF5F7FA,
    sidebar_active_border: 0x353C4B,
    dock_pill_top: 0x252A36,
    dock_pill_bottom: 0x1C2029,
    primary_btn_bg: 0xDCE1EB,
    primary_btn_top: 0xEAEEF5,
    primary_btn_bottom: 0xCFD6E3,
    primary_btn_hover_bg: 0xE7ECF4,
    primary_btn_hover_top: 0xF4F6FA,
    primary_btn_hover_bottom: 0xDAE0EC,
    primary_btn_text: 0x111318,
    primary_shadow_rgba: 0x02030658,
    primary_specular_rgba: 0xFFFFFF58,
    accent_soft_bg: 0x1E2129,
    accent_soft_border: 0x343A48,
    accent_soft_text: 0xDCE0E8,
    link_text: 0xA2A9B8,
    link_hover_text: 0xEBEEF4,
    input_focus_border: 0x8A92A0,
    input_selection_rgba: 0x8A92A038,
    toggle_track_on: 0x8A92A0,
});

/// Default Light palette alias (preserved for backward compatibility).
pub const LIGHT_C2: ThemePalette = CRYSTAL_GLASS_LIGHT;

/// Default Dark palette alias (preserved for backward compatibility).
pub const DARK_C3: ThemePalette = CRYSTAL_GLASS_DARK;

impl ThemePalette {
    pub fn hero(&self, tone: HeroTone) -> HeroSurface {
        match tone {
            HeroTone::Healthy => self.hero_healthy,
            HeroTone::Tripped => self.hero_tripped,
            HeroTone::DisarmedOrPaused => self.hero_disarmed,
        }
    }

    pub fn badge(&self, tone: BadgeTone) -> BadgeSurface {
        match tone {
            BadgeTone::Pass => self.badge_pass,
            BadgeTone::Fail => self.badge_fail,
            BadgeTone::Warn => self.badge_warn,
            BadgeTone::Muted => self.badge_muted,
        }
    }
}

/// Resolves the active [`ThemePalette`] given [`ThemeStyle`], [`ThemeMode`], and system polarity.
pub fn resolve_styled_palette(
    style: ThemeStyle,
    mode: ThemeMode,
    system_prefers_light: bool,
) -> &'static ThemePalette {
    let is_light = match mode {
        ThemeMode::Light => true,
        ThemeMode::Dark => false,
        ThemeMode::Auto => system_prefers_light,
    };
    match (style, is_light) {
        (ThemeStyle::CrystalGlass, true) => &CRYSTAL_GLASS_LIGHT,
        (ThemeStyle::CrystalGlass, false) => &CRYSTAL_GLASS_DARK,
        (ThemeStyle::LinearIndigo, true) => &LINEAR_INDIGO_LIGHT,
        (ThemeStyle::LinearIndigo, false) => &LINEAR_INDIGO_DARK,
        (ThemeStyle::MinimalMist, true) => &MINIMAL_MIST_LIGHT,
        (ThemeStyle::MinimalMist, false) => &MINIMAL_MIST_DARK,
        (ThemeStyle::AlpineSapphire, true) => &ALPINE_SAPPHIRE_LIGHT,
        (ThemeStyle::AlpineSapphire, false) => &ALPINE_SAPPHIRE_DARK,
        (ThemeStyle::ObsidianInk, true) => &OBSIDIAN_INK_LIGHT,
        (ThemeStyle::ObsidianInk, false) => &OBSIDIAN_INK_DARK,
    }
}

/// Resolves the default ([`ThemeStyle::CrystalGlass`]) [`ThemePalette`] for `mode` and system polarity.
pub fn resolve_palette(mode: ThemeMode, system_prefers_light: bool) -> &'static ThemePalette {
    resolve_styled_palette(ThemeStyle::CrystalGlass, mode, system_prefers_light)
}

/// Detects whether Windows currently prefers Light apps (`AppsUseLightTheme != 0`).
#[cfg(windows)]
pub fn system_prefers_light_theme() -> bool {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        .and_then(|k| k.get_value::<u32, _>("AppsUseLightTheme"))
        .map(|v| v != 0)
        .unwrap_or(true)
}

#[cfg(not(windows))]
pub fn system_prefers_light_theme() -> bool {
    true
}

/// Convenience `0xRRGGBB` -> GPUI `Rgba`.
pub fn c_rgb(hex: u32) -> Rgba {
    rgb(hex)
}

/// Convenience `0xRRGGBBAA` -> GPUI `Rgba`.
pub fn c_rgba(hex: u32) -> Rgba {
    rgba(hex)
}

/// Convenience `0xRRGGBB` -> GPUI `Hsla`.
pub fn c_hsla(hex: u32) -> Hsla {
    rgb(hex).into()
}

/// Layout constants for Mode A (Tray Quick HUD) and Mode B (Main Console).
pub mod layout {
    pub const HUD_WIDTH: f32 = 398.0;
    pub const HUD_HEIGHT: f32 = 432.0;

    pub const CONSOLE_WIDTH: f32 = 944.0;
    pub const CONSOLE_HEIGHT: f32 = 682.0;
    pub const CONSOLE_MIN_WIDTH: f32 = 820.0;
    pub const CONSOLE_MIN_HEIGHT: f32 = 580.0;

    pub const SIDEBAR_WIDTH: f32 = 192.0;
    pub const TOPBAR_HEIGHT: f32 = 44.0;
    pub const BENTO_GAP: f32 = 12.0;
    pub const RADIUS_FRAME: f32 = 20.0;
    pub const RADIUS_BENTO: f32 = 16.0;
    pub const RADIUS_INSET: f32 = 11.0;
    pub const RADIUS_CONTROL: f32 = 9.0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_style_round_trips_keys_metadata_and_v2_persistence() {
        assert_eq!(ThemeStyle::default(), ThemeStyle::CrystalGlass);
        assert_eq!(THEME_STYLES.len(), 5);

        for style in THEME_STYLES {
            assert_eq!(ThemeStyle::from_key(style.key()), Some(style));
            assert_eq!(
                ThemeStyle::from_key(&format!("  {} \n", style.key())),
                Some(style)
            );
            assert!(!style.label().is_empty());
            assert!(!style.tagline().is_empty());
            assert_ne!(style.swatch_accent(false), style.swatch_surface(false));
            assert_ne!(style.swatch_accent(true), style.swatch_surface(true));

            let v2_json = format!("{{\"v\":2,\"style\":\"{}\"}}\n", style.key());
            assert_eq!(parse_theme_style_json(&v2_json), style);

            // Legacy v1 files without `"v":2` must migrate cleanly to CrystalGlass default
            let v1_json = format!("{{\"style\":\"{}\"}}\n", style.key());
            assert_eq!(parse_theme_style_json(&v1_json), ThemeStyle::CrystalGlass);
        }

        assert_eq!(ThemeStyle::CrystalGlass.label(), "琉璃冰晶");
        assert_eq!(ThemeStyle::LinearIndigo.label(), "线性星靛");
        assert_eq!(ThemeStyle::MinimalMist.label(), "莫兰迪雾");
        assert_eq!(ThemeStyle::AlpineSapphire.label(), "深海蓝宝");
        assert_eq!(ThemeStyle::ObsidianInk.label(), "曜石极黑");

        assert_eq!(ThemeStyle::from_key("unknown_style"), None);
        assert_eq!(parse_theme_style_json(""), ThemeStyle::CrystalGlass);
        assert_eq!(
            parse_theme_style_json("{\"v\":1,\"style\":\"obsidian_ink\"}"),
            ThemeStyle::CrystalGlass
        );
        assert_eq!(
            parse_theme_style_json("{\"v\":20,\"style\":\"obsidian_ink\"}"),
            ThemeStyle::CrystalGlass
        );
        assert_eq!(
            parse_theme_style_json("{ \"v\" : 2 , \"style\" : \"linear_indigo\" }"),
            ThemeStyle::LinearIndigo
        );
        assert_eq!(
            parse_theme_style_json("{\"v\":2,\"style\":\"bogus\"}"),
            ThemeStyle::CrystalGlass
        );
    }

    #[test]
    fn crystal_glass_default_and_linear_indigo_tokens_match_spec() {
        assert_eq!(LIGHT_C2, CRYSTAL_GLASS_LIGHT);
        assert_eq!(DARK_C3, CRYSTAL_GLASS_DARK);

        const { assert!(!CRYSTAL_GLASS_LIGHT.is_dark) };
        assert_eq!(CRYSTAL_GLASS_LIGHT.frame_bg, 0xF3F5F8);
        assert_eq!(CRYSTAL_GLASS_LIGHT.card_bg, 0xFFFFFF);
        assert_eq!(CRYSTAL_GLASS_LIGHT.card_border, 0xE6E9F0);
        assert_eq!(CRYSTAL_GLASS_LIGHT.primary_btn_top, 0xEEF4FE);
        assert_eq!(CRYSTAL_GLASS_LIGHT.primary_btn_bg, 0xE5EEFC);
        assert_eq!(CRYSTAL_GLASS_LIGHT.primary_btn_bottom, 0xDAE6FA);
        assert_eq!(CRYSTAL_GLASS_LIGHT.primary_btn_text, 0x1E3D75);
        assert_eq!(CRYSTAL_GLASS_LIGHT.accent_soft_border, 0xB8CEEF);
        assert_eq!(CRYSTAL_GLASS_LIGHT.toggle_track_on, 0x4E78C2);
        assert_eq!(CRYSTAL_GLASS_LIGHT.hero_healthy.bg, 0xFFFFFFFF);
        assert_eq!(CRYSTAL_GLASS_LIGHT.hero_disarmed.bg, 0xFFFFFFFF);
        assert_eq!(CRYSTAL_GLASS_LIGHT.hero_disarmed.border, 0xE5E8F0FF);
        assert_eq!(CRYSTAL_GLASS_LIGHT.badge_pass.dot, 0x2F946E);
        assert_eq!(CRYSTAL_GLASS_LIGHT.badge_warn.dot, 0xBA8634);
        assert_eq!(CRYSTAL_GLASS_LIGHT.badge_fail.dot, 0xC64956);
        assert_eq!(CRYSTAL_GLASS_LIGHT.timeline.pass, 0x56A382);
        assert_eq!(CRYSTAL_GLASS_LIGHT.timeline.warn, 0xCFA05A);
        assert_eq!(CRYSTAL_GLASS_LIGHT.timeline.fail, 0xCC6872);

        const { assert!(CRYSTAL_GLASS_DARK.is_dark) };
        assert_eq!(CRYSTAL_GLASS_DARK.frame_bg, 0x0E1015);
        assert_eq!(CRYSTAL_GLASS_DARK.card_bg, 0x151820);
        assert_eq!(CRYSTAL_GLASS_DARK.primary_btn_top, 0x2B4068);
        assert_eq!(CRYSTAL_GLASS_DARK.primary_btn_bg, 0x233659);
        assert_eq!(CRYSTAL_GLASS_DARK.primary_btn_bottom, 0x1D2D4C);
        assert_eq!(CRYSTAL_GLASS_DARK.primary_btn_text, 0xECF3FF);
        assert_eq!(CRYSTAL_GLASS_DARK.toggle_track_on, 0x5B88D4);

        assert_eq!(LINEAR_INDIGO_LIGHT.primary_btn_top, 0x6A78DE);
        assert_eq!(LINEAR_INDIGO_LIGHT.primary_btn_bg, 0x5B69D0);
        assert_eq!(LINEAR_INDIGO_LIGHT.primary_btn_bottom, 0x4D5AC0);
        assert_eq!(LINEAR_INDIGO_LIGHT.primary_btn_text, 0xFFFFFF);
        assert_eq!(LINEAR_INDIGO_LIGHT.toggle_track_on, 0x5B69D0);
        assert_eq!(LINEAR_INDIGO_DARK.primary_btn_bg, 0x6876DE);
        assert_eq!(LINEAR_INDIGO_DARK.primary_btn_text, 0xF8F9FF);
    }

    #[test]
    fn all_ten_palettes_share_unified_crisp_canvas_with_distinct_accents() {
        let pairs = [
            (
                ThemeStyle::CrystalGlass,
                &CRYSTAL_GLASS_LIGHT,
                &CRYSTAL_GLASS_DARK,
            ),
            (
                ThemeStyle::LinearIndigo,
                &LINEAR_INDIGO_LIGHT,
                &LINEAR_INDIGO_DARK,
            ),
            (
                ThemeStyle::MinimalMist,
                &MINIMAL_MIST_LIGHT,
                &MINIMAL_MIST_DARK,
            ),
            (
                ThemeStyle::AlpineSapphire,
                &ALPINE_SAPPHIRE_LIGHT,
                &ALPINE_SAPPHIRE_DARK,
            ),
            (
                ThemeStyle::ObsidianInk,
                &OBSIDIAN_INK_LIGHT,
                &OBSIDIAN_INK_DARK,
            ),
        ];

        for (style, light, dark) in pairs {
            assert!(!light.is_dark);
            assert!(dark.is_dark);
            assert_ne!(light.name, dark.name);

            // Unified crisp Studio White & Cool Gray neutral canvas across ALL 5 Light themes
            assert_eq!(light.frame_bg, 0xF3F5F8);
            assert_eq!(light.frame_border, 0xDFE3EC);
            assert_eq!(light.card_bg, 0xFFFFFF);
            assert_eq!(light.card_border, 0xE6E9F0);
            assert_eq!(light.inset_bg, 0xF6F8FB);
            assert_eq!(light.sidebar_bg, 0xF8F9FC);
            assert_eq!(light.text_primary, 0x161B24);
            assert_eq!(light.hero_healthy.bg, 0xFFFFFFFF);
            assert_eq!(light.hero_disarmed.bg, 0xFFFFFFFF);
            assert_eq!(light.hero_disarmed.border, 0xE5E8F0FF);

            // Unified Apple Pro Studio Graphite neutral canvas across ALL 5 Dark themes
            assert_eq!(dark.frame_bg, 0x0E1015);
            assert_eq!(dark.frame_border, 0x212633);
            assert_eq!(dark.card_bg, 0x151820);
            assert_eq!(dark.card_border, 0x232836);
            assert_eq!(dark.inset_bg, 0x1A1E28);
            assert_eq!(dark.sidebar_bg, 0x13161E);
            assert_eq!(dark.text_primary, 0xEEF2F9);
            assert_eq!(dark.hero_healthy.bg, 0x151820FF);
            assert_eq!(dark.hero_disarmed.bg, 0x151820FF);

            assert_eq!(
                resolve_styled_palette(style, ThemeMode::Light, false),
                light
            );
            assert_eq!(resolve_styled_palette(style, ThemeMode::Dark, true), dark);
            assert_eq!(resolve_styled_palette(style, ThemeMode::Auto, true), light);
            assert_eq!(resolve_styled_palette(style, ThemeMode::Auto, false), dark);
        }

        // All 5 Light CTA accents and 5 Dark CTA accents must be genuinely distinct
        let light_accents = [
            CRYSTAL_GLASS_LIGHT.primary_btn_bg,
            LINEAR_INDIGO_LIGHT.primary_btn_bg,
            MINIMAL_MIST_LIGHT.primary_btn_bg,
            ALPINE_SAPPHIRE_LIGHT.primary_btn_bg,
            OBSIDIAN_INK_LIGHT.primary_btn_bg,
        ];
        let dark_accents = [
            CRYSTAL_GLASS_DARK.primary_btn_bg,
            LINEAR_INDIGO_DARK.primary_btn_bg,
            MINIMAL_MIST_DARK.primary_btn_bg,
            ALPINE_SAPPHIRE_DARK.primary_btn_bg,
            OBSIDIAN_INK_DARK.primary_btn_bg,
        ];
        for i in 0..light_accents.len() {
            for j in (i + 1)..light_accents.len() {
                assert_ne!(light_accents[i], light_accents[j]);
                assert_ne!(dark_accents[i], dark_accents[j]);
            }
        }
    }

    #[test]
    fn resolve_palette_respects_auto_preference() {
        assert_eq!(resolve_palette(ThemeMode::Light, false).name, LIGHT_C2.name);
        assert_eq!(resolve_palette(ThemeMode::Dark, true).name, DARK_C3.name);
        assert_eq!(resolve_palette(ThemeMode::Auto, true).name, LIGHT_C2.name);
        assert_eq!(resolve_palette(ThemeMode::Auto, false).name, DARK_C3.name);
    }
}
