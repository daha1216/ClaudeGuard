//! Scheme C (Glass Bento) theme system: C2 Light (`Apple Silver Frost`) + C3 Dark (`Obsidian Emerald`).
//!
//! Supports `Light`, `Dark`, and `Auto` (follows Windows `HKCU\...\Personalize\AppsUseLightTheme`).

pub use cg_protocol::ThemeMode;
use gpui::{Hsla, Rgba, rgb, rgba};

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

/// Visual tone for the Hero Bento card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeroTone {
    Healthy,
    Tripped,
    DisarmedOrPaused,
}

/// Visual tone for status pills and target badges.
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

/// Complete resolved Scheme C color palette (`0xRRGGBB` or `0xRRGGBBAA` for alpha surfaces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThemePalette {
    pub is_dark: bool,
    pub name: &'static str,

    // Outer frame & surfaces (0xRRGGBB)
    pub frame_bg: u32,
    pub frame_border: u32,
    pub card_bg: u32,
    pub card_border: u32,
    pub inset_bg: u32,
    pub inset_border: u32,

    // Typography (0xRRGGBB)
    pub text_primary: u32,
    pub text_secondary: u32,
    pub text_muted: u32,

    // Sidebar & navigation (0xRRGGBB)
    pub sidebar_bg: u32,
    pub sidebar_active_bg: u32,
    pub sidebar_active_text: u32,
    pub sidebar_active_border: u32,
    pub sidebar_hover_bg: u32,

    // Switchers & Segmented Capsules (0xRRGGBB)
    pub switcher_track_bg: u32,
    pub switcher_active_bg: u32,
    pub switcher_active_text: u32,
    pub capsule_track_bg: u32,
    pub capsule_active_bg: u32,
    pub capsule_active_text: u32,

    // Interactive buttons & accents (0xRRGGBB)
    pub primary_btn_bg: u32,
    pub primary_btn_hover_bg: u32,
    pub primary_btn_text: u32,
    pub secondary_btn_bg: u32,
    pub secondary_btn_border: u32,
    pub secondary_btn_text: u32,
    pub danger_btn_bg: u32,
    pub danger_btn_text: u32,
    pub link_text: u32,

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

    // Ambient shadow (`0xRRGGBBAA`)
    pub shadow_rgba: u32,
}

/// C2 · Apple Silver Frost (Light): pure silver-frost cold white with zero heavy dark slabs.
pub const LIGHT_C2: ThemePalette = ThemePalette {
    is_dark: false,
    name: "C2 · Apple Silver Frost",

    frame_bg: 0xEEF1F6,
    frame_border: 0xD8E0EA,
    card_bg: 0xFFFFFF,
    card_border: 0xE2E8F0,
    inset_bg: 0xF8FAFC,
    inset_border: 0xE2E8F0,

    text_primary: 0x0F172A,
    text_secondary: 0x475569,
    text_muted: 0x64748B,

    sidebar_bg: 0xFFFFFF,
    sidebar_active_bg: 0xE8F1FD,
    sidebar_active_text: 0x0066CC,
    sidebar_active_border: 0xBFDBFE,
    sidebar_hover_bg: 0xF1F5F9,

    switcher_track_bg: 0xE2E8F0,
    switcher_active_bg: 0xFFFFFF,
    switcher_active_text: 0x0F172A,
    capsule_track_bg: 0xE2E8F0,
    capsule_active_bg: 0xFFFFFF,
    capsule_active_text: 0x0F172A,

    primary_btn_bg: 0x0066CC,
    primary_btn_hover_bg: 0x0052A3,
    primary_btn_text: 0xFFFFFF,
    secondary_btn_bg: 0xFFFFFF,
    secondary_btn_border: 0xCBD5E1,
    secondary_btn_text: 0x0F172A,
    danger_btn_bg: 0xDC2626,
    danger_btn_text: 0xFFFFFF,
    link_text: 0x0066CC,

    input_bg: 0xFFFFFF,
    input_border: 0xCBD5E1,
    input_focus_border: 0x0066CC,
    input_selection_rgba: 0x0066CC2E,
    toggle_track_off: 0xCBD5E1,
    toggle_track_on: 0x0066CC,
    toggle_knob: 0xFFFFFF,

    cc_pill_bg: 0xE2E8F0,
    cc_pill_text: 0x334155,

    hero_healthy: HeroSurface {
        bg: 0xF3FDF7FF,
        border: 0xBBF7D0FF,
        title: 0x0F172A,
        subtitle: 0x475569,
        pill_bg: 0xDCFCE7FF,
        pill_text: 0x15803D,
        ring: 0x16A34AFF,
    },
    hero_tripped: HeroSurface {
        bg: 0xFEF2F2FF,
        border: 0xFCA5A5FF,
        title: 0x991B1B,
        subtitle: 0x7F1D1D,
        pill_bg: 0xFEE2E2FF,
        pill_text: 0xB91C1C,
        ring: 0xEF4444FF,
    },
    hero_disarmed: HeroSurface {
        bg: 0xFFFBEBFF,
        border: 0xFCD34DFF,
        title: 0x92400E,
        subtitle: 0x78350F,
        pill_bg: 0xFEF3C7FF,
        pill_text: 0xB45309,
        ring: 0xF59E0BFF,
    },

    badge_pass: BadgeSurface {
        bg: 0xECFDF5FF,
        text: 0x15803D,
        dot: 0x16A34A,
    },
    badge_fail: BadgeSurface {
        bg: 0xFEF2F2FF,
        text: 0xB91C1C,
        dot: 0xEF4444,
    },
    badge_warn: BadgeSurface {
        bg: 0xFFFBEBFF,
        text: 0xB45309,
        dot: 0xF59E0B,
    },
    badge_muted: BadgeSurface {
        bg: 0xF1F5F9FF,
        text: 0x64748B,
        dot: 0x94A3B8,
    },

    timeline: TimelinePalette {
        pass: 0x16A34A,
        warn: 0xF59E0B,
        fail: 0xEF4444,
        empty: 0xE2E8F0,
    },

    shadow_rgba: 0x0F172A0E,
};

/// C3 · Obsidian Emerald (Dark): OLED eye-care dark obsidian with emerald accents.
pub const DARK_C3: ThemePalette = ThemePalette {
    is_dark: true,
    name: "C3 · Obsidian Emerald",

    frame_bg: 0x0E1117,
    frame_border: 0x242B3A,
    card_bg: 0x161A24,
    card_border: 0x252D3D,
    inset_bg: 0x10141D,
    inset_border: 0x202736,

    text_primary: 0xF1F5F9,
    text_secondary: 0xCBD5E1,
    text_muted: 0x94A3B8,

    sidebar_bg: 0x161A24,
    sidebar_active_bg: 0x21293A,
    sidebar_active_text: 0x34D399,
    sidebar_active_border: 0x2F3B52,
    sidebar_hover_bg: 0x1D2433,

    switcher_track_bg: 0x1D2433,
    switcher_active_bg: 0x2A3448,
    switcher_active_text: 0xF8FAFC,
    capsule_track_bg: 0x161A24,
    capsule_active_bg: 0x242C3E,
    capsule_active_text: 0xF8FAFC,

    primary_btn_bg: 0x10B981,
    primary_btn_hover_bg: 0x059669,
    primary_btn_text: 0x052E16,
    secondary_btn_bg: 0x1D2433,
    secondary_btn_border: 0x2F3B52,
    secondary_btn_text: 0xF1F5F9,
    danger_btn_bg: 0xEF4444,
    danger_btn_text: 0xFFFFFF,
    link_text: 0x38BDF8,

    input_bg: 0x10141D,
    input_border: 0x252D3D,
    input_focus_border: 0x34D399,
    input_selection_rgba: 0x34D39938,
    toggle_track_off: 0x2A3448,
    toggle_track_on: 0x10B981,
    toggle_knob: 0xF8FAFC,

    cc_pill_bg: 0x252D3D,
    cc_pill_text: 0xCBD5E1,

    hero_healthy: HeroSurface {
        bg: 0x0E2E24FF,
        border: 0x34D39966, // rgba(52,211,153,0.40)
        title: 0xF8FAFC,
        subtitle: 0xCBD5E1,
        pill_bg: 0x10B98138, // rgba(16,185,129,0.22)
        pill_text: 0x6EE7B7,
        ring: 0x34D3998C, // rgba(52,211,153,0.55)
    },
    hero_tripped: HeroSurface {
        bg: 0x2D1219FF,
        border: 0xF8717173, // rgba(248,113,113,0.45)
        title: 0xFEF2F2,
        subtitle: 0xFECACA,
        pill_bg: 0xEF444438,
        pill_text: 0xFCA5A5,
        ring: 0xF8717199,
    },
    hero_disarmed: HeroSurface {
        bg: 0x2B200EFF,
        border: 0xFBBF246B, // rgba(251,191,36,0.42)
        title: 0xFEF3C7,
        subtitle: 0xFDE68A,
        pill_bg: 0xF59E0B38,
        pill_text: 0xFCD34D,
        ring: 0xFBBF2494,
    },

    badge_pass: BadgeSurface {
        bg: 0x10B98126, // rgba(16,185,129,0.15)
        text: 0x34D399,
        dot: 0x10B981,
    },
    badge_fail: BadgeSurface {
        bg: 0xEF444429,
        text: 0xF87171,
        dot: 0xF87171,
    },
    badge_warn: BadgeSurface {
        bg: 0xF59E0B29,
        text: 0xFBBF24,
        dot: 0xFBBF24,
    },
    badge_muted: BadgeSurface {
        bg: 0x252D3DFF,
        text: 0x94A3B8,
        dot: 0x64748B,
    },

    timeline: TimelinePalette {
        pass: 0x10B981,
        warn: 0xFBBF24,
        fail: 0xF87171,
        empty: 0x202736,
    },

    shadow_rgba: 0x00000048,
};

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

/// Resolves a [`ThemeMode`] given whether the host OS prefers light mode.
pub fn resolve_palette(mode: ThemeMode, system_prefers_light: bool) -> &'static ThemePalette {
    match mode {
        ThemeMode::Light => &LIGHT_C2,
        ThemeMode::Dark => &DARK_C3,
        ThemeMode::Auto => {
            if system_prefers_light {
                &LIGHT_C2
            } else {
                &DARK_C3
            }
        }
    }
}

/// Reads Windows `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme`.
/// Returns `true` (Light C2) if the key is absent or equals `1`, and `false` (Dark C3) if `0`.
#[cfg(windows)]
pub fn system_prefers_light_theme() -> bool {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
    else {
        return true;
    };
    let val: u32 = key.get_value("AppsUseLightTheme").unwrap_or(1);
    val != 0
}

#[cfg(not(windows))]
pub fn system_prefers_light_theme() -> bool {
    true
}

/// Convenience converter from `0xRRGGBB` to GPUI `Rgba`.
#[inline]
pub fn c_rgb(hex: u32) -> Rgba {
    rgb(hex)
}

/// Convenience converter from `0xRRGGBBAA` to GPUI `Rgba`.
#[inline]
pub fn c_rgba(hex: u32) -> Rgba {
    rgba(hex)
}

/// Convenience converter from `0xRRGGBB` to GPUI `Hsla`.
#[inline]
pub fn c_hsla(hex: u32) -> Hsla {
    rgb(hex).into()
}

/// Layout constants for Mode A (Tray Quick HUD) and Mode B (Wide Bento Main Console).
pub mod layout {
    pub const HUD_WIDTH: f32 = 376.0;
    pub const HUD_HEIGHT: f32 = 486.0;

    pub const CONSOLE_WIDTH: f32 = 1040.0;
    pub const CONSOLE_HEIGHT: f32 = 768.0;
    pub const CONSOLE_MIN_WIDTH: f32 = 760.0;
    pub const CONSOLE_MIN_HEIGHT: f32 = 440.0;

    pub const SIDEBAR_WIDTH: f32 = 192.0;
    pub const TOPBAR_HEIGHT: f32 = 46.0;
    pub const BENTO_GAP: f32 = 12.0;
    pub const RADIUS_FRAME: f32 = 16.0;
    pub const RADIUS_BENTO: f32 = 14.0;
    pub const RADIUS_INSET: f32 = 11.0;
    pub const RADIUS_CONTROL: f32 = 9.0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c2_light_tokens_match_locked_visual_spec() {
        const { assert!(!LIGHT_C2.is_dark) };
        assert_eq!(LIGHT_C2.frame_bg, 0xEEF1F6);
        assert_eq!(LIGHT_C2.frame_border, 0xD8E0EA);
        assert_eq!(LIGHT_C2.card_bg, 0xFFFFFF);
        assert_eq!(LIGHT_C2.card_border, 0xE2E8F0);
        assert_eq!(LIGHT_C2.inset_bg, 0xF8FAFC);
        assert_eq!(LIGHT_C2.text_primary, 0x0F172A);
        assert_eq!(LIGHT_C2.text_muted, 0x64748B);
        assert_eq!(LIGHT_C2.sidebar_active_bg, 0xE8F1FD);
        assert_eq!(LIGHT_C2.sidebar_active_text, 0x0066CC);
        assert_eq!(LIGHT_C2.sidebar_active_border, 0xBFDBFE);
        assert_eq!(LIGHT_C2.primary_btn_bg, 0x0066CC);
        assert_eq!(LIGHT_C2.primary_btn_text, 0xFFFFFF);
        assert_eq!(LIGHT_C2.cc_pill_bg, 0xE2E8F0);
        assert_eq!(LIGHT_C2.cc_pill_text, 0x334155);
        assert_eq!(LIGHT_C2.hero_healthy.bg, 0xF3FDF7FF);
        assert_eq!(LIGHT_C2.hero_healthy.border, 0xBBF7D0FF);
        assert_eq!(LIGHT_C2.hero_healthy.pill_bg, 0xDCFCE7FF);
        assert_eq!(LIGHT_C2.hero_healthy.pill_text, 0x15803D);
        assert_eq!(LIGHT_C2.hero_healthy.ring, 0x16A34AFF);
        assert_eq!(LIGHT_C2.hero_tripped.bg, 0xFEF2F2FF);
        assert_eq!(LIGHT_C2.hero_tripped.border, 0xFCA5A5FF);
        assert_eq!(LIGHT_C2.hero_tripped.title, 0x991B1B);
        assert_eq!(LIGHT_C2.hero_disarmed.bg, 0xFFFBEBFF);
        assert_eq!(LIGHT_C2.hero_disarmed.border, 0xFCD34DFF);
        assert_eq!(LIGHT_C2.hero_disarmed.title, 0x92400E);
        assert_eq!(LIGHT_C2.timeline.pass, 0x16A34A);
        assert_eq!(LIGHT_C2.timeline.warn, 0xF59E0B);
        assert_eq!(LIGHT_C2.timeline.fail, 0xEF4444);
    }

    #[test]
    fn c3_dark_tokens_match_locked_visual_spec() {
        const { assert!(DARK_C3.is_dark) };
        assert_eq!(DARK_C3.frame_bg, 0x0E1117);
        assert_eq!(DARK_C3.frame_border, 0x242B3A);
        assert_eq!(DARK_C3.card_bg, 0x161A24);
        assert_eq!(DARK_C3.card_border, 0x252D3D);
        assert_eq!(DARK_C3.inset_bg, 0x10141D);
        assert_eq!(DARK_C3.inset_border, 0x202736);
        assert_eq!(DARK_C3.text_primary, 0xF1F5F9);
        assert_eq!(DARK_C3.text_muted, 0x94A3B8);
        assert_eq!(DARK_C3.sidebar_active_bg, 0x21293A);
        assert_eq!(DARK_C3.sidebar_active_text, 0x34D399);
        assert_eq!(DARK_C3.sidebar_active_border, 0x2F3B52);
        assert_eq!(DARK_C3.switcher_track_bg, 0x1D2433);
        assert_eq!(DARK_C3.switcher_active_bg, 0x2A3448);
        assert_eq!(DARK_C3.capsule_active_bg, 0x242C3E);
        assert_eq!(DARK_C3.primary_btn_bg, 0x10B981);
        assert_eq!(DARK_C3.primary_btn_text, 0x052E16);
        assert_eq!(DARK_C3.link_text, 0x38BDF8);
        assert_eq!(DARK_C3.cc_pill_bg, 0x252D3D);
        assert_eq!(DARK_C3.cc_pill_text, 0xCBD5E1);
        assert_eq!(DARK_C3.hero_healthy.bg, 0x0E2E24FF);
        assert_eq!(DARK_C3.hero_healthy.border, 0x34D39966);
        assert_eq!(DARK_C3.hero_healthy.pill_bg, 0x10B98138);
        assert_eq!(DARK_C3.hero_healthy.pill_text, 0x6EE7B7);
        assert_eq!(DARK_C3.hero_healthy.ring, 0x34D3998C);
        assert_eq!(DARK_C3.hero_tripped.bg, 0x2D1219FF);
        assert_eq!(DARK_C3.hero_tripped.border, 0xF8717173);
        assert_eq!(DARK_C3.hero_disarmed.bg, 0x2B200EFF);
        assert_eq!(DARK_C3.hero_disarmed.border, 0xFBBF246B);
        assert_eq!(DARK_C3.timeline.pass, 0x10B981);
        assert_eq!(DARK_C3.timeline.warn, 0xFBBF24);
        assert_eq!(DARK_C3.timeline.fail, 0xF87171);
    }

    #[test]
    fn resolve_palette_respects_auto_preference() {
        assert_eq!(resolve_palette(ThemeMode::Light, false).name, LIGHT_C2.name);
        assert_eq!(resolve_palette(ThemeMode::Dark, true).name, DARK_C3.name);
        assert_eq!(resolve_palette(ThemeMode::Auto, true).name, LIGHT_C2.name);
        assert_eq!(resolve_palette(ThemeMode::Auto, false).name, DARK_C3.name);
    }
}
