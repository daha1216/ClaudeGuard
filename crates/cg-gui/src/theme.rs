//! Frost Ceramic theme system: pure neutral ceramic Light + obsidian ceramic Dark.
//!
//! Zero color cast, high-contrast charcoal/white ink accents, semantic status dots/pills,
//! supporting `Light`, `Dark`, and `Auto` (Windows `AppsUseLightTheme`).

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

/// Complete resolved Frost Ceramic color palette (`0xRRGGBB` or `0xRRGGBBAA` for alpha surfaces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThemePalette {
    pub is_dark: bool,
    pub name: &'static str,

    // Outer shell & ceramic surfaces (0xRRGGBB)
    pub frame_bg: u32,
    pub frame_border: u32,
    pub card_bg: u32,
    pub card_border: u32,
    pub inset_bg: u32,
    pub inset_border: u32,
    pub guide_bg: u32,
    pub line_strong: u32,

    // Typography (0xRRGGBB)
    pub text_primary: u32,
    pub text_secondary: u32,
    pub text_muted: u32,

    // Navigation Dock & active pill (0xRRGGBB)
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

    // Interactive buttons & ink accents (0xRRGGBB)
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
    // Modal / HUD overlay scrim (`0xRRGGBBAA`)
    pub scrim_rgba: u32,
}

/// Frost Ceramic (Light): pure neutral white ceramic with charcoal ink accents and zero rainbow cast.
pub const LIGHT_C2: ThemePalette = ThemePalette {
    is_dark: false,
    name: "Frost Ceramic Light",

    frame_bg: 0xF2F4F7,
    frame_border: 0xDDE1E8,
    card_bg: 0xFFFFFF,
    card_border: 0xE6E9EF,
    inset_bg: 0xF4F5F8,
    inset_border: 0xE6E9EF,
    guide_bg: 0xF8F9FB,
    line_strong: 0xD2D7E0,

    text_primary: 0x111317,
    text_secondary: 0x4B5260,
    text_muted: 0x646D7D,

    sidebar_bg: 0xFFFFFF,
    sidebar_active_bg: 0x14171F,
    sidebar_active_text: 0xFFFFFF,
    sidebar_active_border: 0x14171F,
    sidebar_hover_bg: 0xECEFF4,

    switcher_track_bg: 0xECEFF4,
    switcher_active_bg: 0xFFFFFF,
    switcher_active_text: 0x111317,
    capsule_track_bg: 0xF4F5F8,
    capsule_active_bg: 0xFFFFFF,
    capsule_active_text: 0x111317,

    primary_btn_bg: 0x14171F,
    primary_btn_hover_bg: 0x272C38,
    primary_btn_text: 0xFFFFFF,
    secondary_btn_bg: 0xF4F5F8,
    secondary_btn_border: 0xE2E5EC,
    secondary_btn_text: 0x111317,
    danger_btn_bg: 0xDC2626,
    danger_btn_text: 0xFFFFFF,
    link_text: 0x14171F,

    input_bg: 0xFFFFFF,
    input_border: 0xD2D7E0,
    input_focus_border: 0x14171F,
    input_selection_rgba: 0x14171F26,
    toggle_track_off: 0xCFD4DE,
    toggle_track_on: 0x16A34A,
    toggle_knob: 0xFFFFFF,

    cc_pill_bg: 0xECEFF4,
    cc_pill_text: 0x111317,

    hero_healthy: HeroSurface {
        bg: 0xFFFFFFFF,
        border: 0xE4E7EEFF,
        title: 0x111317,
        subtitle: 0x525866,
        pill_bg: 0x16A34A18,
        pill_text: 0x16A34A,
        ring: 0x16A34AFF,
    },
    hero_tripped: HeroSurface {
        bg: 0xFEF5F5FF,
        border: 0xDC26263D,
        title: 0x111317,
        subtitle: 0x7F1D1D,
        pill_bg: 0xDC262618,
        pill_text: 0xDC2626,
        ring: 0xDC2626FF,
    },
    hero_disarmed: HeroSurface {
        bg: 0xFFFDF5FF,
        border: 0xD9770644,
        title: 0x111317,
        subtitle: 0x78350F,
        pill_bg: 0xD9770618,
        pill_text: 0xD97706,
        ring: 0xD97706FF,
    },

    badge_pass: BadgeSurface {
        bg: 0x16A34A18,
        text: 0x16A34A,
        dot: 0x16A34A,
    },
    badge_fail: BadgeSurface {
        bg: 0xDC262618,
        text: 0xDC2626,
        dot: 0xDC2626,
    },
    badge_warn: BadgeSurface {
        bg: 0xD9770618,
        text: 0xD97706,
        dot: 0xD97706,
    },
    badge_muted: BadgeSurface {
        bg: 0x1113170F,
        text: 0x4B5260,
        dot: 0x646D7D,
    },

    timeline: TimelinePalette {
        pass: 0x16A34A,
        warn: 0xD97706,
        fail: 0xDC2626,
        empty: 0xE2E5EC,
    },

    shadow_rgba: 0x0F172A0B,
    scrim_rgba: 0x0F172A48,
};

/// Frost Ceramic (Dark): crisp neutral dark graphite tiles with high-contrast white ink accents.
pub const DARK_C3: ThemePalette = ThemePalette {
    is_dark: true,
    name: "Frost Ceramic Dark",

    frame_bg: 0x141518,
    frame_border: 0x2B2D35,
    card_bg: 0x1C1D22,
    card_border: 0x2A2C34,
    inset_bg: 0x24262D,
    inset_border: 0x30333D,
    guide_bg: 0x18191E,
    line_strong: 0x3C3F4A,

    text_primary: 0xF3F4F6,
    text_secondary: 0xB4BCC8,
    text_muted: 0x8E98A8,

    sidebar_bg: 0x1E2026,
    sidebar_active_bg: 0xF3F4F6,
    sidebar_active_text: 0x111317,
    sidebar_active_border: 0xF3F4F6,
    sidebar_hover_bg: 0x2B2D36,

    switcher_track_bg: 0x23252C,
    switcher_active_bg: 0x1C1D22,
    switcher_active_text: 0xF3F4F6,
    capsule_track_bg: 0x23252C,
    capsule_active_bg: 0x1C1D22,
    capsule_active_text: 0xF3F4F6,

    primary_btn_bg: 0xF3F4F6,
    primary_btn_hover_bg: 0xE0E3EA,
    primary_btn_text: 0x111317,
    secondary_btn_bg: 0x25272F,
    secondary_btn_border: 0x353844,
    secondary_btn_text: 0xF3F4F6,
    danger_btn_bg: 0xDC2626,
    danger_btn_text: 0xFFFFFF,
    link_text: 0xF3F4F6,

    input_bg: 0x1C1D22,
    input_border: 0x3B3E49,
    input_focus_border: 0xF3F4F6,
    input_selection_rgba: 0xF3F4F633,
    toggle_track_off: 0x3B3E49,
    toggle_track_on: 0x22C55E,
    toggle_knob: 0xFFFFFF,

    cc_pill_bg: 0x2A2C34,
    cc_pill_text: 0xF3F4F6,

    hero_healthy: HeroSurface {
        bg: 0x1C1D22FF,
        border: 0x2D3039FF,
        title: 0xF3F4F6,
        subtitle: 0xB4BCC8,
        pill_bg: 0x22C55E24,
        pill_text: 0x22C55E,
        ring: 0x22C55EFF,
    },
    hero_tripped: HeroSurface {
        bg: 0x281A1DFF,
        border: 0xEF444457,
        title: 0xF3F4F6,
        subtitle: 0xFCA5A5,
        pill_bg: 0xF8717126,
        pill_text: 0xF87171,
        ring: 0xF87171FF,
    },
    hero_disarmed: HeroSurface {
        bg: 0x262016FF,
        border: 0xF59E0B55,
        title: 0xF3F4F6,
        subtitle: 0xFDE68A,
        pill_bg: 0xF59E0B24,
        pill_text: 0xF59E0B,
        ring: 0xF59E0BFF,
    },

    badge_pass: BadgeSurface {
        bg: 0x22C55E24,
        text: 0x22C55E,
        dot: 0x22C55E,
    },
    badge_fail: BadgeSurface {
        bg: 0xF8717124,
        text: 0xF87171,
        dot: 0xF87171,
    },
    badge_warn: BadgeSurface {
        bg: 0xF59E0B24,
        text: 0xF59E0B,
        dot: 0xF59E0B,
    },
    badge_muted: BadgeSurface {
        bg: 0xFFFFFF12,
        text: 0xB4BCC8,
        dot: 0x8E98A8,
    },

    timeline: TimelinePalette {
        pass: 0x22C55E,
        warn: 0xF59E0B,
        fail: 0xF87171,
        empty: 0x2C2F38,
    },

    shadow_rgba: 0x00000044,
    scrim_rgba: 0x00000084,
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

/// Resolves the active [`ThemePalette`] given user preference and Windows light/dark theme.
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

/// Layout constants for Mode A (Tray Quick HUD) and Mode B (Frost Ceramic Main Console).
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
    fn frost_ceramic_light_tokens_match_spec() {
        const { assert!(!LIGHT_C2.is_dark) };
        assert_eq!(LIGHT_C2.frame_bg, 0xF2F4F7);
        assert_eq!(LIGHT_C2.card_bg, 0xFFFFFF);
        assert_eq!(LIGHT_C2.inset_bg, 0xF4F5F8);
        assert_eq!(LIGHT_C2.text_primary, 0x111317);
        assert_eq!(LIGHT_C2.text_secondary, 0x4B5260);
        assert_eq!(LIGHT_C2.text_muted, 0x646D7D);
        assert_eq!(LIGHT_C2.primary_btn_bg, 0x14171F);
        assert_eq!(LIGHT_C2.primary_btn_text, 0xFFFFFF);
        assert_eq!(LIGHT_C2.toggle_track_on, 0x16A34A);
        assert_eq!(LIGHT_C2.timeline.pass, 0x16A34A);
        assert_eq!(LIGHT_C2.timeline.warn, 0xD97706);
        assert_eq!(LIGHT_C2.timeline.fail, 0xDC2626);
    }

    #[test]
    fn frost_ceramic_dark_tokens_match_spec() {
        const { assert!(DARK_C3.is_dark) };
        assert_eq!(DARK_C3.frame_bg, 0x141518);
        assert_eq!(DARK_C3.card_bg, 0x1C1D22);
        assert_eq!(DARK_C3.text_primary, 0xF3F4F6);
        assert_eq!(DARK_C3.text_secondary, 0xB4BCC8);
        assert_eq!(DARK_C3.text_muted, 0x8E98A8);
        assert_eq!(DARK_C3.primary_btn_bg, 0xF3F4F6);
        assert_eq!(DARK_C3.primary_btn_text, 0x111317);
        assert_eq!(DARK_C3.toggle_track_on, 0x22C55E);
        assert_eq!(DARK_C3.timeline.pass, 0x22C55E);
        assert_eq!(DARK_C3.timeline.warn, 0xF59E0B);
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
