//! Embedded monochrome UI SVG icons & high-DPI transparent brand PNG glyphs for GPUI.

use gpui::{
    AssetSource, Div, ObjectFit, Result, SharedString, Svg, div, img, prelude::*, px, rgb, svg,
};
use std::borrow::Cow;

/// All embedded high-DPI brand PNG asset paths for startup image-cache pre-warming.
pub const PREWARM_BRAND_ASSETS: &[&str] = &[
    "icons/brands/claudeguard.png",
    "icons/brands/claudeguard_dark.png",
    "icons/brands/claude.png",
    "icons/brands/claude_dark.png",
    "icons/brands/claude_code.png",
    "icons/brands/claude_code_dark.png",
    "icons/brands/chatgpt.png",
    "icons/brands/chatgpt_dark.png",
    "icons/brands/codex_cli.png",
    "icons/brands/codex_cli_dark.png",
    "icons/brands/antigravity.png",
    "icons/brands/antigravity_dark.png",
    "icons/brands/antigravity_cn.png",
    "icons/brands/antigravity_cn_dark.png",
];

pub struct EmbeddedAssets;

impl AssetSource for EmbeddedAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        let bytes: Option<&'static [u8]> = match path {
            // Monochrome UI icons (tinted dynamically via `.text_color(rgb(...))`)
            "icons/ui/shield.svg" => Some(include_bytes!("../assets/icons/ui/shield.svg")),
            "icons/ui/shield_alert.svg" => {
                Some(include_bytes!("../assets/icons/ui/shield_alert.svg"))
            }
            "icons/ui/home.svg" => Some(include_bytes!("../assets/icons/ui/home.svg")),
            "icons/ui/globe.svg" => Some(include_bytes!("../assets/icons/ui/globe.svg")),
            "icons/ui/flame.svg" => Some(include_bytes!("../assets/icons/ui/flame.svg")),
            "icons/ui/radar.svg" => Some(include_bytes!("../assets/icons/ui/radar.svg")),
            "icons/ui/clock.svg" => Some(include_bytes!("../assets/icons/ui/clock.svg")),
            "icons/ui/download.svg" => Some(include_bytes!("../assets/icons/ui/download.svg")),
            "icons/ui/bell.svg" => Some(include_bytes!("../assets/icons/ui/bell.svg")),
            "icons/ui/play.svg" => Some(include_bytes!("../assets/icons/ui/play.svg")),
            "icons/ui/lock.svg" => Some(include_bytes!("../assets/icons/ui/lock.svg")),
            "icons/ui/refresh.svg" => Some(include_bytes!("../assets/icons/ui/refresh.svg")),
            "icons/ui/eye.svg" => Some(include_bytes!("../assets/icons/ui/eye.svg")),
            "icons/ui/sun.svg" => Some(include_bytes!("../assets/icons/ui/sun.svg")),
            "icons/ui/moon.svg" => Some(include_bytes!("../assets/icons/ui/moon.svg")),
            "icons/ui/chevrons.svg" => Some(include_bytes!("../assets/icons/ui/chevrons.svg")),
            "icons/ui/check.svg" => Some(include_bytes!("../assets/icons/ui/check.svg")),
            "icons/ui/plus.svg" => Some(include_bytes!("../assets/icons/ui/plus.svg")),
            "icons/ui/search.svg" => Some(include_bytes!("../assets/icons/ui/search.svg")),
            "icons/ui/trash.svg" => Some(include_bytes!("../assets/icons/ui/trash.svg")),
            "icons/ui/puzzle.svg" => Some(include_bytes!("../assets/icons/ui/puzzle.svg")),
            "icons/ui/close.svg" => Some(include_bytes!("../assets/icons/ui/close.svg")),
            "icons/ui/win_min.svg" => Some(include_bytes!("../assets/icons/ui/win_min.svg")),
            "icons/ui/win_max.svg" => Some(include_bytes!("../assets/icons/ui/win_max.svg")),
            "icons/ui/win_restore.svg" => {
                Some(include_bytes!("../assets/icons/ui/win_restore.svg"))
            }
            "icons/ui/ext.svg" => Some(include_bytes!("../assets/icons/ui/ext.svg")),

            // Bespoke ClaudeGuard Sculpted Liquid-Glass Origami Aegis shield brand mark
            "icons/brands/claudeguard.png" => {
                Some(include_bytes!("../assets/icons/brands/claudeguard.png"))
            }
            "icons/brands/claudeguard_dark.png" => Some(include_bytes!(
                "../assets/icons/brands/claudeguard_dark.png"
            )),

            // High-DPI 128x128 transparent brand glyphs rendered inside unified Ceramic Squircle tiles
            "icons/brands/claude.png" => Some(include_bytes!("../assets/icons/brands/claude.png")),
            "icons/brands/claude_dark.png" => {
                Some(include_bytes!("../assets/icons/brands/claude_dark.png"))
            }
            "icons/brands/claude_code.png" => {
                Some(include_bytes!("../assets/icons/brands/claude_code.png"))
            }
            "icons/brands/claude_code_dark.png" => Some(include_bytes!(
                "../assets/icons/brands/claude_code_dark.png"
            )),
            "icons/brands/chatgpt.png" => {
                Some(include_bytes!("../assets/icons/brands/chatgpt.png"))
            }
            "icons/brands/chatgpt_dark.png" => {
                Some(include_bytes!("../assets/icons/brands/chatgpt_dark.png"))
            }
            "icons/brands/codex_cli.png" => {
                Some(include_bytes!("../assets/icons/brands/codex_cli.png"))
            }
            "icons/brands/codex_cli_dark.png" => {
                Some(include_bytes!("../assets/icons/brands/codex_cli_dark.png"))
            }
            "icons/brands/antigravity.png" => {
                Some(include_bytes!("../assets/icons/brands/antigravity.png"))
            }
            "icons/brands/antigravity_dark.png" => Some(include_bytes!(
                "../assets/icons/brands/antigravity_dark.png"
            )),
            "icons/brands/antigravity_cn.png" => {
                Some(include_bytes!("../assets/icons/brands/antigravity_cn.png"))
            }
            "icons/brands/antigravity_cn_dark.png" => Some(include_bytes!(
                "../assets/icons/brands/antigravity_cn_dark.png"
            )),
            _ => None,
        };
        Ok(bytes.map(Cow::Borrowed))
    }

    fn list(&self, _path: &str) -> Result<Vec<SharedString>> {
        Ok(Vec::new())
    }
}

/// Renders a crisp embedded monochrome SVG icon tinted with `color`.
pub fn ui_icon(path: &'static str, size_px: f32, color: u32) -> Svg {
    svg()
        .path(path)
        .size(px(size_px))
        .flex_shrink_0()
        .text_color(rgb(color))
}

/// Renders the bespoke ClaudeGuard Sculpted Liquid-Glass Origami Aegis shield app brand mark.
pub fn brand_mark(size_px: f32, is_dark: bool) -> Div {
    let path = if is_dark {
        "icons/brands/claudeguard_dark.png"
    } else {
        "icons/brands/claudeguard.png"
    };
    div()
        .flex()
        .items_center()
        .justify_center()
        .flex_shrink_0()
        .w(px(size_px))
        .h(px(size_px))
        .child(
            img(path)
                .w(px(size_px))
                .h(px(size_px))
                .object_fit(ObjectFit::Contain),
        )
}

/// Resolves the icon key for an agent runtime row, distinguishing `Codex CLI` (`id="codex", kind="cli"`)
/// from the `Codex / OpenAI` egress probe target (`id="codex"`).
pub fn agent_icon_key<'a>(id: &'a str, kind: &str) -> &'a str {
    if id.eq_ignore_ascii_case("codex") && kind.to_ascii_lowercase().contains("cli") {
        "codex-cli"
    } else {
        id
    }
}

/// Maps agent / target / component id to its embedded transparent brand PNG glyph path.
pub fn brand_icon_path(key: &str, is_dark: bool) -> Option<&'static str> {
    match key.to_ascii_lowercase().as_str() {
        "claude" | "claude_desktop" | "claude-desktop" => Some(if is_dark {
            "icons/brands/claude_dark.png"
        } else {
            "icons/brands/claude.png"
        }),
        "claude-code" | "claude_code" => Some(if is_dark {
            "icons/brands/claude_code_dark.png"
        } else {
            "icons/brands/claude_code.png"
        }),
        "chatgpt" | "codex_desktop" | "codex-desktop" | "openai" | "codex" => Some(if is_dark {
            "icons/brands/chatgpt_dark.png"
        } else {
            "icons/brands/chatgpt.png"
        }),
        "codex-cli" | "codex_cli" => Some(if is_dark {
            "icons/brands/codex_cli_dark.png"
        } else {
            "icons/brands/codex_cli.png"
        }),
        "antigravity" | "antigravity_ide" | "antigravity-ide" | "antigravity_proxy" => {
            Some(if is_dark {
                "icons/brands/antigravity_dark.png"
            } else {
                "icons/brands/antigravity.png"
            })
        }
        "antigravity_cn" | "antigravity-cn" | "antigravity-desktop-cn" => Some(if is_dark {
            "icons/brands/antigravity_cn_dark.png"
        } else {
            "icons/brands/antigravity_cn.png"
        }),
        _ => None,
    }
}

/// Returns `(background_rgb, hairline_border_rgb)` for the unified serene Ceramic Squircle tile.
///
/// Uses one harmonious Porcelain-Mist Ceramic surface in Light mode (`0xF5F6F8` / `0xE6E8ED`)
/// and one Satin Slate Ceramic surface in Dark mode (`0x1D212A` / `0x2C3240`) so brand icons
/// never create competing pastel boxes across the dashboard.
const fn brand_tile_surface(is_dark: bool) -> (u32, u32) {
    if is_dark {
        (0x1D212A, 0x2C3240)
    } else {
        (0xF5F6F8, 0xE6E8ED)
    }
}

/// Distinct Frost Ceramic monogram badge `(glyph, bg_hex, border_hex, text_hex)` for clients
/// without embedded raster PNGs so all 11 managed tools are instantly recognizable at a glance.
pub fn brand_monogram_spec(key: &str, is_dark: bool) -> Option<(&'static str, u32, u32, u32)> {
    match key.trim().to_ascii_lowercase().as_str() {
        "cursor" | "cursor_ide" | "cursor-ide" => Some(if is_dark {
            ("CU", 0x1E2436, 0x364366, 0x9BB5FF)
        } else {
            ("CU", 0xEEF2FF, 0xD5DDFB, 0x3B4FA8)
        }),
        "windsurf" | "windsurf_ide" | "windsurf-ide" => Some(if is_dark {
            ("WS", 0x182B2F, 0x2A4E55, 0x7CE2EC)
        } else {
            ("WS", 0xECFAFC, 0xCBECEF, 0x166B75)
        }),
        "zed" | "zed_ide" | "zed-ide" => Some(if is_dark {
            ("Z", 0x2B241A, 0x4E3F2B, 0xF4C57A)
        } else {
            ("Z", 0xFDF6EC, 0xF0DFC2, 0x8F5B14)
        }),
        "trae" | "trae_ide" | "trae-ide" => Some(if is_dark {
            ("TR", 0x192B24, 0x2C4E40, 0x7FE3B4)
        } else {
            ("TR", 0xECFBF3, 0xCBEFDB, 0x1B6E4A)
        }),
        "gemini" | "gemini_cli" | "gemini-cli" => Some(if is_dark {
            ("GM", 0x241F36, 0x413663, 0xC2A8FF)
        } else {
            ("GM", 0xF3EFFD, 0xDDD2FA, 0x5A3EA6)
        }),
        "aider" | "aider_cli" | "aider-cli" => Some(if is_dark {
            ("AD", 0x2E2022, 0x54383C, 0xF59FA8)
        } else {
            ("AD", 0xFDF0F2, 0xF3D2D7, 0x993342)
        }),
        _ => None,
    }
}

/// Renders a unified Ceramic Squircle brand icon (`size_px × size_px`) at fixed crisp dimensions
/// (avoiding layout-time pixel stepping during card unfolds).
pub fn brand_icon_scaled(
    key: &str,
    size_px: f32,
    radius_px: f32,
    is_dark: bool,
    _icon_scale: f32,
) -> Div {
    let normalized = key.to_ascii_lowercase();
    let tile_radius = (size_px * 0.27).round().max(radius_px.min(size_px * 0.3));
    let (bg_hex, border_hex) = brand_tile_surface(is_dark);

    let mut container = div()
        .relative()
        .flex()
        .items_center()
        .justify_center()
        .flex_shrink_0()
        .w(px(size_px))
        .h(px(size_px))
        .rounded(px(tile_radius))
        .bg(rgb(bg_hex))
        .border_1()
        .border_color(rgb(border_hex))
        .overflow_hidden();

    if let Some(path) = brand_icon_path(normalized.as_str(), is_dark) {
        let inner_px = (size_px - 2.0).max(8.0);
        container = container.child(
            img(path)
                .w(px(inner_px))
                .h(px(inner_px))
                .object_fit(ObjectFit::Contain),
        );

        if matches!(
            normalized.as_str(),
            "antigravity_cn" | "antigravity-cn" | "antigravity-desktop-cn"
        ) {
            let badge_size = (size_px * 0.44).round().max(10.0);
            let badge_radius = (badge_size * 0.28).round().max(2.5);
            let badge_font = (badge_size * 0.68).max(7.0);
            container = container.child(
                div()
                    .absolute()
                    .right(px(1.0))
                    .bottom(px(1.0))
                    .w(px(badge_size))
                    .h(px(badge_size))
                    .rounded(px(badge_radius))
                    .bg(rgb(if is_dark { 0x6F8BA8 } else { 0x5D7691 }))
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_size(px(badge_font))
                    .line_height(px(badge_size))
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_color(rgb(0xFFFFFF))
                    .child("中"),
            );
        }

        container
    } else if let Some((glyph, mono_bg, mono_border, mono_fg)) =
        brand_monogram_spec(normalized.as_str(), is_dark)
    {
        let font_px = if glyph.len() == 1 {
            (size_px * 0.48).max(10.0)
        } else {
            (size_px * 0.40).max(9.0)
        };
        container
            .bg(rgb(mono_bg))
            .border_color(rgb(mono_border))
            .text_size(px(font_px))
            .font_weight(gpui::FontWeight::BOLD)
            .text_color(rgb(mono_fg))
            .child(glyph)
    } else if normalized == "local" {
        let icon_px = (size_px * 0.58).max(8.0);
        let globe_tint = if is_dark { 0x9BB0C7 } else { 0x5A7088 };
        container.child(ui_icon("icons/ui/globe.svg", icon_px, globe_tint))
    } else {
        container
            .text_size(px((size_px * 0.40).max(9.0)))
            .font_weight(gpui::FontWeight::SEMIBOLD)
            .text_color(rgb(if is_dark { 0xB8C2D1 } else { 0x4E5B6E }))
            .child("AI")
    }
}

/// Renders a unified Ceramic Squircle brand icon (`size_px × size_px`) with Light/Dark adaptation.
pub fn brand_icon(key: &str, size_px: f32, radius_px: f32, is_dark: bool) -> Div {
    brand_icon_scaled(key, size_px, radius_px, is_dark, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prewarm_brand_assets_are_all_embedded_pngs() {
        const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
        let assets = EmbeddedAssets;
        for path in PREWARM_BRAND_ASSETS {
            let bytes = assets
                .load(path)
                .expect("asset load should not error")
                .unwrap_or_else(|| panic!("missing embedded asset: {path}"));
            assert!(
                bytes.starts_with(PNG_MAGIC),
                "asset {path} does not start with PNG header"
            );
        }
    }

    #[test]
    fn brand_icon_path_distinguishes_codex_target_and_codex_cli() {
        assert_eq!(
            brand_icon_path("codex", false),
            Some("icons/brands/chatgpt.png")
        );
        assert_eq!(
            brand_icon_path("codex", true),
            Some("icons/brands/chatgpt_dark.png")
        );
        assert_eq!(
            brand_icon_path("codex-cli", false),
            Some("icons/brands/codex_cli.png")
        );
        assert_eq!(
            brand_icon_path("codex_cli", true),
            Some("icons/brands/codex_cli_dark.png")
        );
        assert_eq!(
            brand_icon_path("claude", false),
            Some("icons/brands/claude.png")
        );
        assert_eq!(
            brand_icon_path("claude", true),
            Some("icons/brands/claude_dark.png")
        );
        assert_eq!(
            brand_icon_path("claude-code", false),
            Some("icons/brands/claude_code.png")
        );
        assert_eq!(
            brand_icon_path("claude_code", true),
            Some("icons/brands/claude_code_dark.png")
        );
        assert_eq!(
            brand_icon_path("antigravity_cn", false),
            Some("icons/brands/antigravity_cn.png")
        );
        assert_eq!(
            brand_icon_path("antigravity_cn", true),
            Some("icons/brands/antigravity_cn_dark.png")
        );
        assert_eq!(brand_icon_path("local", false), None);
        assert_eq!(agent_icon_key("codex", "cli"), "codex-cli");
        assert_eq!(agent_icon_key("codex", "gui"), "codex");
        assert_eq!(agent_icon_key("chatgpt", "gui"), "chatgpt");
        assert_eq!(agent_icon_key("claude-code", "cli"), "claude-code");
    }

    #[test]
    fn ui_svgs_load_cleanly_with_fixed_flame_and_sun() {
        let assets = EmbeddedAssets;
        let flame_bytes = assets
            .load("icons/ui/flame.svg")
            .unwrap()
            .expect("flame.svg embedded");
        let flame = std::str::from_utf8(flame_bytes.as_ref()).unwrap();
        assert!(
            !flame.contains("M12 22s8-4 8-10V5"),
            "flame.svg must not be shield"
        );
        assert!(flame.contains("stroke-width=\"1.8\""));

        let sun_bytes = assets
            .load("icons/ui/sun.svg")
            .unwrap()
            .expect("sun.svg embedded");
        let sun = std::str::from_utf8(sun_bytes.as_ref()).unwrap();
        assert!(sun.contains("m6.34 17.66-1.41 1.41"));
        assert!(sun.contains("m19.07 4.93-1.41 1.41"));
    }

    #[test]
    fn unified_ceramic_brand_tiles_and_scaled_helper_work_across_polarities() {
        assert_eq!(brand_tile_surface(false), (0xF5F6F8, 0xE6E8ED));
        assert_eq!(brand_tile_surface(true), (0x1D212A, 0x2C3240));

        // Verify zero-panic construction for brand, local, and fallback icons across scale extremes
        for key in ["claude", "codex", "antigravity_cn", "local", "unknown"] {
            let _ = brand_icon(key, 24.0, 6.0, false);
            let _ = brand_icon_scaled(key, 24.0, 6.0, false, 0.80);
            let _ = brand_icon_scaled(key, 24.0, 6.0, true, 1.05);
            let _ = brand_icon_scaled(key, 24.0, 6.0, true, 0.10);
        }
    }

    #[test]
    fn v5_brand_monograms_are_distinct_across_six_new_clients() {
        let keys = ["cursor", "windsurf", "zed", "trae", "gemini", "aider"];
        for is_dark in [false, true] {
            let mut seen_glyphs = std::collections::HashSet::new();
            let mut seen_bgs = std::collections::HashSet::new();
            for key in keys {
                let (glyph, bg, border, fg) =
                    brand_monogram_spec(key, is_dark).expect("v5 client monogram");
                assert_ne!(glyph, "AI");
                assert!(
                    seen_glyphs.insert(glyph),
                    "duplicate monogram glyph {glyph}"
                );
                assert!(seen_bgs.insert(bg), "duplicate monogram bg {bg:#x}");
                assert_ne!(bg, border);
                assert_ne!(bg, fg);
                let _ = brand_icon(key, 24.0, 6.0, is_dark);
            }
        }
    }
}
