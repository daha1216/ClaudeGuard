//! Embedded monochrome UI SVG icons & high-DPI multi-color brand PNG icons for GPUI.

use gpui::{AssetSource, Div, ObjectFit, Result, SharedString, Svg, div, img, prelude::*, px, rgb, svg};
use std::borrow::Cow;

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

            // Full-color 128x128 brand icons rendered via `gpui::img(...)`
            "icons/brands/claude.png" => Some(include_bytes!("../assets/icons/brands/claude.png")),
            "icons/brands/claude_code.png" => {
                Some(include_bytes!("../assets/icons/brands/claude_code.png"))
            }
            "icons/brands/chatgpt.png" => {
                Some(include_bytes!("../assets/icons/brands/chatgpt.png"))
            }
            "icons/brands/codex_cli.png" => {
                Some(include_bytes!("../assets/icons/brands/codex_cli.png"))
            }
            "icons/brands/antigravity.png" => {
                Some(include_bytes!("../assets/icons/brands/antigravity.png"))
            }
            "icons/brands/antigravity_dark.png" => {
                Some(include_bytes!("../assets/icons/brands/antigravity_dark.png"))
            }
            "icons/brands/antigravity_cn.png" => {
                Some(include_bytes!("../assets/icons/brands/antigravity_cn.png"))
            }
            "icons/brands/antigravity_cn_dark.png" => {
                Some(include_bytes!("../assets/icons/brands/antigravity_cn_dark.png"))
            }
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

/// Maps agent / target / component id to its embedded multi-color brand PNG asset path.
pub fn brand_icon_path(key: &str, is_dark: bool) -> Option<&'static str> {
    match key.to_ascii_lowercase().as_str() {
        "claude" | "claude_desktop" | "claude-desktop" => Some("icons/brands/claude.png"),
        "claude-code" | "claude_code" => Some("icons/brands/claude_code.png"),
        "chatgpt" | "codex_desktop" | "codex-desktop" | "openai" => {
            Some("icons/brands/chatgpt.png")
        }
        "codex" | "codex-cli" | "codex_cli" => Some("icons/brands/codex_cli.png"),
        "antigravity" | "antigravity_ide" | "antigravity-ide" | "antigravity_proxy" => {
            if is_dark {
                Some("icons/brands/antigravity_dark.png")
            } else {
                Some("icons/brands/antigravity.png")
            }
        }
        "antigravity_cn" | "antigravity-cn" | "antigravity-desktop-cn" => {
            if is_dark {
                Some("icons/brands/antigravity_cn_dark.png")
            } else {
                Some("icons/brands/antigravity_cn.png")
            }
        }
        _ => None,
    }
}

/// Renders a rounded multi-color brand icon (`size_px × size_px`) with dark-theme adaptation.
pub fn brand_icon(key: &str, size_px: f32, radius_px: f32, is_dark: bool) -> Div {
    let container = div()
        .flex()
        .items_center()
        .justify_center()
        .flex_shrink_0()
        .w(px(size_px))
        .h(px(size_px))
        .rounded(px(radius_px))
        .overflow_hidden();

    if let Some(path) = brand_icon_path(key, is_dark) {
        container.child(
            img(path)
                .w(px(size_px))
                .h(px(size_px))
                .rounded(px(radius_px))
                .object_fit(ObjectFit::Cover),
        )
    } else {
        container
            .bg(rgb(if is_dark { 0x2A2D36 } else { 0x14171F }))
            .text_size(px((size_px * 0.42).max(9.0)))
            .font_weight(gpui::FontWeight::BOLD)
            .text_color(rgb(0xFFFFFF))
            .child("AI")
    }
}
