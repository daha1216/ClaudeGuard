//! Live end-to-end check of the Antigravity proxy "one-click hot repair" path.
//!
//! These tests hit the real `yuaotian/antigravity-proxy` GitHub release, so they are `#[ignore]`d
//! and only run on demand:
//!
//! ```text
//! cargo test -p cg-platform --test live_antigravity_repair -- --ignored --nocapture
//! ```
//!
//! `CG_TEST_PROXY` overrides the proxy address (default `http://127.0.0.1:7890`).

use std::path::{Path, PathBuf};

use cg_platform::antigravity_proxy_win::{
    repair_antigravity_proxy, validate_antigravity_proxy_dll_bytes, AntigravityRepairReport,
};
use cg_platform::probe_http::ProbeRoute;

/// `CG_TEST_DIR` makes the live tests install into a real directory (e.g. the Antigravity install
/// dir) instead of a throw-away temp dir. The target must not be held open by a running client.
fn target_dir(tag: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("CG_TEST_DIR") {
        let dir = PathBuf::from(dir);
        println!("[target] using CG_TEST_DIR={}", dir.display());
        return dir;
    }
    fresh_dir(tag)
}

fn fresh_dir(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "cg-live-repair-{tag}-{}-{:016x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn proxy_route() -> ProbeRoute {
    let addr =
        std::env::var("CG_TEST_PROXY").unwrap_or_else(|_| "http://127.0.0.1:7890".to_string());
    ProbeRoute::Proxy(addr)
}

fn assert_repair_output(dir: &Path, route_label: &str, report: &AntigravityRepairReport) {
    let bytes = std::fs::read(dir.join("version.dll")).expect("version.dll must be written");
    assert!(
        validate_antigravity_proxy_dll_bytes(&bytes),
        "installed version.dll failed the antigravity-proxy signature check"
    );
    assert_eq!(&bytes[..2], b"MZ", "installed payload is not a PE image");
    assert!(
        bytes.len() > 100_000,
        "proxy DLL looks truncated: {} bytes",
        bytes.len()
    );

    let cfg_raw =
        std::fs::read_to_string(dir.join("config.json")).expect("config.json must be written");
    let cfg: serde_json::Value = serde_json::from_str(&cfg_raw).expect("config.json parses");
    assert_eq!(
        cfg["child_injection"], true,
        "child_injection must be enabled"
    );
    assert_eq!(cfg["proxy"]["port"], 7890, "proxy.port must match");

    println!(
        "[{route_label}] dir={} tag={} len={} sha256={} cfg_version={}",
        dir.display(),
        report.release_tag,
        bytes.len(),
        report.sha256_hex,
        cfg["_version"]
    );
}

#[test]
#[ignore = "network: downloads the real antigravity-proxy release through the configured proxy"]
fn live_repair_via_system_proxy_installs_validated_dll() {
    let dir = fresh_dir("proxy");
    let report = repair_antigravity_proxy(&proxy_route(), 7890, Some(&dir))
        .expect("one-click repair must succeed over the system proxy route");
    println!("summary: {}", report.summary);
    assert_repair_output(&dir, "proxy", &report);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "network: the TUN route is Direct by design; meaningful only while TUN captures traffic"]
fn live_repair_via_direct_route_installs_validated_dll() {
    let dir = target_dir("direct");
    let report = repair_antigravity_proxy(&ProbeRoute::Direct, 7890, Some(&dir))
        .expect("one-click repair must succeed when TUN carries the traffic (Direct route)");
    println!("summary: {}", report.summary);
    assert_repair_output(&dir, "direct", &report);
    if std::env::var("CG_TEST_DIR").is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}
