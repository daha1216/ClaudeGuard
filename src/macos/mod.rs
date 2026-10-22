//! macOS adapters. Shared v3 target, policy, monitoring and frontend remain upstream.
pub mod autostart;
pub mod credentials;
pub mod monitor_acceptance;
pub mod package;
pub mod ui_acceptance;

pub fn data_dir() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("CG_DATA_DIR") {
        return path.into();
    }
    std::path::PathBuf::from(std::env::var_os("HOME").expect("macOS HOME is required"))
        .join("Library/Application Support/ClaudeGuard")
}

/// AppKit activation state is queried only on the native main thread.
pub fn application_is_active() -> bool {
    objc2::MainThreadMarker::new()
        .is_some_and(|main| objc2_app_kit::NSApplication::sharedApplication(main).isActive())
}
