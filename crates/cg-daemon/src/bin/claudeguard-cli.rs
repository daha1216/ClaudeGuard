//! `claudeguard-cli.exe` binary entrypoint.

use std::sync::Arc;

use cg_daemon::journal::PlatformRecoveryExecutor;

fn main() {
    let driver = Arc::new(cg_platform::default_platform_driver());
    let executor = PlatformRecoveryExecutor::new(driver);
    let code = cg_daemon::cli::run_from_env(&executor);
    std::process::exit(code);
}
