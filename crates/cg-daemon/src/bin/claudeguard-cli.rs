//! `claudeguard-cli.exe` binary entrypoint.

use std::sync::Arc;

use cg_daemon::journal::PlatformRecoveryExecutor;

fn main() {
    let code = if std::env::var_os("CG_TEST_NO_OS_FIREWALL").is_some_and(|v| v == "1") {
        cg_daemon::cli::run_from_env(&cg_daemon::journal::NoopRecoveryExecutor)
    } else {
        let driver = Arc::new(cg_platform::default_platform_driver());
        let executor = PlatformRecoveryExecutor::new(driver);
        cg_daemon::cli::run_from_env(&executor)
    };
    std::process::exit(code);
}
