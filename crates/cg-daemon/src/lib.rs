//! ClaudeGuard v5 Daemon Crate (`cg-daemon`).
//!
//! Provides:
//! - [`service_win`]: Windows Service (`ClaudeGuardService`) host, SCM installer helpers, and `--console` mode.
//! - [`journal`]: Crash-safe Write-Ahead Recovery Journal (WAL) + [`journal::RecoveryExecutor`] hook.
//! - [`ipc_pipe`]: SDDL-secured Named Pipe IPC server & client (`\\.\pipe\ClaudeGuardV4`).
//! - [`coordinator`]: O(1) `Arc<RwLock<GuardSnapshot>>` reader + `<2ms` `FastHookGate` fast path + single-writer queue.
//! - [`config_store`]: Crash-safe atomic `config.json` read/write with legacy migration and read-back check.
//! - [`egress_ledger`]: DPAPI-HMAC 7-day zero-plaintext-IP geo-velocity ledger.
//! - [`hook_installer`]: Idempotent Claude Code `settings.json` & PowerShell `$PROFILE` hook installer.
//! - [`wsl_bridge`]: WSL2 loopback HMAC-SHA256 bridge with replay protection & distro shim sync.
//! - [`engine_runtime`]: `GuardEngine` + `PlatformDriver` + `ProbeRunner` + v5 orchestration & telemetry.
//! - [`protocol`]: 4-byte LE length-prefixed JSON wire contract aligned with `cg-protocol`.
//! - [`disarm`]: Persistent user disarm intent marker.
//! - [`cli`]: Scriptable `--hook-gate`, `--check`, `--restore`, `--launch-vault`, `--cleanroom-scan`, and `--status` CLI.

pub mod cli;
pub mod config_store;
pub mod coordinator;
pub mod diagnostics;
pub mod disarm;
pub mod egress_ledger;
pub mod engine_runtime;
pub mod feishu;
pub mod hook_installer;
pub mod ipc_pipe;
pub mod journal;
pub mod protocol;
pub mod service_win;
pub mod wsl_bridge;
