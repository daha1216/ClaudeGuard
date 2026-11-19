//! ClaudeGuard v4 Daemon Crate (`cg-daemon`).
//!
//! Provides:
//! - [`service_win`]: Windows Service (`ClaudeGuardService`) host, SCM installer helpers, and `--console` mode.
//! - [`journal`]: Crash-safe Write-Ahead Recovery Journal (WAL) + [`journal::RecoveryExecutor`] hook.
//! - [`ipc_pipe`]: SDDL-secured Named Pipe IPC server & client (`\\.\pipe\ClaudeGuardV4`).
//! - [`coordinator`]: O(1) `Arc<RwLock<GuardSnapshot>>` reader + single-writer mutation queue.
//! - [`config_store`]: Crash-safe atomic `config.json` read/write with legacy migration and read-back check.
//! - [`engine_runtime`]: Wave-2 `GuardEngine` + `PlatformDriver` + `ProbeRunner` + background monitor wiring.
//! - [`protocol`]: 4-byte LE length-prefixed JSON wire contract aligned with `cg-protocol`.
//! - [`disarm`]: Persistent user disarm intent marker.
//! - [`cli`]: Scriptable `--check`, `--restore`, and `--status` command-line logic.

pub mod cli;
pub mod config_store;
pub mod coordinator;
pub mod disarm;
pub mod engine_runtime;
pub mod ipc_pipe;
pub mod journal;
pub mod protocol;
pub mod service_win;
