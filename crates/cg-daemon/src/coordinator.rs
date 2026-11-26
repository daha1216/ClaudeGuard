//! O(1) snapshot store and single-writer mutation coordinator queue.
//!
//! - [`PipeRequest::GetSnapshot`] reads [`SnapshotStore`] (`Arc<RwLock<GuardSnapshot>>`)
//!   in O(1) memory with ZERO syscalls, process scans, or queue blocking.
//! - All mutating/query IPC requests, background monitor ticks, async probe completions,
//!   and periodic telemetry updates flow through one dedicated single-writer coordinator thread.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use cg_core::CheckPurpose;

use crate::protocol::{
    AccessEvidence, AgentRuntimeStatus, AntigravityProxyState, AntigravityProxyStatus,
    DefenseSelfCheck, EnvCheck, ErrorCode, FeishuStatus, GuardSnapshot, LeakReport,
    LeakShieldStatus, MihomoStatus, OperationReceipt, PipeRequest, PipeResponse, ProbeResult,
    UpdateSummary,
};

const QUEUE_CAPACITY: usize = 256;

/// Thread-safe O(1) snapshot container backed by `Arc<RwLock<GuardSnapshot>>`.
#[derive(Clone, Debug)]
pub struct SnapshotStore {
    inner: Arc<RwLock<GuardSnapshot>>,
}

impl SnapshotStore {
    /// Creates a new store initialized with `initial`.
    pub fn new(initial: GuardSnapshot) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Reads the current snapshot in O(1) with zero syscalls or process scans.
    pub fn read(&self) -> GuardSnapshot {
        match self.inner.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Atomically replaces the stored snapshot.
    pub fn replace(&self, next: GuardSnapshot) {
        match self.inner.write() {
            Ok(mut guard) => *guard = next,
            Err(mut poisoned) => **poisoned.get_mut() = next,
        }
    }

    /// Mutates the snapshot under the write lock.
    pub fn update(&self, f: impl FnOnce(&mut GuardSnapshot)) {
        match self.inner.write() {
            Ok(mut guard) => f(&mut guard),
            Err(mut poisoned) => f(poisoned.get_mut()),
        }
    }
}

/// Control signal returned by [`CoordinatorActor::on_event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorControl {
    Continue,
    Stop,
}

/// Telemetry bundle computed off-thread and published into [`GuardEngine`].
#[derive(Clone, Debug)]
pub struct TelemetryBundle {
    pub cfg_rev: u64,
    pub runtime_epoch: u64,
    pub agents: Vec<AgentRuntimeStatus>,
    pub leak: LeakReport,
    pub leak_shield: LeakShieldStatus,
    pub mihomo: MihomoStatus,
    pub env: EnvCheck,
    pub antigravity_proxy: AntigravityProxyStatus,
    pub self_check: DefenseSelfCheck,
    pub updates: Option<UpdateSummary>,
    pub now_secs: u64,
}

/// Events serialized by the single-writer coordinator thread.
pub enum CoordinatorEvent {
    Pipe {
        req: PipeRequest,
        reply: SyncSender<PipeResponse>,
    },
    Tick,
    SystemResumed,
    RoundFinished {
        cfg_rev: u64,
        runtime_epoch: u64,
        purpose: CheckPurpose,
        access: AccessEvidence,
        probes: Vec<(String, ProbeResult)>,
        now_secs: u64,
    },
    SingleTargetProbed {
        cfg_rev: u64,
        runtime_epoch: u64,
        target_id: String,
        access: AccessEvidence,
        probe: ProbeResult,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    FeishuTestFinished {
        result: Result<FeishuStatus, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    AntigravityRepairFinished {
        result: Result<String, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    /// Background re-injection of `version.dll` after Antigravity overwrote it (no pipe reply).
    AntigravityAutoRepairFinished {
        result: Result<String, String>,
        now_secs: u64,
        trigger_state: AntigravityProxyState,
    },
    MihomoSwitchFinished {
        cfg_rev: u64,
        runtime_epoch: u64,
        result: Result<String, String>,
        mihomo: MihomoStatus,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    Telemetry(Box<TelemetryBundle>),
    UpdatesChecked {
        summary: Box<UpdateSummary>,
        component: Option<String>,
        now_secs: u64,
        reply: Option<SyncSender<PipeResponse>>,
    },
    BeginStopping {
        reply: SyncSender<Result<OperationReceipt, String>>,
    },
    Shutdown,
}

/// Context passed to [`CoordinatorActor::on_event`].
pub struct CoordinatorContext<'a> {
    pub snapshot: &'a SnapshotStore,
    pub event_tx: &'a SyncSender<CoordinatorEvent>,
}

/// Stateful single-writer actor owned exclusively by the coordinator thread.
pub trait CoordinatorActor: Send + 'static {
    fn on_event(&mut self, event: CoordinatorEvent, ctx: &CoordinatorContext<'_>) -> ActorControl;
}

/// Cloneable handle to submit mutations/events or read O(1) [`GuardSnapshot`]s.
#[derive(Clone)]
pub struct CoordinatorHandle {
    snapshot: SnapshotStore,
    tx: SyncSender<CoordinatorEvent>,
    stopped: Arc<AtomicBool>,
    worker: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl CoordinatorHandle {
    /// Returns the latest committed [`GuardSnapshot`] in O(1) with zero syscalls or queue wait.
    pub fn snapshot(&self) -> GuardSnapshot {
        self.snapshot.read()
    }

    /// Updates the published snapshot directly (mainly for tests).
    pub fn update_snapshot(&self, f: impl FnOnce(&mut GuardSnapshot)) {
        self.snapshot.update(f);
    }

    /// Replaces the published snapshot atomically.
    pub fn replace_snapshot(&self, next: GuardSnapshot) {
        self.snapshot.replace(next);
    }

    /// Returns a clone of the coordinator event sender for background workers.
    pub fn event_sender(&self) -> SyncSender<CoordinatorEvent> {
        self.tx.clone()
    }

    /// Dispatches a [`PipeRequest`].
    ///
    /// - `GetSnapshot` reads `Arc<RwLock<GuardSnapshot>>` directly in O(1).
    /// - All other operations are serialized FIFO through the single-writer queue.
    pub fn dispatch(&self, req: PipeRequest) -> PipeResponse {
        if matches!(req, PipeRequest::GetSnapshot) {
            return PipeResponse::Snapshot {
                snapshot: Box::new(self.snapshot.read()),
            };
        }
        if self.stopped.load(Ordering::Acquire) {
            return PipeResponse::Error {
                code: ErrorCode::Busy,
                message: "daemon coordinator is shutting down".into(),
                receipt: None,
            };
        }
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        match self.tx.try_send(CoordinatorEvent::Pipe {
            req,
            reply: reply_tx,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return PipeResponse::Error {
                    code: ErrorCode::Busy,
                    message: "mutation coordinator queue is full".into(),
                    receipt: None,
                };
            }
            Err(TrySendError::Disconnected(_)) => {
                return PipeResponse::Error {
                    code: ErrorCode::Internal,
                    message: "mutation coordinator stopped".into(),
                    receipt: None,
                };
            }
        }
        reply_rx.recv().unwrap_or_else(|_| PipeResponse::Error {
            code: ErrorCode::Internal,
            message: "mutation coordinator exited before replying".into(),
            receipt: None,
        })
    }

    /// Enqueues a background monitor tick (non-blocking; drops cleanly if busy).
    pub fn try_tick(&self) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self.tx.try_send(CoordinatorEvent::Tick);
        }
    }

    /// Notifies the coordinator that Windows resumed from sleep/hibernate (`PBT_APMRESUME*`).
    pub fn notify_system_resumed(&self) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self.tx.try_send(CoordinatorEvent::SystemResumed);
        }
    }

    /// Enqueues off-thread telemetry updates (non-blocking).
    pub fn try_send_telemetry(&self, bundle: TelemetryBundle) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self
                .tx
                .try_send(CoordinatorEvent::Telemetry(Box::new(bundle)));
        }
    }

    /// Drives the engine's `BeginStopping` Flow B cleanup protocol synchronously.
    pub fn begin_stopping_flow_b(&self) -> Result<OperationReceipt, String> {
        if self.stopped.load(Ordering::Acquire) {
            return Err("coordinator already stopped".to_string());
        }
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.tx
            .send(CoordinatorEvent::BeginStopping { reply: reply_tx })
            .map_err(|_| "coordinator channel disconnected".to_string())?;
        reply_rx
            .recv()
            .map_err(|_| "coordinator dropped stop reply".to_string())?
    }

    /// Signals the single-writer thread to stop and joins it (idempotent).
    pub fn shutdown(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            let _ = self.tx.send(CoordinatorEvent::Shutdown);
        }
        if let Ok(mut guard) = self.worker.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Starts the single-writer mutation coordinator thread from a factory receiving its [`CoordinatorEvent`] sender.
pub fn start_coordinator_with<T, F>(factory: F) -> (CoordinatorHandle, T)
where
    F: FnOnce(SyncSender<CoordinatorEvent>) -> (GuardSnapshot, Box<dyn CoordinatorActor>, T),
{
    let (tx, rx) = mpsc::sync_channel::<CoordinatorEvent>(QUEUE_CAPACITY);
    let (initial_snapshot, mut actor, extra) = factory(tx.clone());
    let snapshot = SnapshotStore::new(initial_snapshot);
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_snapshot = snapshot.clone();
    let worker_tx = tx.clone();

    let handle = std::thread::Builder::new()
        .name("cg-mutation-coordinator".to_string())
        .spawn(move || {
            let ctx = CoordinatorContext {
                snapshot: &worker_snapshot,
                event_tx: &worker_tx,
            };
            while let Ok(event) = rx.recv() {
                if matches!(event, CoordinatorEvent::Shutdown) {
                    break;
                }
                if actor.on_event(event, &ctx) == ActorControl::Stop {
                    break;
                }
            }
        })
        .expect("failed to spawn mutation coordinator thread");

    (
        CoordinatorHandle {
            snapshot,
            tx,
            stopped,
            worker: Arc::new(Mutex::new(Some(handle))),
        },
        extra,
    )
}

/// Starts the single-writer mutation coordinator thread and returns its [`CoordinatorHandle`].
pub fn start_coordinator(
    initial_snapshot: GuardSnapshot,
    actor: Box<dyn CoordinatorActor>,
) -> CoordinatorHandle {
    let (handle, ()) = start_coordinator_with(|_| (initial_snapshot, actor, ()));
    handle
}
