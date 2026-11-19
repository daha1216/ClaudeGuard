//! Secure Windows Named Pipe IPC server and client (`\\.\pipe\ClaudeGuardV4`).
//!
//! Security model:
//! - Constructs Win32 `SECURITY_ATTRIBUTES` from SDDL
//!   `D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)` so normal-privilege GUI/CLI users
//!   can connect without UAC while anonymous/network accounts lack access.
//! - Creates pipes with `PIPE_REJECT_REMOTE_CLIENTS` so remote SMB clients are rejected.
//! - Uses 4-byte little-endian `u32` framing (max 4 MiB) + UTF-8 JSON.
//! - Serves `GetSnapshot` in O(1) directly from `Arc<RwLock<SnapshotPayload>>` and
//!   routes mutations through the single-writer [`CoordinatorHandle`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::coordinator::CoordinatorHandle;
use crate::protocol::{
    encode_frame, ErrorCode, FrameError, PipeRequest, PipeResponse, DEFAULT_PIPE_NAME,
    MAX_FRAME_BYTES,
};

/// Default SDDL ACL for `\\.\pipe\ClaudeGuardV4`:
/// - `SY` (LocalSystem): Generic All
/// - `BA` (Builtin Administrators): Generic All
/// - `AU` (Authenticated Users / interactive desktop user): Generic Read + Generic Write
pub const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// Normalizes a pipe name to `\\.\pipe\<name>`.
pub fn normalize_pipe_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_PIPE_NAME.to_string();
    }
    if trimmed.starts_with(r"\\.\pipe\") || trimmed.starts_with(r"\\?\pipe\") {
        return trimmed.to_string();
    }
    let clean = trimmed.trim_start_matches(['\\', '/']);
    format!(r"\\.\pipe\{clean}")
}

/// Resolves the Named Pipe endpoint from explicit override, `CG_PIPE_NAME`, or default.
pub fn resolve_pipe_name(explicit: Option<&str>) -> String {
    if let Some(name) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return normalize_pipe_name(name);
    }
    if let Ok(env_name) = std::env::var("CG_PIPE_NAME") {
        let trimmed = env_name.trim();
        if !trimmed.is_empty() {
            return normalize_pipe_name(trimmed);
        }
    }
    DEFAULT_PIPE_NAME.to_string()
}

/// Named Pipe IPC transport errors.
#[derive(Debug)]
pub enum PipeError {
    NotFound(String),
    AccessDenied(String),
    BusyTimeout(String),
    Disconnected,
    ShuttingDown,
    Frame(FrameError),
    Win32 { code: u32, context: String },
    UnsupportedPlatform,
}

impl PipeError {
    /// Returns true if the pipe does not currently exist (service offline).
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// Returns true if access to the pipe was denied by its ACL.
    pub fn is_access_denied(&self) -> bool {
        matches!(self, Self::AccessDenied(_))
    }
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "pipe not found: {msg}"),
            Self::AccessDenied(msg) => write!(f, "pipe access denied: {msg}"),
            Self::BusyTimeout(msg) => write!(f, "pipe busy timeout: {msg}"),
            Self::Disconnected => write!(f, "pipe disconnected"),
            Self::ShuttingDown => write!(f, "pipe server shutting down"),
            Self::Frame(err) => write!(f, "{err}"),
            Self::Win32 { code, context } => write!(f, "{context} (win32 error {code})"),
            Self::UnsupportedPlatform => write!(f, "Windows Named Pipes require Windows"),
        }
    }
}

impl std::error::Error for PipeError {}

impl From<FrameError> for PipeError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::mpsc;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
        ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
        ERROR_PIPE_NOT_CONNECTED, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE, TRUE, WAIT_OBJECT_0, WIN32_ERROR,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, INFINITE,
    };
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn map_win32_err(err: &windows::core::Error, context: &str) -> PipeError {
        let code = err.code().0 as u32 & 0xFFFF;
        if code == ERROR_FILE_NOT_FOUND.0 {
            PipeError::NotFound(format!("{context}: {err}"))
        } else if code == ERROR_ACCESS_DENIED.0 {
            PipeError::AccessDenied(format!("{context}: {err}"))
        } else if code == ERROR_BROKEN_PIPE.0
            || code == ERROR_NO_DATA.0
            || code == ERROR_PIPE_NOT_CONNECTED.0
        {
            PipeError::Disconnected
        } else {
            PipeError::Win32 {
                code,
                context: format!("{context}: {err}"),
            }
        }
    }

    fn win32_code(err: &windows::core::Error) -> WIN32_ERROR {
        WIN32_ERROR(err.code().0 as u32 & 0xFFFF)
    }

    /// RAII wrapper for Win32 `SECURITY_ATTRIBUTES` + `PSECURITY_DESCRIPTOR` allocated from SDDL.
    pub struct SecurityDescriptorGuard {
        sd: PSECURITY_DESCRIPTOR,
        attrs: SECURITY_ATTRIBUTES,
    }

    impl SecurityDescriptorGuard {
        /// Returns a reference to the Win32 `SECURITY_ATTRIBUTES`.
        pub fn as_security_attributes(&self) -> &SECURITY_ATTRIBUTES {
            &self.attrs
        }

        /// Returns whether the underlying security descriptor pointer is non-null.
        pub fn is_valid(&self) -> bool {
            !self.sd.0.is_null() && !self.attrs.lpSecurityDescriptor.is_null()
        }
    }

    impl Drop for SecurityDescriptorGuard {
        fn drop(&mut self) {
            if !self.sd.0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.sd.0));
                }
                self.sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
            }
        }
    }

    /// Parses an SDDL string into Win32 `SECURITY_ATTRIBUTES` via
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    pub fn build_pipe_security_attributes(
        sddl: &str,
    ) -> Result<SecurityDescriptorGuard, PipeError> {
        let wide = to_wide_null(sddl);
        let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .map_err(|e| {
                map_win32_err(&e, "ConvertStringSecurityDescriptorToSecurityDescriptorW")
            })?;
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: FALSE,
        };
        Ok(SecurityDescriptorGuard { sd, attrs })
    }

    struct OwnedHandle(HANDLE);

    unsafe impl Send for OwnedHandle {}

    impl OwnedHandle {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct SharedEvent(HANDLE);

    unsafe impl Send for SharedEvent {}
    unsafe impl Sync for SharedEvent {}

    impl SharedEvent {
        fn new_manual_reset() -> Result<Self, PipeError> {
            let handle = unsafe { CreateEventW(None, TRUE, FALSE, None) }
                .map_err(|e| map_win32_err(&e, "CreateEventW"))?;
            Ok(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0
        }

        fn signal(&self) {
            unsafe {
                let _ = SetEvent(self.0);
            }
        }
    }

    impl Drop for SharedEvent {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn create_pipe_instance(
        pipe_wide: &[u16],
        sd_guard: &SecurityDescriptorGuard,
        first_instance: bool,
    ) -> Result<OwnedHandle, PipeError> {
        let mut open_mode: FILE_FLAGS_AND_ATTRIBUTES = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first_instance {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_wide.as_ptr()),
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                65_536,
                65_536,
                5_000,
                Some(sd_guard.as_security_attributes()),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_invalid() {
            let err = windows::core::Error::from_win32();
            return Err(map_win32_err(&err, "CreateNamedPipeW"));
        }
        Ok(OwnedHandle(handle))
    }

    fn connect_pipe_overlapped(
        pipe: HANDLE,
        io_event: HANDLE,
        shutdown_event: HANDLE,
    ) -> Result<(), PipeError> {
        unsafe {
            let _ = ResetEvent(io_event);
        }
        let mut overlapped = OVERLAPPED {
            hEvent: io_event,
            ..Default::default()
        };
        let res = unsafe { ConnectNamedPipe(pipe, Some(&mut overlapped)) };
        match res {
            Ok(()) => Ok(()),
            Err(e) if win32_code(&e) == ERROR_PIPE_CONNECTED => Ok(()),
            Err(e) if win32_code(&e) == ERROR_IO_PENDING => {
                let handles = [io_event, shutdown_event];
                let wait = unsafe { WaitForMultipleObjects(&handles, FALSE, INFINITE) };
                if wait == WAIT_OBJECT_0 {
                    let mut dummy = 0u32;
                    unsafe { GetOverlappedResult(pipe, &overlapped, &mut dummy, FALSE) }
                        .map_err(|err| map_win32_err(&err, "GetOverlappedResult(connect)"))?;
                    Ok(())
                } else {
                    unsafe {
                        let _ = CancelIoEx(pipe, Some(&overlapped));
                        let mut dummy = 0u32;
                        let _ = GetOverlappedResult(pipe, &overlapped, &mut dummy, TRUE);
                    }
                    Err(PipeError::ShuttingDown)
                }
            }
            Err(e) => Err(map_win32_err(&e, "ConnectNamedPipe")),
        }
    }

    fn read_exact_overlapped(
        pipe: HANDLE,
        io_event: HANDLE,
        shutdown_event: HANDLE,
        mut dst: &mut [u8],
    ) -> Result<(), PipeError> {
        while !dst.is_empty() {
            unsafe {
                let _ = ResetEvent(io_event);
            }
            let mut overlapped = OVERLAPPED {
                hEvent: io_event,
                ..Default::default()
            };
            let res = unsafe { ReadFile(pipe, Some(dst), None, Some(&mut overlapped)) };
            let transferred = match res {
                Ok(()) => {
                    let mut n = 0u32;
                    unsafe { GetOverlappedResult(pipe, &overlapped, &mut n, FALSE) }
                        .map_err(|e| map_win32_err(&e, "GetOverlappedResult(read)"))?;
                    n as usize
                }
                Err(e) if win32_code(&e) == ERROR_IO_PENDING => {
                    let handles = [io_event, shutdown_event];
                    let wait = unsafe { WaitForMultipleObjects(&handles, FALSE, INFINITE) };
                    if wait == WAIT_OBJECT_0 {
                        let mut n = 0u32;
                        unsafe { GetOverlappedResult(pipe, &overlapped, &mut n, FALSE) }
                            .map_err(|err| map_win32_err(&err, "GetOverlappedResult(read)"))?;
                        n as usize
                    } else {
                        unsafe {
                            let _ = CancelIoEx(pipe, Some(&overlapped));
                            let mut n = 0u32;
                            let _ = GetOverlappedResult(pipe, &overlapped, &mut n, TRUE);
                        }
                        return Err(PipeError::ShuttingDown);
                    }
                }
                Err(e) => return Err(map_win32_err(&e, "ReadFile")),
            };
            if transferred == 0 {
                return Err(PipeError::Disconnected);
            }
            dst = &mut dst[transferred..];
        }
        Ok(())
    }

    fn write_all_overlapped(
        pipe: HANDLE,
        io_event: HANDLE,
        shutdown_event: HANDLE,
        mut src: &[u8],
    ) -> Result<(), PipeError> {
        while !src.is_empty() {
            unsafe {
                let _ = ResetEvent(io_event);
            }
            let mut overlapped = OVERLAPPED {
                hEvent: io_event,
                ..Default::default()
            };
            let res = unsafe { WriteFile(pipe, Some(src), None, Some(&mut overlapped)) };
            let transferred = match res {
                Ok(()) => {
                    let mut n = 0u32;
                    unsafe { GetOverlappedResult(pipe, &overlapped, &mut n, FALSE) }
                        .map_err(|e| map_win32_err(&e, "GetOverlappedResult(write)"))?;
                    n as usize
                }
                Err(e) if win32_code(&e) == ERROR_IO_PENDING => {
                    let handles = [io_event, shutdown_event];
                    let wait = unsafe { WaitForMultipleObjects(&handles, FALSE, INFINITE) };
                    if wait == WAIT_OBJECT_0 {
                        let mut n = 0u32;
                        unsafe { GetOverlappedResult(pipe, &overlapped, &mut n, FALSE) }
                            .map_err(|err| map_win32_err(&err, "GetOverlappedResult(write)"))?;
                        n as usize
                    } else {
                        unsafe {
                            let _ = CancelIoEx(pipe, Some(&overlapped));
                            let mut n = 0u32;
                            let _ = GetOverlappedResult(pipe, &overlapped, &mut n, TRUE);
                        }
                        return Err(PipeError::ShuttingDown);
                    }
                }
                Err(e) => return Err(map_win32_err(&e, "WriteFile")),
            };
            if transferred == 0 {
                return Err(PipeError::Disconnected);
            }
            src = &src[transferred..];
        }
        Ok(())
    }

    fn validate_len(len: usize) -> Result<(), PipeError> {
        if len == 0 {
            return Err(PipeError::Frame(FrameError::ZeroLength));
        }
        if len > MAX_FRAME_BYTES {
            return Err(PipeError::Frame(FrameError::TooLarge {
                len,
                max: MAX_FRAME_BYTES,
            }));
        }
        Ok(())
    }

    fn read_pipe_frame_overlapped(
        pipe: HANDLE,
        io_event: HANDLE,
        shutdown_event: HANDLE,
    ) -> Result<Vec<u8>, PipeError> {
        let mut header = [0u8; 4];
        read_exact_overlapped(pipe, io_event, shutdown_event, &mut header)?;
        let len = u32::from_le_bytes(header) as usize;
        validate_len(len)?;
        let mut payload = vec![0u8; len];
        read_exact_overlapped(pipe, io_event, shutdown_event, &mut payload)?;
        Ok(payload)
    }

    fn serve_client_connection(
        pipe: OwnedHandle,
        shutdown_event: Arc<SharedEvent>,
        coordinator: CoordinatorHandle,
    ) {
        let Ok(io_event) = SharedEvent::new_manual_reset() else {
            unsafe {
                let _ = DisconnectNamedPipe(pipe.raw());
            }
            return;
        };

        loop {
            if shutdown_event.raw().is_invalid() {
                break;
            }
            let payload = match read_pipe_frame_overlapped(
                pipe.raw(),
                io_event.raw(),
                shutdown_event.raw(),
            ) {
                Ok(bytes) => bytes,
                Err(_) => break,
            };

            let response = match serde_json::from_slice::<PipeRequest>(&payload) {
                Ok(req) => coordinator.dispatch(req),
                Err(err) => PipeResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("invalid request JSON: {err}"),
                    receipt: None,
                },
            };

            let encoded = match encode_frame(&response) {
                Ok(bytes) => bytes,
                Err(err) => {
                    let fallback = PipeResponse::Error {
                        code: ErrorCode::Internal,
                        message: err.to_string(),
                        receipt: None,
                    };
                    match encode_frame(&fallback) {
                        Ok(b) => b,
                        Err(_) => break,
                    }
                }
            };

            if write_all_overlapped(pipe.raw(), io_event.raw(), shutdown_event.raw(), &encoded)
                .is_err()
            {
                break;
            }
        }

        unsafe {
            let _ = DisconnectNamedPipe(pipe.raw());
        }
    }

    /// Running Windows Named Pipe IPC server.
    pub struct PipeServer {
        pipe_name: String,
        shutdown_event: Arc<SharedEvent>,
        stopped: Arc<AtomicBool>,
        accept_thread: Mutex<Option<JoinHandle<()>>>,
    }

    impl PipeServer {
        /// Starts the Named Pipe server on `pipe_name` using SDDL ACL security.
        ///
        /// Synchronously binds the first pipe instance before returning so callers
        /// can immediately connect without racing pipe creation.
        pub fn start(pipe_name: &str, coordinator: CoordinatorHandle) -> Result<Self, PipeError> {
            let normalized = normalize_pipe_name(pipe_name);
            let shutdown_event = Arc::new(SharedEvent::new_manual_reset()?);
            let stopped = Arc::new(AtomicBool::new(false));
            let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), PipeError>>(1);

            let thread_pipe_name = normalized.clone();
            let thread_shutdown = shutdown_event.clone();
            let thread_stopped = stopped.clone();

            let accept_thread = std::thread::Builder::new()
                .name("cg-pipe-accept".to_string())
                .spawn(move || {
                    let sd_guard = match build_pipe_security_attributes(PIPE_SDDL) {
                        Ok(g) => g,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                            return;
                        }
                    };
                    let pipe_wide = to_wide_null(&thread_pipe_name);
                    let mut current_pipe = match create_pipe_instance(&pipe_wide, &sd_guard, true) {
                        Ok(p) => p,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                            return;
                        }
                    };
                    let connect_event = match SharedEvent::new_manual_reset() {
                        Ok(ev) => ev,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                            return;
                        }
                    };

                    let _ = ready_tx.send(Ok(()));

                    let mut client_workers: Vec<JoinHandle<()>> = Vec::new();
                    loop {
                        if thread_stopped.load(Ordering::Acquire) {
                            break;
                        }

                        match connect_pipe_overlapped(
                            current_pipe.raw(),
                            connect_event.raw(),
                            thread_shutdown.raw(),
                        ) {
                            Ok(()) => {
                                let connected_pipe = current_pipe;
                                let c_coord = coordinator.clone();
                                let c_shutdown = thread_shutdown.clone();
                                let worker = std::thread::Builder::new()
                                    .name("cg-pipe-client".to_string())
                                    .spawn(move || {
                                        serve_client_connection(connected_pipe, c_shutdown, c_coord)
                                    })
                                    .ok();
                                if let Some(w) = worker {
                                    client_workers.push(w);
                                }
                                client_workers.retain(|h| !h.is_finished());

                                if thread_stopped.load(Ordering::Acquire) {
                                    break;
                                }
                                match create_pipe_instance(&pipe_wide, &sd_guard, false) {
                                    Ok(next_pipe) => current_pipe = next_pipe,
                                    Err(_) => break,
                                }
                            }
                            Err(PipeError::ShuttingDown) => break,
                            Err(_) => {
                                if thread_stopped.load(Ordering::Acquire) {
                                    break;
                                }
                                match create_pipe_instance(&pipe_wide, &sd_guard, false) {
                                    Ok(next_pipe) => current_pipe = next_pipe,
                                    Err(_) => break,
                                }
                            }
                        }
                    }

                    for w in client_workers {
                        let _ = w.join();
                    }
                })
                .map_err(|e| PipeError::Win32 {
                    code: 0,
                    context: format!("failed to spawn pipe accept thread: {e}"),
                })?;

            match ready_rx.recv() {
                Ok(Ok(())) => Ok(Self {
                    pipe_name: normalized,
                    shutdown_event,
                    stopped,
                    accept_thread: Mutex::new(Some(accept_thread)),
                }),
                Ok(Err(err)) => {
                    shutdown_event.signal();
                    let _ = accept_thread.join();
                    Err(err)
                }
                Err(_) => {
                    shutdown_event.signal();
                    let _ = accept_thread.join();
                    Err(PipeError::ShuttingDown)
                }
            }
        }

        /// Returns the normalized Named Pipe path.
        pub fn pipe_name(&self) -> &str {
            &self.pipe_name
        }

        /// Signals the server to stop accepting connections and joins all IPC threads.
        pub fn shutdown(&self) {
            if !self.stopped.swap(true, Ordering::AcqRel) {
                self.shutdown_event.signal();
            }
            if let Ok(mut guard) = self.accept_thread.lock() {
                if let Some(handle) = guard.take() {
                    let _ = handle.join();
                }
            }
        }
    }

    impl Drop for PipeServer {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// Synchronous Windows Named Pipe IPC client.
    pub struct PipeClient {
        handle: OwnedHandle,
    }

    impl PipeClient {
        /// Connects to `pipe_name` with bounded `WaitNamedPipeW` retry on busy instances.
        pub fn connect(pipe_name: &str, timeout_ms: u32) -> Result<Self, PipeError> {
            let normalized = normalize_pipe_name(pipe_name);
            let wide = to_wide_null(&normalized);
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_millis(u64::from(timeout_ms));

            loop {
                let res = unsafe {
                    CreateFileW(
                        PCWSTR(wide.as_ptr()),
                        GENERIC_READ.0 | GENERIC_WRITE.0,
                        FILE_SHARE_NONE,
                        None,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        HANDLE::default(),
                    )
                };
                match res {
                    Ok(handle) => {
                        return Ok(Self {
                            handle: OwnedHandle(handle),
                        })
                    }
                    Err(e) if win32_code(&e) == ERROR_PIPE_BUSY => {
                        let remaining = deadline
                            .saturating_duration_since(std::time::Instant::now())
                            .as_millis() as u32;
                        if remaining == 0 {
                            return Err(PipeError::BusyTimeout(format!(
                                "pipe {normalized} remained busy after {timeout_ms}ms"
                            )));
                        }
                        let wait_slice = remaining.clamp(1, 250);
                        let waited = unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), wait_slice) };
                        if !waited.as_bool() {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                    Err(e) => return Err(map_win32_err(&e, &format!("CreateFileW({normalized})"))),
                }
            }
        }

        /// Sends one [`PipeRequest`] and waits for its [`PipeResponse`].
        pub fn call(&mut self, req: &PipeRequest) -> Result<PipeResponse, PipeError> {
            let encoded = encode_frame(req)?;
            self.write_all_sync(&encoded)?;

            let mut header = [0u8; 4];
            self.read_exact_sync(&mut header)?;
            let len = u32::from_le_bytes(header) as usize;
            validate_len(len)?;
            let mut payload = vec![0u8; len];
            self.read_exact_sync(&mut payload)?;
            serde_json::from_slice(&payload)
                .map_err(|e| PipeError::Frame(FrameError::DecodeFailed(e.to_string())))
        }

        fn write_all_sync(&self, mut buf: &[u8]) -> Result<(), PipeError> {
            while !buf.is_empty() {
                let mut written = 0u32;
                unsafe {
                    WriteFile(self.handle.raw(), Some(buf), Some(&mut written), None)
                        .map_err(|e| map_win32_err(&e, "client WriteFile"))?;
                }
                if written == 0 {
                    return Err(PipeError::Disconnected);
                }
                buf = &buf[written as usize..];
            }
            Ok(())
        }

        fn read_exact_sync(&self, mut buf: &mut [u8]) -> Result<(), PipeError> {
            while !buf.is_empty() {
                let mut read = 0u32;
                unsafe {
                    ReadFile(self.handle.raw(), Some(buf), Some(&mut read), None)
                        .map_err(|e| map_win32_err(&e, "client ReadFile"))?;
                }
                if read == 0 {
                    return Err(PipeError::Disconnected);
                }
                buf = &mut buf[read as usize..];
            }
            Ok(())
        }
    }

    /// Opens a short-lived Named Pipe connection, sends `req`, and returns the response.
    pub fn send_request(
        pipe_name: &str,
        req: &PipeRequest,
        timeout_ms: u32,
    ) -> Result<PipeResponse, PipeError> {
        let mut client = PipeClient::connect(pipe_name, timeout_ms)?;
        client.call(req)
    }
}

#[cfg(not(windows))]
mod stub_impl {
    use super::*;

    pub struct SecurityDescriptorGuard;

    impl SecurityDescriptorGuard {
        pub fn is_valid(&self) -> bool {
            false
        }
    }

    pub fn build_pipe_security_attributes(
        _sddl: &str,
    ) -> Result<SecurityDescriptorGuard, PipeError> {
        Err(PipeError::UnsupportedPlatform)
    }

    pub struct PipeServer {
        pipe_name: String,
    }

    impl PipeServer {
        pub fn start(pipe_name: &str, _coordinator: CoordinatorHandle) -> Result<Self, PipeError> {
            let _ = pipe_name;
            Err(PipeError::UnsupportedPlatform)
        }

        pub fn pipe_name(&self) -> &str {
            &self.pipe_name
        }

        pub fn shutdown(&self) {}
    }

    pub struct PipeClient;

    impl PipeClient {
        pub fn connect(_pipe_name: &str, _timeout_ms: u32) -> Result<Self, PipeError> {
            Err(PipeError::UnsupportedPlatform)
        }

        pub fn call(&mut self, _req: &PipeRequest) -> Result<PipeResponse, PipeError> {
            Err(PipeError::UnsupportedPlatform)
        }
    }

    pub fn send_request(
        _pipe_name: &str,
        _req: &PipeRequest,
        _timeout_ms: u32,
    ) -> Result<PipeResponse, PipeError> {
        Err(PipeError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
pub use win_impl::{
    build_pipe_security_attributes, send_request, PipeClient, PipeServer, SecurityDescriptorGuard,
};

#[cfg(not(windows))]
pub use stub_impl::{
    build_pipe_security_attributes, send_request, PipeClient, PipeServer, SecurityDescriptorGuard,
};

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::coordinator::{
        start_coordinator, ActorControl, CoordinatorActor, CoordinatorContext, CoordinatorEvent,
    };
    use crate::protocol::{
        Config, GuardSnapshot, Lifecycle, OperationReceipt, OperationStatus, PolicyPreset,
        ProtectionState, TargetState, TargetStatus,
    };
    use std::sync::atomic::AtomicU64;

    static PIPE_SEQ: AtomicU64 = AtomicU64::new(1);

    fn unique_test_pipe() -> String {
        let n = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\ClaudeGuardV4-test-{}-{n}", std::process::id())
    }

    struct MockPipeActor {
        state: GuardSnapshot,
    }

    impl CoordinatorActor for MockPipeActor {
        fn on_event(
            &mut self,
            event: CoordinatorEvent,
            ctx: &CoordinatorContext<'_>,
        ) -> ActorControl {
            match event {
                CoordinatorEvent::Pipe { req, reply } => {
                    let resp = match req {
                        PipeRequest::SetPolicyPreset { preset } => {
                            self.state.preset = preset;
                            self.state.config.preset = preset;
                            ctx.snapshot.replace(self.state.clone());
                            PipeResponse::Ack {
                                receipt: None,
                                snapshot: Some(Box::new(self.state.clone())),
                            }
                        }
                        PipeRequest::SaveConfig { config } => {
                            self.state.config = config;
                            self.state.cfg_rev += 1;
                            ctx.snapshot.replace(self.state.clone());
                            PipeResponse::Ack {
                                receipt: None,
                                snapshot: Some(Box::new(self.state.clone())),
                            }
                        }
                        PipeRequest::DisarmAndRestoreFlowB { reason } => {
                            self.state.lifecycle = Lifecycle::Disarmed;
                            self.state.protection = ProtectionState::Monitoring;
                            self.state.disarmed_reason = reason.unwrap_or_default();
                            ctx.snapshot.replace(self.state.clone());
                            PipeResponse::Ack {
                                receipt: Some(OperationReceipt::new(
                                    "flowb-test",
                                    OperationStatus::Verified,
                                )),
                                snapshot: Some(Box::new(self.state.clone())),
                            }
                        }
                        other => PipeResponse::Error {
                            code: ErrorCode::IllegalState,
                            message: format!("unhandled test request: {other:?}"),
                            receipt: None,
                        },
                    };
                    let _ = reply.send(resp);
                }
                CoordinatorEvent::Shutdown => return ActorControl::Stop,
                _ => {}
            }
            ActorControl::Continue
        }
    }

    #[test]
    fn sddl_security_attributes_creation_and_invalid_sddl_rejected() {
        let guard = build_pipe_security_attributes(PIPE_SDDL)
            .expect("PIPE_SDDL must produce a valid Windows security descriptor");
        assert!(guard.is_valid());
        assert_eq!(
            guard.as_security_attributes().nLength as usize,
            std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>()
        );
        drop(guard);

        assert!(build_pipe_security_attributes("NOT_VALID_SDDL").is_err());
    }

    #[test]
    fn named_pipe_real_client_server_roundtrip_and_concurrent_clients() {
        let claude_target = Config::default()
            .targets
            .into_iter()
            .find(|t| t.id == "claude")
            .expect("default config has claude target");
        let mut target_status = TargetStatus::from_target(&claude_target, TargetState::Pass);
        target_status.ip = Some("198.51.100.98".into());
        target_status.country = Some("US".into());
        target_status.latency_ms = 25;
        target_status.checked_at = Some(100);
        target_status.reason = "ok".into();

        let initial = GuardSnapshot {
            lifecycle: Lifecycle::Armed,
            protection: ProtectionState::Monitoring,
            targets: vec![target_status],
            ..Default::default()
        };
        let coord = start_coordinator(initial.clone(), Box::new(MockPipeActor { state: initial }));

        let pipe = unique_test_pipe();
        let server = PipeServer::start(&pipe, coord.clone()).expect("start PipeServer");
        assert_eq!(server.pipe_name(), pipe);

        // 1) Persistent client connection performing multiple sequential requests.
        let mut client = PipeClient::connect(&pipe, 3000).expect("connect PipeClient");
        let snap_resp = client.call(&PipeRequest::GetSnapshot).expect("GetSnapshot");
        match snap_resp {
            PipeResponse::Snapshot { snapshot } => {
                assert_eq!(snapshot.lifecycle, Lifecycle::Armed);
                assert!(snapshot.all_enabled_pass());
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let preset_resp = client
            .call(&PipeRequest::SetPolicyPreset {
                preset: PolicyPreset::StrictStaticIp,
            })
            .expect("SetPolicyPreset");
        assert!(matches!(preset_resp, PipeResponse::Ack { .. }));

        // 2) Concurrent clients hitting multi-instance Named Pipe server simultaneously.
        let mut handles = Vec::new();
        for i in 0..6 {
            let p = pipe.clone();
            handles.push(std::thread::spawn(move || {
                let mut c = PipeClient::connect(&p, 3000).expect("concurrent connect");
                let r1 = c
                    .call(&PipeRequest::GetSnapshot)
                    .expect("concurrent snapshot");
                assert!(matches!(r1, PipeResponse::Snapshot { .. }));
                let cfg = Config {
                    interval_secs: 20 + i,
                    ..Default::default()
                };
                let r2 = c
                    .call(&PipeRequest::SaveConfig { config: cfg })
                    .expect("concurrent SaveConfig");
                assert!(matches!(r2, PipeResponse::Ack { .. }));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // 3) Flow B disarm over pipe transitions to Disarmed cleanly.
        let flow_b = send_request(
            &pipe,
            &PipeRequest::DisarmAndRestoreFlowB {
                reason: Some("pipe test".into()),
            },
            3000,
        )
        .expect("Flow B via pipe");
        assert!(matches!(flow_b, PipeResponse::Ack { .. }));

        let final_snap = coord.snapshot();
        assert_eq!(final_snap.lifecycle, Lifecycle::Disarmed);
        assert_eq!(final_snap.preset, PolicyPreset::StrictStaticIp);
        assert_eq!(final_snap.cfg_rev, 6);

        drop(client);
        server.shutdown();
        coord.shutdown();
    }

    #[test]
    fn connecting_to_nonexistent_pipe_reports_not_found() {
        let missing = unique_test_pipe();
        let err = PipeClient::connect(&missing, 200).err().expect("must fail");
        assert!(err.is_not_found(), "expected NotFound, got {err}");
    }
}
