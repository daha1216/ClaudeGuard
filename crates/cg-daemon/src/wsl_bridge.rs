//! M6: WSL2 Loopback HMAC-SHA256 Gate Bridge (`127.0.0.1:<ephemeral_port>`).
//!
//! Security model:
//! - Binds strictly on loopback (`127.0.0.1:0`) and immediately drops any peer whose IP is
//!   not loopback (zero LAN / Wi-Fi exposure surface).
//! - Generates a fresh per-boot 256-bit CSPRNG hex secret (`BCryptGenRandom`) persisted to
//!   `<user_home>\.claudeguard-wsl-token` with ancestor reparse-point checks and user-only
//!   protected DACL when elevated / Session-0.
//! - Authenticates every request with constant-time HMAC-SHA256 verification, a `<= 60s`
//!   clock skew window, and a bounded 512-entry LRU nonce replay cache.
//! - Detects WSL2 proxy desync (host in `SystemProxy` mode while WSL2 has empty `HTTPS_PROXY`),
//!   otherwise delegates directly to O(1) `CoordinatorHandle::fast_hook_gate`.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use cg_platform::{crypto_win, vault_win};
use cg_protocol::{AccessLevel, HookDecision, PipeResponse, WslBridgeStatus};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::coordinator::CoordinatorHandle;
use crate::egress_ledger::{constant_time_eq, hmac_sha256_hex};
use crate::hook_installer;
use crate::protocol::now_unix_secs;

/// Filename written under `<user_home>` carrying per-boot ephemeral port & 256-bit HMAC secret.
pub const WSL_TOKEN_FILE: &str = ".claudeguard-wsl-token";

/// Allowed timestamp drift window in seconds (`|now - ts| <= 60`).
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Bounded capacity of the LRU nonce replay cache.
pub const NONCE_CACHE_CAPACITY: usize = 512;

/// Maximum incoming single-line JSON request frame bytes.
const MAX_REQUEST_BYTES: usize = 4096;

/// Persisted token file structure read by WSL2 `~/.local/bin/claudeguard-wsl-gate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslTokenFile {
    pub port: u16,
    pub host_wsl_ip: String,
    pub proxy_port: u16,
    pub secret_hex: String,
    pub boot_epoch: u64,
}

/// Incoming single-line JSON request sent by WSL2 clients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslGateRequest {
    pub ts: u64,
    pub nonce: String,
    pub agent: String,
    #[serde(default)]
    pub vault: String,
    #[serde(default)]
    pub hook_event: Option<String>,
    #[serde(default)]
    pub wsl_proxy_env: Option<String>,
    pub hmac: String,
}

/// Compact single-line JSON response returned to WSL2 clients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslGateResponse {
    pub allowed: bool,
    pub decision: HookDecision,
    pub safety_score: u8,
    pub reason: String,
    pub latency_path: String,
}

/// Bounded LRU nonce replay cache preventing HMAC request replay within the clock window.
#[derive(Debug)]
pub struct NonceReplayCache {
    capacity: usize,
    order: VecDeque<String>,
    seen: HashMap<String, u64>,
}

impl NonceReplayCache {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(16);
        Self {
            capacity: cap,
            order: VecDeque::with_capacity(cap),
            seen: HashMap::with_capacity(cap),
        }
    }

    /// Inserts `nonce` if valid & unseen within the replay window; returns `false` on replay.
    pub fn check_and_insert(&mut self, nonce: &str, now_secs: u64) -> bool {
        // Evict expired entries from the front first.
        let expiry_cutoff = now_secs.saturating_sub(MAX_CLOCK_SKEW_SECS.saturating_mul(2));
        while let Some(front) = self.order.front() {
            let expired = self.seen.get(front).is_none_or(|&ts| ts < expiry_cutoff);
            if expired {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            } else {
                break;
            }
        }

        if self.seen.contains_key(nonce) {
            return false;
        }

        while self.order.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }

        let owned = nonce.to_string();
        self.seen.insert(owned.clone(), now_secs);
        self.order.push_back(owned);
        true
    }
}

/// Computes canonical HMAC-SHA256 hex digest for a WSL2 gate request.
///
/// Format:
/// - When `wsl_proxy_env` is `None`: `HMAC-SHA256(secret_hex, "{ts}:{nonce}:{agent}:{vault}")`
/// - When `wsl_proxy_env` is `Some(p)`: `HMAC-SHA256(secret_hex, "{ts}:{nonce}:{agent}:{vault}:{p}")`
pub fn compute_wsl_hmac(
    secret_hex: &str,
    ts: u64,
    nonce: &str,
    agent: &str,
    vault: &str,
    wsl_proxy_env: Option<&str>,
) -> String {
    let payload = match wsl_proxy_env {
        Some(p) if !p.is_empty() => format!("{ts}:{nonce}:{agent}:{vault}:{p}"),
        _ => format!("{ts}:{nonce}:{agent}:{vault}"),
    };
    hmac_sha256_hex(secret_hex.as_bytes(), payload.as_bytes())
}

fn verify_request_hmac(secret_hex: &str, req: &WslGateRequest) -> bool {
    let got = req.hmac.trim().to_ascii_lowercase();
    if got.len() != 64 || !got.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let key = secret_hex.as_bytes();
    let got_bytes = got.as_bytes();

    match req.wsl_proxy_env.as_deref() {
        Some(p) if !p.is_empty() => {
            let colon_msg = format!("{}:{}:{}:{}:{p}", req.ts, req.nonce, req.agent, req.vault);
            let pipe_msg = format!("{}|{}|{}|{}|{p}", req.ts, req.nonce, req.agent, req.vault);
            constant_time_eq(
                hmac_sha256_hex(key, colon_msg.as_bytes()).as_bytes(),
                got_bytes,
            ) || constant_time_eq(
                hmac_sha256_hex(key, pipe_msg.as_bytes()).as_bytes(),
                got_bytes,
            )
        }
        Some("") => {
            let base_colon = format!("{}:{}:{}:{}", req.ts, req.nonce, req.agent, req.vault);
            let full_colon = format!("{}:{}:{}:{}:", req.ts, req.nonce, req.agent, req.vault);
            let full_pipe = format!("{}|{}|{}|{}|", req.ts, req.nonce, req.agent, req.vault);
            constant_time_eq(
                hmac_sha256_hex(key, base_colon.as_bytes()).as_bytes(),
                got_bytes,
            ) || constant_time_eq(
                hmac_sha256_hex(key, full_colon.as_bytes()).as_bytes(),
                got_bytes,
            ) || constant_time_eq(
                hmac_sha256_hex(key, full_pipe.as_bytes()).as_bytes(),
                got_bytes,
            )
        }
        None => {
            let base_colon = format!("{}:{}:{}:{}", req.ts, req.nonce, req.agent, req.vault);
            constant_time_eq(
                hmac_sha256_hex(key, base_colon.as_bytes()).as_bytes(),
                got_bytes,
            )
        }
        Some(_) => false,
    }
}

fn is_valid_nonce(nonce: &str) -> bool {
    let len = nonce.len();
    (8..=128).contains(&len)
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Evaluates a parsed [`WslGateRequest`] against HMAC, clock window, nonce replay cache,
/// WSL2 proxy-desync check, and O(1) `CoordinatorHandle::fast_hook_gate`.
pub fn evaluate_wsl_request(
    req: &WslGateRequest,
    secret_hex: &str,
    replay_cache: &Mutex<NonceReplayCache>,
    coordinator: &CoordinatorHandle,
    now_secs: u64,
) -> WslGateResponse {
    if !is_valid_nonce(&req.nonce) {
        return WslGateResponse {
            allowed: false,
            decision: HookDecision::Block,
            safety_score: 0,
            reason: "WSL2 桥接鉴权失败：nonce 格式非法".into(),
            latency_path: "wsl_auth_reject".into(),
        };
    }

    if now_secs.abs_diff(req.ts) > MAX_CLOCK_SKEW_SECS {
        return WslGateResponse {
            allowed: false,
            decision: HookDecision::Block,
            safety_score: 0,
            reason: format!("WSL2 桥接鉴权失败：时间戳偏差超过 {MAX_CLOCK_SKEW_SECS}s 窗口"),
            latency_path: "wsl_clock_reject".into(),
        };
    }

    if !verify_request_hmac(secret_hex, req) {
        return WslGateResponse {
            allowed: false,
            decision: HookDecision::Block,
            safety_score: 0,
            reason: "WSL2 桥接鉴权失败：HMAC-SHA256 签名无效".into(),
            latency_path: "wsl_hmac_reject".into(),
        };
    }

    let fresh_nonce = replay_cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .check_and_insert(&req.nonce, now_secs);
    if !fresh_nonce {
        return WslGateResponse {
            allowed: false,
            decision: HookDecision::Block,
            safety_score: 0,
            reason: "WSL2 桥接安全拦截：检测到重放 Nonce 请求".into(),
            latency_path: "wsl_replay_reject".into(),
        };
    }

    let snap = coordinator.snapshot();
    // Detect WSL2 proxy desync: host uses SystemProxy (non-TUN) while WSL2 reports empty proxy env.
    if snap.access.level == AccessLevel::SystemProxy
        && req
            .wsl_proxy_env
            .as_deref()
            .is_some_and(|v| v.trim().is_empty())
    {
        coordinator.set_wsl_proxy_desync(true);
        let port = snap.config.proxy_port;
        return WslGateResponse {
            allowed: false,
            decision: HookDecision::Block,
            safety_score: snap.risk_assessment.score,
            reason: format!(
                "🛡️ [ClaudeGuard v5 WSL2 防裸连拦截] 宿主机处于系统代理模式（非全局 TUN），但 WSL2 终端内未配置 HTTPS_PROXY！请先执行 `export HTTPS_PROXY=http://127.0.0.1:{port}` 后重试。"
            ),
            latency_path: "wsl_proxy_desync".into(),
        };
    }
    if req
        .wsl_proxy_env
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty())
        || snap.access.level == AccessLevel::Tun
    {
        coordinator.set_wsl_proxy_desync(false);
    }

    let vault_opt = (!req.vault.trim().is_empty()).then_some(req.vault.as_str());
    match coordinator.fast_hook_gate(&req.agent, vault_opt, req.hook_event.as_deref()) {
        PipeResponse::FastGateVerdict {
            allowed,
            decision,
            safety_score,
            reason,
            latency_path,
        } => WslGateResponse {
            allowed,
            decision,
            safety_score,
            reason,
            latency_path,
        },
        PipeResponse::Error { message, .. } => WslGateResponse {
            allowed: false,
            decision: HookDecision::Block,
            safety_score: 0,
            reason: format!("WSL2 桥接门禁异常：{message}"),
            latency_path: "wsl_error".into(),
        },
        _ => WslGateResponse {
            allowed: false,
            decision: HookDecision::Block,
            safety_score: 0,
            reason: "WSL2 桥接收到未知门禁响应".into(),
            latency_path: "wsl_error".into(),
        },
    }
}

/// Live WSL2 loopback HMAC TCP server handle.
pub struct WslBridgeServer {
    bound_addr: SocketAddr,
    secret_hex: String,
    token_path: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl WslBridgeServer {
    /// Starts the loopback HMAC bridge on `127.0.0.1:0` and persists `.claudeguard-wsl-token`
    /// inside `token_dir` (usually the interactive user home directory).
    pub fn start(
        coordinator: CoordinatorHandle,
        token_dir: Option<&Path>,
        proxy_port: u16,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("failed to bind WSL2 loopback bridge on 127.0.0.1:0: {e}"))?;
        let bound_addr = listener
            .local_addr()
            .map_err(|e| format!("failed to inspect WSL2 bridge local_addr: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to configure non-blocking WSL2 listener: {e}"))?;

        let secret_hex = crypto_win::random_hex(32)?;
        let boot_epoch = now_unix_secs();

        let token_file = WslTokenFile {
            port: bound_addr.port(),
            host_wsl_ip: "127.0.0.1".to_string(),
            proxy_port,
            secret_hex: secret_hex.clone(),
            boot_epoch,
        };

        let token_path = if let Some(dir) = token_dir {
            let p = dir.join(WSL_TOKEN_FILE);
            write_wsl_token_file(&p, &token_file)?;
            Some(p)
        } else {
            None
        };

        let stop = Arc::new(AtomicBool::new(false));
        let replay_cache = Arc::new(Mutex::new(NonceReplayCache::new(NONCE_CACHE_CAPACITY)));

        let t_stop = stop.clone();
        let t_secret = secret_hex.clone();
        let t_cache = replay_cache.clone();
        let t_coord = coordinator;

        let handle = std::thread::Builder::new()
            .name("cg-wsl-bridge".to_string())
            .spawn(move || {
                while !t_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            if !is_allowed_peer_ip(peer.ip()) {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                continue;
                            }
                            handle_client_stream(stream, &t_secret, &t_cache, &t_coord);
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(15));
                        }
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })
            .map_err(|e| format!("failed to spawn WSL2 bridge thread: {e}"))?;

        Ok(Self {
            bound_addr,
            secret_hex,
            token_path,
            stop,
            thread: Mutex::new(Some(handle)),
        })
    }

    pub fn port(&self) -> u16 {
        self.bound_addr.port()
    }

    pub fn addr(&self) -> SocketAddr {
        self.bound_addr
    }

    pub fn secret_hex(&self) -> &str {
        &self.secret_hex
    }

    pub fn token_path(&self) -> Option<&Path> {
        self.token_path.as_deref()
    }

    /// Builds a [`WslBridgeStatus`] reflecting this live bridge.
    pub fn status(
        &self,
        synced_distros: Vec<String>,
        proxy_desync_detected: bool,
    ) -> WslBridgeStatus {
        let port = self.bound_addr.port();
        let token_ready = self.token_path.as_ref().is_some_and(|p| p.is_file());
        let summary = if proxy_desync_detected {
            format!("WSL2 桥接监听 127.0.0.1:{port}，检测到 WSL2 代理环境变量失步")
        } else if synced_distros.is_empty() {
            format!("WSL2 桥接就绪（127.0.0.1:{port}），等待同步发行版探针")
        } else {
            format!(
                "WSL2 桥接就绪（127.0.0.1:{port}，已同步 {} 个发行版）",
                synced_distros.len()
            )
        };
        WslBridgeStatus {
            enabled: true,
            listening: !self.stop.load(Ordering::Acquire),
            bound_port: Some(port),
            token_ready,
            synced_distros,
            proxy_desync_detected,
            summary,
        }
    }

    /// Stops the listener thread cleanly (idempotent).
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        // Nudge accept loop cleanly.
        let _ = TcpStream::connect_timeout(&self.bound_addr, Duration::from_millis(50));
        if let Ok(mut guard) = self.thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for WslBridgeServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Strictly permits loopback peers only (zero LAN exposure).
pub fn is_allowed_peer_ip(ip: IpAddr) -> bool {
    ip.is_loopback()
}

fn handle_client_stream(
    mut stream: TcpStream,
    secret_hex: &str,
    replay_cache: &Mutex<NonceReplayCache>,
    coordinator: &CoordinatorHandle,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));

    let mut line = String::new();
    let read_res = {
        let mut reader = BufReader::new((&mut stream).take(MAX_REQUEST_BYTES as u64));
        reader.read_line(&mut line)
    };
    let resp = match read_res {
        Ok(0) => return,
        Ok(_) => match serde_json::from_str::<WslGateRequest>(line.trim()) {
            Ok(req) => {
                evaluate_wsl_request(&req, secret_hex, replay_cache, coordinator, now_unix_secs())
            }
            Err(err) => WslGateResponse {
                allowed: false,
                decision: HookDecision::Block,
                safety_score: 0,
                reason: format!("WSL2 请求 JSON 格式无效：{err}"),
                latency_path: "wsl_parse_error".into(),
            },
        },
        Err(_) => return,
    };

    if let Ok(mut body) = serde_json::to_vec(&resp) {
        body.push(b'\n');
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    }
}

/// Writes `.claudeguard-wsl-token` atomically with reparse-point checks and protected DACL when elevated.
pub fn write_wsl_token_file(path: &Path, token: &WslTokenFile) -> Result<(), String> {
    vault_win::ensure_no_reparse_points_chain(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("WSL token path lacks parent dir: {}", path.display()))?;
    vault_win::safe_create_dir_all_no_reparse(parent)?;

    let bytes = serde_json::to_vec_pretty(token)
        .map_err(|e| format!("failed to serialize WSL token JSON: {e}"))?;
    let mut tmp = NamedTempFile::new_in(parent)
        .map_err(|e| format!("failed to create temp WSL token file: {e}"))?;
    tmp.write_all(&bytes)
        .map_err(|e| format!("failed to write temp WSL token file: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("failed to sync temp WSL token file: {e}"))?;
    tmp.persist(path).map_err(|e| {
        format!(
            "failed to persist WSL token {}: {}",
            path.display(),
            e.error
        )
    })?;

    #[cfg(windows)]
    if cg_platform::access_win::is_session_zero()
        || cg_platform::access_win::is_elevated().unwrap_or(false)
    {
        let _ = apply_user_only_token_dacl(path);
    }

    Ok(())
}

#[cfg(windows)]
fn apply_user_only_token_dacl(path: &Path) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL, NO_ERROR};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    struct SdGuard(PSECURITY_DESCRIPTOR);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0));
                }
            }
        }
    }

    let sddl = match cg_platform::access_win::active_interactive_user_sid() {
        Some(sid) if sid.starts_with("S-1-5-21-") => {
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{sid})")
        }
        _ => "D:P(A;;FA;;;SY)(A;;FA;;;BA)".to_string(),
    };

    let sddl_w: Vec<u16> = OsStr::new(&sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|e| format!("ConvertStringSecurityDescriptorToSecurityDescriptorW: {e}"))?;
    let _guard = SdGuard(sd);

    let mut present = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = BOOL(0);
    unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }
        .map_err(|e| format!("GetSecurityDescriptorDacl: {e}"))?;
    if !present.as_bool() || dacl.is_null() {
        return Err("empty DACL for WSL token".into());
    }

    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(dacl.cast_const()),
            None,
        )
    };
    if status != NO_ERROR {
        return Err(format!(
            "SetNamedSecurityInfoW on WSL token failed: {}",
            status.0
        ));
    }
    Ok(())
}

/// Converts a Windows path (e.g. `D:\Users\alice\.claudeguard-wsl-token` or
/// `\\?\C:\Users\mjq\.claudeguard-wsl-token`) to its WSL2 DrvFs mount path
/// (`/mnt/d/Users/alice/.claudeguard-wsl-token`).
pub fn windows_path_to_wsl_mnt_path(win_path: &Path) -> String {
    let raw = win_path.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw).trim();
    let bytes = stripped.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = stripped[2..].replace('\\', "/");
        let rest = rest.trim_start_matches('/');
        format!("/mnt/{drive}/{rest}")
    } else {
        stripped.replace('\\', "/")
    }
}

/// Renders the pure-LF `~/.local/bin/claudeguard-wsl-gate` zero-dep Python3/stdlib gate shim.
pub fn render_wsl_gate_shim(wsl_token_mnt_path: &str) -> String {
    let safe_path = wsl_token_mnt_path
        .trim()
        .replace(['\'', '"', '\n', '\r', '\0'], "");
    format!(
        "#!/usr/bin/env python3\n\
# ClaudeGuard v5 WSL2 Loopback HMAC Gate Shim (auto-managed)\n\
import hashlib, hmac, json, os, secrets, socket, sys, time\n\
\n\
TOKEN_PATH = os.environ.get('CG_WSL_TOKEN_PATH', '{safe_path}')\n\
\n\
def main():\n\
    agent = 'claude-code'\n\
    vault = os.environ.get('CG_VAULT_ID', '')\n\
    hook_event = None\n\
    args = sys.argv[1:]\n\
    i = 0\n\
    while i < len(args):\n\
        if args[i] == '--agent' and i + 1 < len(args):\n\
            agent = args[i + 1]; i += 2\n\
        elif args[i] == '--vault' and i + 1 < len(args):\n\
            vault = args[i + 1]; i += 2\n\
        elif args[i] in ('--hook-event', '--event') and i + 1 < len(args):\n\
            hook_event = args[i + 1]; i += 2\n\
        else:\n\
            i += 1\n\
    try:\n\
        with open(TOKEN_PATH, 'r', encoding='utf-8') as f:\n\
            tok = json.load(f)\n\
    except Exception as e:\n\
        print(json.dumps({{'decision': 'block', 'reason': f'ClaudeGuard WSL2 token unavailable: {{e}}'}}))\n\
        return 0\n\
    ts = int(time.time())\n\
    nonce = secrets.token_hex(12)\n\
    proxy_env = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy') or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy') or ''\n\
    msg = f'{{ts}}:{{nonce}}:{{agent}}:{{vault}}:{{proxy_env}}' if proxy_env else f'{{ts}}:{{nonce}}:{{agent}}:{{vault}}'\n\
    sig = hmac.new(tok['secret_hex'].encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()\n\
    req = {{'ts': ts, 'nonce': nonce, 'agent': agent, 'vault': vault, 'hook_event': hook_event, 'wsl_proxy_env': proxy_env, 'hmac': sig}}\n\
    try:\n\
        with socket.create_connection((tok.get('host_wsl_ip', '127.0.0.1'), int(tok['port'])), timeout=1.5) as s:\n\
            s.sendall((json.dumps(req) + '\\n').encode('utf-8'))\n\
            data = s.recv(4096).decode('utf-8').strip()\n\
        resp = json.loads(data)\n\
    except Exception as e:\n\
        print(json.dumps({{'decision': 'block', 'reason': f'ClaudeGuard WSL2 bridge unreachable: {{e}}'}}))\n\
        return 0\n\
    if not resp.get('allowed', False):\n\
        print(json.dumps({{'decision': 'block', 'reason': resp.get('reason', 'Blocked by ClaudeGuard')}}))\n\
    return 0\n\
\n\
if __name__ == '__main__':\n\
    sys.exit(main())\n"
    )
}

/// Deploys `~/.local/bin/claudeguard-wsl-gate` (LF newlines) and safely updates `.claude/settings.json`
/// inside an explicit Linux home directory (testable without live WSL).
///
/// Uses explicit `python3 "$HOME/.local/bin/claudeguard-wsl-gate"` invocation so the hook executes
/// reliably over `\\wsl.localhost` Plan9 (`9p`) mounts where Windows-created files lack `+x` bits,
/// checks reparse points, saves `.cg-bak` before modifying `settings.json`, and propagates errors.
pub fn sync_wsl_distro_home(linux_home: &Path, win_token_path: &Path) -> Result<PathBuf, String> {
    vault_win::ensure_no_reparse_points_chain(linux_home)?;
    let bin_dir = linux_home.join(".local").join("bin");
    vault_win::safe_create_dir_all_no_reparse(&bin_dir)?;
    let shim_path = bin_dir.join("claudeguard-wsl-gate");
    vault_win::ensure_no_reparse_points_chain(&shim_path)?;
    let wsl_token_mnt = windows_path_to_wsl_mnt_path(win_token_path);
    let script = render_wsl_gate_shim(&wsl_token_mnt);
    std::fs::write(&shim_path, script.as_bytes())
        .map_err(|e| format!("写入 WSL2 门禁探针失败（{}）：{e}", shim_path.display()))?;

    // Merge hook into WSL2 `~/.claude/settings.json` invoking via `python3` (9p safe without chmod +x).
    let settings_dir = linux_home.join(".claude");
    vault_win::safe_create_dir_all_no_reparse(&settings_dir)?;
    let settings_path = settings_dir.join("settings.json");
    vault_win::ensure_no_reparse_points_chain(&settings_path)?;

    let mut root = if settings_path.is_file() {
        let raw_bytes = std::fs::read(&settings_path)
            .map_err(|e| format!("读取 WSL2 settings.json 失败：{e}"))?;
        let raw_text = String::from_utf8(raw_bytes.clone())
            .map_err(|e| format!("WSL2 settings.json 非有效 UTF-8，已中止写入：{e}"))?;
        let trimmed = raw_text.trim();
        let parsed = if trimmed.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str::<serde_json::Value>(trimmed)
                .map_err(|e| format!("WSL2 settings.json 语法错误，已中止写入：{e}"))?
        };
        if !parsed.is_object() {
            return Err("WSL2 settings.json 根节点不是 JSON 对象，已中止写入".into());
        }
        let bak_path = settings_dir.join("settings.json.cg-bak");
        vault_win::ensure_no_reparse_points_chain(&bak_path)?;
        std::fs::write(&bak_path, &raw_bytes)
            .map_err(|e| format!("创建 WSL2 settings.json.cg-bak 备份失败：{e}"))?;
        parsed
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    if let Some(obj) = root.as_object_mut() {
        let hooks = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if !hooks.is_object() {
            return Err("WSL2 settings.json 中 `hooks` 字段不是对象，已中止写入".into());
        }
        if let Some(hobj) = hooks.as_object_mut() {
            let arr = hobj
                .entry("UserPromptSubmit".to_string())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if !arr.is_array() {
                return Err(
                    "WSL2 settings.json 中 `hooks.UserPromptSubmit` 字段不是数组，已中止写入"
                        .into(),
                );
            }
            if let Some(list) = arr.as_array_mut() {
                list.retain(|item| {
                    !item
                        .to_string()
                        .to_ascii_lowercase()
                        .contains("claudeguard-wsl-gate")
                });
                list.push(serde_json::json!({
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python3 \"$HOME/.local/bin/claudeguard-wsl-gate\" --agent claude-code",
                            "timeout": 5
                        }
                    ]
                }));
            }
        }
    }

    let text = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("序列化 WSL2 settings.json 失败：{e}"))?;
    std::fs::write(&settings_path, format!("{text}\n")).map_err(|e| {
        format!(
            "写入 WSL2 settings.json 失败（{}）：{e}",
            settings_path.display()
        )
    })?;
    Ok(shim_path)
}

/// Discovers installed WSL2 distributions from the Windows `Lxss` registry hive.
#[cfg(windows)]
pub fn discover_wsl_distro_names() -> Vec<String> {
    let mut out = Vec::new();
    let key = cg_platform::access_win::open_interactive_user_subkey(
        r"Software\Microsoft\Windows\CurrentVersion\Lxss",
    );
    let Some(lxss) = key else {
        return out;
    };
    for sub in lxss.enum_keys().flatten() {
        let Ok(distro_key) = lxss.open_subkey(&sub) else {
            continue;
        };
        if let Ok(name) = distro_key.get_value::<String, _>("DistributionName") {
            let trimmed = name.trim().to_string();
            if !trimmed.is_empty() && !out.contains(&trimmed) {
                out.push(trimmed);
            }
        }
    }
    out
}

#[cfg(not(windows))]
pub fn discover_wsl_distro_names() -> Vec<String> {
    Vec::new()
}

/// Synchronizes `~/.local/bin/claudeguard-wsl-gate` across all accessible installed WSL2 distros
/// and returns an updated [`WslBridgeStatus`].
pub fn sync_wsl_distros(
    enabled: bool,
    bound_port: Option<u16>,
    token_ready: bool,
    proxy_desync_detected: bool,
) -> WslBridgeStatus {
    let win_token_path = hook_installer::resolve_interactive_user_home()
        .map(|h| h.join(WSL_TOKEN_FILE))
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\User").join(WSL_TOKEN_FILE));

    let distros = discover_wsl_distro_names();
    let mut synced = Vec::new();

    for distro in &distros {
        let home_root = PathBuf::from(format!(r"\\wsl.localhost\{distro}\home"));
        let Ok(entries) = std::fs::read_dir(&home_root) else {
            continue;
        };
        let mut distro_ok = false;
        for entry in entries.flatten() {
            let candidate = entry.path();
            if candidate.is_dir() && sync_wsl_distro_home(&candidate, &win_token_path).is_ok() {
                distro_ok = true;
            }
        }
        if distro_ok {
            synced.push(distro.clone());
        }
    }

    let listening = enabled && bound_port.is_some();
    let summary = if !enabled {
        "WSL2 跨子系统桥接已在设置中关闭".to_string()
    } else if distros.is_empty() {
        match bound_port {
            Some(p) => format!("WSL2 回环桥接监听 127.0.0.1:{p}（未检测到已安装的 WSL 发行版）"),
            None => "未检测到已安装的 WSL 发行版".to_string(),
        }
    } else if synced.is_empty() {
        format!(
            "检测到 {} 个 WSL 发行版（当前休眠中，启动发行版后可再次点击同步）",
            distros.len()
        )
    } else {
        format!(
            "已同步 {} 个 WSL2 发行版门禁探针：{}",
            synced.len(),
            synced.join("、")
        )
    };

    WslBridgeStatus {
        enabled,
        listening,
        bound_port,
        token_ready,
        synced_distros: synced,
        proxy_desync_detected,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{
        start_coordinator, ActorControl, CoordinatorActor, CoordinatorContext, CoordinatorEvent,
    };
    use crate::protocol::{
        AccessEvidence, AccessLevel, Config, GuardSnapshot, Lifecycle, ProtectionState,
        TargetState, TargetStatus,
    };

    struct PassiveActor;
    impl CoordinatorActor for PassiveActor {
        fn on_event(
            &mut self,
            _event: CoordinatorEvent,
            _ctx: &CoordinatorContext<'_>,
        ) -> ActorControl {
            ActorControl::Continue
        }
    }

    fn fresh_passing_snapshot(access_level: AccessLevel, now: u64) -> GuardSnapshot {
        let mut cfg = Config {
            first_run: false,
            proxy_port: 7890,
            ..Config::default()
        };
        for t in &mut cfg.targets {
            t.expect_regions = vec!["US".into()];
        }
        let targets = cfg
            .targets
            .iter()
            .map(|t| {
                let mut st = TargetStatus::from_target(
                    t,
                    if t.enabled {
                        TargetState::Pass
                    } else {
                        TargetState::Disabled
                    },
                );
                if t.enabled {
                    st.country = Some("US".into());
                    st.ip = Some("198.51.100.10".into());
                }
                st
            })
            .collect();
        GuardSnapshot {
            lifecycle: Lifecycle::Armed,
            protection: ProtectionState::Monitoring,
            checked_at: Some(now),
            access: AccessEvidence {
                level: access_level,
                proxy_addr: (access_level == AccessLevel::SystemProxy)
                    .then(|| "127.0.0.1:7890".into()),
                observed_at: now,
                revision: 1,
                ..AccessEvidence::default()
            },
            config: cfg,
            targets,
            ..GuardSnapshot::default()
        }
    }

    fn send_wsl_req(addr: SocketAddr, req: &WslGateRequest) -> WslGateResponse {
        let mut stream = TcpStream::connect(addr).expect("connect wsl bridge");
        let mut line = serde_json::to_vec(req).unwrap();
        line.push(b'\n');
        stream.write_all(&line).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).unwrap();
        serde_json::from_str(resp_line.trim()).unwrap()
    }

    #[test]
    fn wsl_bridge_verifies_hmac_rejects_tamper_expiry_replay_and_detects_proxy_desync() {
        let now = now_unix_secs();
        let dir = tempfile::tempdir().unwrap();
        let coord = start_coordinator(
            fresh_passing_snapshot(AccessLevel::Tun, now),
            Box::new(PassiveActor),
        );
        let bridge = WslBridgeServer::start(coord.clone(), Some(dir.path()), 7890).unwrap();

        // Token file persisted with matching port & 64-char hex secret.
        let tok_raw = std::fs::read_to_string(bridge.token_path().unwrap()).unwrap();
        let tok: WslTokenFile = serde_json::from_str(&tok_raw).unwrap();
        assert_eq!(tok.port, bridge.port());
        assert_eq!(tok.secret_hex.len(), 64);

        // 1) Valid HMAC succeeds in < 50ms (typically < 2ms).
        let started = std::time::Instant::now();
        let nonce1 = "a1b2c3d4e5f60718".to_string();
        let sig1 = compute_wsl_hmac(&tok.secret_hex, now, &nonce1, "claude-code", "", None);
        let req1 = WslGateRequest {
            ts: now,
            nonce: nonce1.clone(),
            agent: "claude-code".into(),
            vault: String::new(),
            hook_event: None,
            wsl_proxy_env: None,
            hmac: sig1,
        };
        let resp1 = send_wsl_req(bridge.addr(), &req1);
        assert!(resp1.allowed, "valid HMAC should pass: {resp1:?}");
        assert_eq!(resp1.decision, HookDecision::Allow);
        assert!(started.elapsed() < Duration::from_millis(250));

        // 2) Replaying the exact same nonce MUST be rejected!
        let replay = send_wsl_req(bridge.addr(), &req1);
        assert!(!replay.allowed);
        assert_eq!(replay.latency_path, "wsl_replay_reject");

        // 3) Tampered HMAC MUST be rejected!
        let mut bad_sig = req1.clone();
        bad_sig.nonce = "deadbeefcafebabe".into();
        bad_sig.hmac = "0".repeat(64);
        let tamper_resp = send_wsl_req(bridge.addr(), &bad_sig);
        assert!(!tamper_resp.allowed);
        assert_eq!(tamper_resp.latency_path, "wsl_hmac_reject");

        // 4) Expired timestamp (> 60s old) MUST be rejected!
        let stale_ts = now.saturating_sub(120);
        let nonce_stale = "1122334455667788".to_string();
        let sig_stale = compute_wsl_hmac(
            &tok.secret_hex,
            stale_ts,
            &nonce_stale,
            "claude-code",
            "",
            None,
        );
        let stale_resp = send_wsl_req(
            bridge.addr(),
            &WslGateRequest {
                ts: stale_ts,
                nonce: nonce_stale,
                agent: "claude-code".into(),
                vault: String::new(),
                hook_event: None,
                wsl_proxy_env: None,
                hmac: sig_stale,
            },
        );
        assert!(!stale_resp.allowed);
        assert_eq!(stale_resp.latency_path, "wsl_clock_reject");

        // 5) Host in SystemProxy mode + WSL empty proxy env => blocked with proxy desync alert!
        coord.replace_snapshot(fresh_passing_snapshot(AccessLevel::SystemProxy, now));
        let nonce_desync = "9988776655443322".to_string();
        let sig_desync = compute_wsl_hmac(
            &tok.secret_hex,
            now,
            &nonce_desync,
            "claude-code",
            "",
            Some(""),
        );
        let desync_resp = send_wsl_req(
            bridge.addr(),
            &WslGateRequest {
                ts: now,
                nonce: nonce_desync,
                agent: "claude-code".into(),
                vault: String::new(),
                hook_event: None,
                wsl_proxy_env: Some(String::new()),
                hmac: sig_desync,
            },
        );
        assert!(!desync_resp.allowed);
        assert_eq!(desync_resp.latency_path, "wsl_proxy_desync");
        assert!(desync_resp.reason.contains("HTTPS_PROXY"));
        assert!(coord.wsl_proxy_desync());

        // 6) Host in SystemProxy mode + WSL proxy env populated => allowed & desync cleared!
        let nonce_ok = "abcdef0123456789".to_string();
        let proxy_val = "http://127.0.0.1:7890";
        let sig_ok = compute_wsl_hmac(
            &tok.secret_hex,
            now,
            &nonce_ok,
            "claude-code",
            "",
            Some(proxy_val),
        );
        let ok_resp = send_wsl_req(
            bridge.addr(),
            &WslGateRequest {
                ts: now,
                nonce: nonce_ok,
                agent: "claude-code".into(),
                vault: String::new(),
                hook_event: None,
                wsl_proxy_env: Some(proxy_val.into()),
                hmac: sig_ok,
            },
        );
        assert!(ok_resp.allowed);
        assert!(!coord.wsl_proxy_desync());

        // 7) Non-loopback peer IP rejected by allowlist helper.
        assert!(is_allowed_peer_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_allowed_peer_ip("192.168.1.50".parse().unwrap()));

        // 8) WSL distro shim deployment uses pure LF newlines, dynamic /mnt/<drive> path,
        //    python3 invocation (9p safe without chmod +x), .cg-bak backup, and error propagation.
        assert_eq!(
            windows_path_to_wsl_mnt_path(Path::new(r"D:\Users\alice\.claudeguard-wsl-token")),
            "/mnt/d/Users/alice/.claudeguard-wsl-token"
        );
        let fake_linux_home = dir.path().join("wsl_home");
        let wsl_claude_dir = fake_linux_home.join(".claude");
        std::fs::create_dir_all(&wsl_claude_dir).unwrap();
        let orig_settings = r#"{"theme":"dark","hooks":{"UserPromptSubmit":[{"matcher":"keep","hooks":[{"type":"command","command":"echo hi"}]}]}}"#;
        std::fs::write(wsl_claude_dir.join("settings.json"), orig_settings).unwrap();

        let custom_win_tok = PathBuf::from(r"D:\Profiles\alice\.claudeguard-wsl-token");
        let shim = sync_wsl_distro_home(&fake_linux_home, &custom_win_tok).unwrap();
        let shim_content = std::fs::read_to_string(&shim).unwrap();
        assert!(!shim_content.contains('\r'), "WSL shim must use LF only");
        assert!(shim_content.contains("/mnt/d/Profiles/alice/.claudeguard-wsl-token"));
        let wsl_settings = std::fs::read_to_string(wsl_claude_dir.join("settings.json")).unwrap();
        assert!(
            wsl_settings.contains(
                r#"python3 \"$HOME/.local/bin/claudeguard-wsl-gate\" --agent claude-code"#
            ),
            "WSL hook must invoke python3 explicitly for 9p mounts: {wsl_settings}"
        );
        assert!(wsl_settings.contains("echo hi"));
        assert!(wsl_claude_dir.join("settings.json.cg-bak").is_file());

        // Corrupt settings.json aborts cleanly without clobbering file.
        let bad_home = dir.path().join("wsl_bad_home");
        std::fs::create_dir_all(bad_home.join(".claude")).unwrap();
        std::fs::write(bad_home.join(".claude").join("settings.json"), "{broken").unwrap();
        assert!(sync_wsl_distro_home(&bad_home, &custom_win_tok).is_err());
        assert_eq!(
            std::fs::read_to_string(bad_home.join(".claude").join("settings.json")).unwrap(),
            "{broken"
        );

        bridge.shutdown();
        coord.shutdown();
    }
}
