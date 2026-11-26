//! Dual-layer `yuaotian/antigravity-proxy` detector (static `version.dll` + `config.json`
//! inspection and live `Toolhelp32` memory module verification).
//!
//! Protects Antigravity users against silent direct-connection fallback when an Antigravity IDE
//! self-update wipes or replaces `<AntigravityDir>\version.dll`, when `config.json` has
//! `child_injection: false` or a mismatched proxy port, or when a running `language_server.exe`
//! failed to load `<AntigravityDir>\version.dll` in memory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use cg_protocol::{AntigravityProxyState, AntigravityProxyStatus};

use crate::process_win::{
    self, is_live_root_antigravity_gui, path_under_dir_l, CachedProcessSnapshot, ProcInfo,
};

/// Minimum valid file size (32 KiB) for `yuaotian/antigravity-proxy` `version.dll`.
pub const MIN_PROXY_DLL_BYTES: usize = 32 * 1024;

/// Maximum `version.dll` size read into memory (64 MiB defensive bound).
const MAX_PROXY_DLL_BYTES: u64 = 64 * 1024 * 1024;

/// Zero-allocation case-insensitive ASCII substring search (`needle_lower` must be lowercase ASCII).
fn contains_ascii_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if haystack.len() < needle_lower.len() {
        return false;
    }
    let first_lo = needle_lower[0];
    let first_hi = first_lo.to_ascii_uppercase();
    let end = haystack.len() - needle_lower.len();
    let mut idx = 0;
    while idx <= end {
        let b = haystack[idx];
        if (b == first_lo || b == first_hi)
            && haystack[idx..idx + needle_lower.len()].eq_ignore_ascii_case(needle_lower)
        {
            return true;
        }
        idx += 1;
    }
    false
}

/// Pure binary signature validator distinguishing `yuaotian/antigravity-proxy`'s `version.dll`
/// from Microsoft's `System32\version.dll` or truncated/corrupt files.
pub fn validate_antigravity_proxy_dll_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < MIN_PROXY_DLL_BYTES || !bytes.starts_with(b"MZ") {
        return false;
    }
    contains_ascii_ci(bytes, b"antigravity")
        && contains_ascii_ci(bytes, b"proxy")
        && (contains_ascii_ci(bytes, b"config.json")
            || contains_ascii_ci(bytes, b"child_injection")
            || contains_ascii_ci(bytes, b"socks5"))
}

/// Normalize a Windows filesystem path for case-insensitive module comparison.
pub fn normalize_module_path(raw: &str) -> String {
    raw.trim()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// Inspect loaded modules of `pid` via Win32 `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`
/// and verify whether `expected_dll_path` (`<AntigravityDir>\version.dll`, NOT `System32\version.dll`)
/// is mapped into the process address space.
#[cfg(windows)]
pub fn is_module_loaded_in_process(pid: u32, expected_dll_path: &Path) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    const HRESULT_ERROR_BAD_LENGTH: i32 = 0x8007_0018u32 as i32;

    if pid == 0 {
        return false;
    }
    let expected_norm = normalize_module_path(&expected_dll_path.to_string_lossy());
    if expected_norm.is_empty() {
        return false;
    }

    unsafe {
        let mut snap_opt = None;
        for _ in 0..4 {
            match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
                Ok(h) if h != INVALID_HANDLE_VALUE => {
                    snap_opt = Some(h);
                    break;
                }
                Ok(_) => break,
                Err(e) if e.code().0 == HRESULT_ERROR_BAD_LENGTH => {
                    // MSDN: retry when target process module list is mid-mutation.
                    continue;
                }
                Err(_) => break,
            }
        }
        let Some(snap) = snap_opt else {
            return false;
        };
        let _snap_guard = HandleGuard(snap);

        let mut matched = false;
        let mut entry = MODULEENTRY32W {
            dwSize: core::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        if Module32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExePath
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExePath.len());
                let mod_path = String::from_utf16_lossy(&entry.szExePath[..len]);
                if normalize_module_path(&mod_path) == expected_norm {
                    matched = true;
                    break;
                }
                if Module32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        matched
    }
}

#[cfg(not(windows))]
pub fn is_module_loaded_in_process(_pid: u32, _expected_dll_path: &Path) -> bool {
    false
}

/// Fast liveness probe preventing stale cached PIDs (from a process that exited moments ago)
/// from triggering spurious `RuntimeUnhooked` warnings during normal app shutdown.
#[cfg(windows)]
fn is_process_still_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    const STILL_ACTIVE_CODE: u32 = 259;

    if pid == 0 {
        return false;
    }
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let _guard = HandleGuard(handle);
        let mut code: u32 = 0;
        GetExitCodeProcess(handle, &mut code).is_ok() && code == STILL_ACTIVE_CODE
    }
}

#[cfg(not(windows))]
fn is_process_still_alive(_pid: u32) -> bool {
    false
}

/// Pure, deterministic inspector for an explicit Antigravity installation directory.
pub fn inspect_antigravity_proxy_in_dir(
    dir: &Path,
    expected_proxy_port: u16,
    last_seen_version: Option<&str>,
    runtime_main_pids: &[u32],
    runtime_ls_pids: &[u32],
    module_checker: impl Fn(u32, &Path) -> bool,
    now_secs: u64,
) -> AntigravityProxyStatus {
    if !dir.is_dir() {
        return AntigravityProxyStatus {
            state: AntigravityProxyState::NotInstalled,
            installed: false,
            checked_at: now_secs,
            summary: "未检测到反重力客户端安装目录".to_string(),
            ..AntigravityProxyStatus::default()
        };
    }

    let antigravity_version = std::fs::read_to_string(dir.join("version"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let version_changed_from = match (
        last_seen_version.map(str::trim).filter(|s| !s.is_empty()),
        antigravity_version.as_deref(),
    ) {
        (Some(prev), Some(curr)) if prev != curr => Some(prev.to_string()),
        _ => None,
    };

    let dll_path = dir.join("version.dll");
    let (dll_present, dll_size, dll_valid) = match std::fs::metadata(&dll_path) {
        Ok(meta) if meta.is_file() => {
            let size = meta.len();
            let valid = if (MIN_PROXY_DLL_BYTES as u64..=MAX_PROXY_DLL_BYTES).contains(&size) {
                std::fs::read(&dll_path)
                    .map(|bytes| validate_antigravity_proxy_dll_bytes(&bytes))
                    .unwrap_or(false)
            } else {
                false
            };
            (true, size, valid)
        }
        _ => (false, 0, false),
    };

    let cfg_path = dir.join("config.json");
    let config_present = cfg_path.is_file();
    let mut injector_version: Option<String> = None;
    let mut child_injection: Option<bool> = None;
    let mut proxy_type: Option<String> = None;
    let mut proxy_host: Option<String> = None;
    let mut proxy_port: Option<u16> = None;

    if config_present {
        if let Ok(raw) = std::fs::read_to_string(&cfg_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                injector_version = val
                    .get("_version")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string);
                child_injection = val.get("child_injection").and_then(|v| v.as_bool());
                proxy_type = val
                    .pointer("/proxy/type")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string);
                proxy_host = val
                    .pointer("/proxy/host")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string);
                proxy_port = val
                    .pointer("/proxy/port")
                    .and_then(|v| {
                        v.as_u64()
                            .and_then(|n| u16::try_from(n).ok())
                            .or_else(|| v.as_str()?.trim().parse::<u16>().ok())
                    })
                    .filter(|&p| p > 0);
            }
        }
    }

    if dll_valid && injector_version.is_none() {
        injector_version = process_win::read_pe_file_version(&dll_path)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    let port_matches_guard =
        proxy_port.is_some_and(|p| expected_proxy_port == 0 || p == expected_proxy_port);

    let runtime_running = !runtime_main_pids.is_empty() || !runtime_ls_pids.is_empty();
    let runtime_dll_loaded_main = runtime_main_pids
        .iter()
        .any(|&pid| module_checker(pid, &dll_path));
    let runtime_dll_loaded_ls = !runtime_ls_pids.is_empty()
        && runtime_ls_pids
            .iter()
            .all(|&pid| module_checker(pid, &dll_path));

    let state = if !dll_present || !dll_valid {
        AntigravityProxyState::MissingDll
    } else if !config_present || child_injection == Some(false) || proxy_port.is_none() {
        AntigravityProxyState::MissingOrInvalidConfig
    } else if !port_matches_guard {
        AntigravityProxyState::PortMismatch
    } else if runtime_running
        && ((!runtime_ls_pids.is_empty() && !runtime_dll_loaded_ls)
            || (runtime_ls_pids.is_empty() && !runtime_dll_loaded_main))
    {
        AntigravityProxyState::RuntimeUnhooked
    } else {
        AntigravityProxyState::Healthy
    };

    let summary = match state {
        AntigravityProxyState::NotInstalled => "未检测到反重力客户端安装目录".to_string(),
        AntigravityProxyState::MissingDll => match (&version_changed_from, &antigravity_version) {
            (Some(prev), Some(curr)) if !dll_present => {
                format!("反重力由 v{prev} 升级至 v{curr} 后 version.dll 被覆盖丢失，需重新注入")
            }
            (Some(prev), Some(curr)) => {
                format!("反重力由 v{prev} 升级至 v{curr} 后 version.dll 签名无效，非代理注入模块")
            }
            _ if !dll_present => {
                "反重力目录缺失 version.dll（可能被客户端更新覆盖），存在直连风险".to_string()
            }
            _ => "反重力目录 version.dll 校验未通过（非有效 antigravity-proxy 模块）".to_string(),
        },
        AntigravityProxyState::MissingOrInvalidConfig => {
            if !config_present {
                "反重力目录缺失 antigravity-proxy 配置文件 config.json".to_string()
            } else if child_injection == Some(false) {
                "config.json 中 child_injection 已关闭，language_server 子进程无法注入代理"
                    .to_string()
            } else {
                "config.json 缺少有效的 proxy.port 代理端口配置".to_string()
            }
        }
        AntigravityProxyState::PortMismatch => format!(
            "config.json 代理端口 ({}) 与 ClaudeGuard 守护端口 ({}) 不一致",
            proxy_port.unwrap_or(0),
            expected_proxy_port
        ),
        AntigravityProxyState::RuntimeUnhooked => {
            if !runtime_ls_pids.is_empty() && !runtime_dll_loaded_ls {
                "反重力运行中，但 language_server 进程内存未挂载 version.dll（请重启反重力）"
                    .to_string()
            } else {
                "反重力主进程运行中，但内存未挂载 version.dll（请重启反重力）".to_string()
            }
        }
        AntigravityProxyState::Healthy => {
            let ver_tag = injector_version
                .as_deref()
                .map(|v| format!("v{v} "))
                .unwrap_or_default();
            let scheme = proxy_type.as_deref().unwrap_or("socks5");
            let host = proxy_host.as_deref().unwrap_or("127.0.0.1");
            let port = proxy_port.unwrap_or(expected_proxy_port);
            let rt_tag = if !runtime_ls_pids.is_empty() && runtime_dll_loaded_ls {
                "language_server 内存已挂载"
            } else if runtime_running && runtime_dll_loaded_main {
                "主进程内存已挂载"
            } else {
                "静态就绪（待启动挂载）"
            };
            format!("{ver_tag}注入生效 · {scheme}://{host}:{port} · {rt_tag}")
        }
    };

    AntigravityProxyStatus {
        state,
        installed: true,
        antigravity_dir: Some(dir.to_string_lossy().to_string()),
        antigravity_version,
        dll_present,
        dll_valid,
        dll_size,
        config_present,
        injector_version,
        proxy_type,
        proxy_host,
        proxy_port,
        port_matches_guard,
        child_injection,
        runtime_running,
        runtime_dll_loaded_main,
        runtime_dll_loaded_ls,
        version_changed_from,
        checked_at: now_secs,
        summary,
    }
}

fn pick_installed_antigravity_dir(dirs: &[PathBuf]) -> Option<&PathBuf> {
    dirs.iter().find(|d| {
        d.join("Antigravity.exe").is_file()
            || d.join("Antigravity IDE.exe").is_file()
            || d.join("version").is_file()
            || d.join("resources").is_dir()
    })
}

/// Extract `(runtime_main_pids, runtime_ls_pids)` belonging to `dir` from a cached process snapshot.
pub fn collect_runtime_pids_for_dir(dir: &Path, procs: &[ProcInfo]) -> (Vec<u32>, Vec<u32>) {
    let dir_l = dir
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    let mut main_pids = Vec::new();
    let mut ls_pids = Vec::new();

    for p in procs {
        if !path_under_dir_l(&p.path_l, &dir_l) {
            continue;
        }
        if p.name_l.starts_with("language_server") {
            if !ls_pids.contains(&p.pid) {
                ls_pids.push(p.pid);
            }
        } else if is_live_root_antigravity_gui(p, &by_pid) && !main_pids.contains(&p.pid) {
            main_pids.push(p.pid);
        }
    }
    (main_pids, ls_pids)
}

/// Production entry point: discovers installed Antigravity root (even under `LocalSystem` service),
/// filters live runtime PIDs from `snap`, and performs static + `Toolhelp32` memory module checks.
pub fn inspect_antigravity_proxy(
    expected_proxy_port: u16,
    last_seen_version: Option<&str>,
    snap: &CachedProcessSnapshot,
    now_secs: u64,
) -> AntigravityProxyStatus {
    let dirs = process_win::antigravity_covered_dirs();
    let Some(dir) = pick_installed_antigravity_dir(&dirs) else {
        return AntigravityProxyStatus {
            state: AntigravityProxyState::NotInstalled,
            installed: false,
            checked_at: now_secs,
            summary: "未检测到反重力客户端安装".to_string(),
            ..AntigravityProxyStatus::default()
        };
    };

    let (raw_main, raw_ls) = collect_runtime_pids_for_dir(dir, &snap.procs);
    let main_pids: Vec<u32> = raw_main
        .into_iter()
        .filter(|&pid| is_process_still_alive(pid))
        .collect();
    let ls_pids: Vec<u32> = raw_ls
        .into_iter()
        .filter(|&pid| is_process_still_alive(pid))
        .collect();

    inspect_antigravity_proxy_in_dir(
        dir,
        expected_proxy_port,
        last_seen_version,
        &main_pids,
        &ls_pids,
        is_module_loaded_in_process,
        now_secs,
    )
}

/// Outcome of one-click verified `yuaotian/antigravity-proxy` hot re-injection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AntigravityRepairReport {
    pub install_dir: PathBuf,
    pub release_tag: String,
    pub sha256_hex: String,
    pub proxy_port: u16,
    pub summary: String,
}

/// Rejects any NTFS junction, mount point, or symbolic link (`FILE_ATTRIBUTE_REPARSE_POINT`)
/// on every ancestor component and target path so `LocalSystem` NEVER follows junctions into
/// privileged system directories.
pub fn ensure_no_reparse_points(path: &Path) -> Result<(), String> {
    use std::path::Component;

    if path.as_os_str().is_empty() {
        return Err("路径为空，已拒绝写入".into());
    }

    let components: Vec<Component<'_>> = path.components().collect();
    let mut cur = PathBuf::new();
    for (idx, comp) in components.iter().enumerate() {
        cur.push(comp.as_os_str());
        if matches!(comp, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let is_last = idx + 1 == components.len();
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "安全拦截：检测到符号链接路径（{}），已拒绝操作",
                        cur.display()
                    ));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                    if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                        return Err(format!(
                            "安全拦截：检测到 NTFS 重解析点/目录联接（{}），已拒绝操作",
                            cur.display()
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && is_last => {
                // Target file does not exist yet (first-time creation).
            }
            Err(e) => {
                return Err(format!("校验路径安全性失败（{}）：{e}", cur.display()));
            }
        }
    }
    Ok(())
}

fn next_temp_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut x = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (std::process::id() as u64);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(windows)]
fn apply_user_writable_acl_if_service(path: &Path) {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{w, PWSTR};
    use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    if !crate::access_win::is_session_zero() {
        return;
    }

    struct SdGuard(PSECURITY_DESCRIPTOR);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0.cast::<c_void>()));
                }
            }
        }
    }

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)"),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .is_err()
        {
            return;
        }
        let _sd_guard = SdGuard(sd);

        let mut dacl_present = BOOL(0);
        let mut dacl_ptr: *mut ACL = core::ptr::null_mut();
        let mut dacl_defaulted = BOOL(0);
        if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted)
            .is_err()
            || !dacl_present.as_bool()
        {
            return;
        }

        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let _ = SetNamedSecurityInfoW(
            PWSTR(wide_path.as_mut_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl_ptr.cast_const()),
            None,
        );
    }
}

#[cfg(not(windows))]
fn apply_user_writable_acl_if_service(_path: &Path) {}

fn atomic_write_verified_file(
    dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    use std::io::Write;

    ensure_no_reparse_points(dir)?;
    let target_path = dir.join(file_name);
    ensure_no_reparse_points(&target_path)?;

    let pid = std::process::id();
    let mut tmp_opt: Option<(PathBuf, std::fs::File)> = None;
    for _ in 0..8 {
        let candidate = dir.join(format!(
            "{file_name}.{pid}.{:016x}.cg-tmp",
            next_temp_nonce()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => {
                tmp_opt = Some((candidate, f));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("创建临时文件 {file_name} 失败：{e}")),
        }
    }
    let Some((tmp_path, mut tmp_file)) = tmp_opt else {
        return Err(format!("创建独占临时文件 {file_name} 失败：命名冲突"));
    };

    if let Err(e) = tmp_file.write_all(bytes).and_then(|()| tmp_file.sync_all()) {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("写入临时 {file_name} 失败：{e}"));
    }
    drop(tmp_file);

    ensure_no_reparse_points(&target_path)?;
    if let Err(rename_err) = std::fs::rename(&tmp_path, &target_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("替换 {file_name} 失败：{rename_err}"));
    }
    apply_user_writable_acl_if_service(&target_path);
    Ok(target_path)
}

/// Candidate DLL entry names across `yuaotian/antigravity-proxy` release layouts.
///
/// The IDE bundle ships `ide/version.dll`; the CLI bundle ships `cli/antigravity_proxy.dll`. Both
/// payloads are the same binary, so either layout is accepted. Matching is suffix-based, therefore
/// any subdirectory works.
const PROXY_DLL_ENTRY_CANDIDATES: &[&str] = &["version.dll", "antigravity_proxy.dll"];

/// Resolves the proxy DLL payload out of a release `.zip` asset.
///
/// Upstream publishes two zip flavours whose entry names differ (`version.dll` in the IDE bundle,
/// `antigravity_proxy.dll` in the CLI bundle), and GitHub returns whichever asset sorts first — so a
/// name-only lookup is fragile. Every candidate is therefore binary-validated before it is accepted,
/// and unrelated entries such as `cli/dbghelp.dll` can never be picked.
fn resolve_proxy_dll_from_zip(zip_bytes: &[u8]) -> Result<(String, Vec<u8>), String> {
    for candidate in PROXY_DLL_ENTRY_CANDIDATES {
        if let Ok((name, bytes)) = crate::zip_util::extract_file_from_zip(zip_bytes, candidate) {
            if validate_antigravity_proxy_dll_bytes(&bytes) {
                return Ok((name, bytes));
            }
        }
    }

    // Fallback for a future upstream rename: scan every `.dll` entry and keep the first one whose
    // bytes carry the antigravity-proxy signature.
    let Ok(entry_names) = crate::zip_util::list_entry_names(zip_bytes) else {
        return Err(format!(
            "ZIP 归档中未找到目标文件：{}（也无法读取归档目录）",
            PROXY_DLL_ENTRY_CANDIDATES[0]
        ));
    };

    for entry_name in &entry_names {
        let lower = entry_name.to_ascii_lowercase();
        if !lower.ends_with(".dll") {
            continue;
        }
        let already_tried = PROXY_DLL_ENTRY_CANDIDATES
            .iter()
            .any(|c| lower == *c || lower.ends_with(&format!("/{c}")));
        if already_tried {
            continue;
        }
        if let Ok((name, bytes)) = crate::zip_util::extract_file_from_zip(zip_bytes, entry_name) {
            if validate_antigravity_proxy_dll_bytes(&bytes) {
                return Ok((name, bytes));
            }
        }
    }

    let listed = entry_names
        .iter()
        .take(8)
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("、");
    let ellipsis = if entry_names.len() > 8 { " 等" } else { "" };
    Err(format!(
        "ZIP 归档中未找到可用的 antigravity-proxy DLL（已检查 {}，均未通过二进制特征校验；归档内容：{listed}{ellipsis}）",
        PROXY_DLL_ENTRY_CANDIDATES.join(" / ")
    ))
}

/// Validates and atomically installs `version.dll` (raw DLL or `.zip` containing the proxy DLL)
/// and synchronizes `config.json` (`proxy.port = proxy_port`, `child_injection = true`).
pub fn install_verified_proxy_bytes_into_dir(
    dir: &Path,
    raw_bytes: &[u8],
    is_zip: bool,
    proxy_port: u16,
    release_tag: &str,
) -> Result<AntigravityRepairReport, String> {
    ensure_no_reparse_points(dir)?;

    let dll_bytes = if is_zip {
        let (_name, bytes) = resolve_proxy_dll_from_zip(raw_bytes)?;
        bytes
    } else {
        raw_bytes.to_vec()
    };

    if !validate_antigravity_proxy_dll_bytes(&dll_bytes) {
        return Err(
            "下载的 version.dll 未通过 antigravity-proxy 二进制特征校验，已拒绝写入".into(),
        );
    }

    let compute_sha256_hex = |bytes: &[u8]| -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        let mut hex = String::with_capacity(64);
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        hex
    };

    // Symlink-safe atomic write `version.dll` via randomized `create_new(true)` sibling temp file.
    // When Antigravity is running, Windows locks the mapped `version.dll` image section against
    // rename/overwrite; if the on-disk `version.dll` is ALREADY a valid `antigravity-proxy` module,
    // keep it in place and hot-repair `config.json` without forcing a client restart.
    let existing_dll_path = dir.join("version.dll");
    let (dll_was_replaced, same_as_candidate, sha256_hex) =
        match atomic_write_verified_file(dir, "version.dll", &dll_bytes) {
            Ok(_) => (true, true, compute_sha256_hex(&dll_bytes)),
            Err(write_err) => {
                let existing_valid_bytes = ensure_no_reparse_points(&existing_dll_path)
                    .ok()
                    .and_then(|()| std::fs::metadata(&existing_dll_path).ok())
                    .filter(|m| m.is_file() && m.len() <= MAX_PROXY_DLL_BYTES)
                    .and_then(|_| std::fs::read(&existing_dll_path).ok())
                    .filter(|b| validate_antigravity_proxy_dll_bytes(b));
                match existing_valid_bytes {
                    Some(existing_bytes) => {
                        let same = existing_bytes == dll_bytes;
                        let hex = compute_sha256_hex(&existing_bytes);
                        (false, same, hex)
                    }
                    None => {
                        return Err(format!(
                            "{write_err}（若 Antigravity 正在运行，请先关闭客户端后重试）"
                        ));
                    }
                }
            }
        };

    // Preserve existing `config.json` fields while aligning `child_injection: true` & `proxy.port`.
    let cfg_path = dir.join("config.json");
    ensure_no_reparse_points(&cfg_path)?;
    let mut cfg_val: serde_json::Value = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .filter(|v: &serde_json::Value| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = cfg_val.as_object_mut() {
        if dll_was_replaced && !release_tag.trim().is_empty() {
            obj.insert(
                "_version".into(),
                serde_json::Value::String(release_tag.trim_start_matches(['v', 'V']).to_string()),
            );
        }
        obj.insert("child_injection".into(), serde_json::Value::Bool(true));
        let proxy_entry = obj
            .entry("proxy".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if !proxy_entry.is_object() {
            *proxy_entry = serde_json::json!({});
        }
        if let Some(pobj) = proxy_entry.as_object_mut() {
            pobj.entry("type".to_string())
                .or_insert_with(|| serde_json::Value::String("socks5".into()));
            pobj.entry("host".to_string())
                .or_insert_with(|| serde_json::Value::String("127.0.0.1".into()));
            pobj.insert(
                "port".into(),
                serde_json::Value::Number(serde_json::Number::from(proxy_port)),
            );
        }
    }
    let cfg_bytes =
        serde_json::to_vec_pretty(&cfg_val).map_err(|e| format!("序列化 config.json 失败：{e}"))?;
    atomic_write_verified_file(dir, "config.json", &cfg_bytes)?;

    process_win::invalidate_discovery_cache();

    let effective_release_tag = if dll_was_replaced || same_as_candidate {
        release_tag.to_string()
    } else {
        cfg_val
            .get("_version")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .or_else(|| process_win::read_pe_file_version(&existing_dll_path))
            .unwrap_or_default()
    };

    let sha_head = sha256_hex.get(..12).unwrap_or(&sha256_hex);
    let summary = if dll_was_replaced {
        format!(
            "已安装并验签 antigravity-proxy {release_tag}（SHA256 {sha_head}…），同步代理端口 :{proxy_port}"
        )
    } else {
        format!(
            "检测到有效 version.dll 正在运行占用，已免重启热修复 config.json 代理端口 :{proxy_port}（SHA256 {sha_head}…）"
        )
    };
    Ok(AntigravityRepairReport {
        install_dir: dir.to_path_buf(),
        release_tag: effective_release_tag,
        sha256_hex,
        proxy_port,
        summary,
    })
}

/// Parse a proxy address string (`"http://127.0.0.1:7890"`, `"socks5h://host:10808/"`, `"user:pass@host:port"`)
/// into `(host, port)`, stripping any leading scheme, credentials, and trailing `/` to prevent `http://http://...`.
fn parse_proxy_route_addr(addr: &str, fallback_port: u16) -> (&str, u16) {
    let mut s = addr.trim();
    loop {
        let matched = ["socks5h://", "socks5://", "https://", "http://"]
            .into_iter()
            .find(|scheme| {
                s.as_bytes()
                    .get(..scheme.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(scheme.as_bytes()))
            });
        if let Some(scheme) = matched {
            s = s.get(scheme.len()..).unwrap_or("").trim_start();
        } else {
            break;
        }
    }
    s = s.split('/').next().unwrap_or("").trim();
    if let Some((_, after_at)) = s.rsplit_once('@') {
        s = after_at.trim();
    }

    if s.starts_with('[') {
        if let Some((bracketed, port_str)) = s.rsplit_once(':') {
            if bracketed.ends_with(']') {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    if port > 0 {
                        return (bracketed.trim(), port);
                    }
                }
                return (bracketed.trim(), fallback_port);
            }
        }
        return (s, fallback_port);
    }

    if let Some((h, p)) = s.rsplit_once(':') {
        let h_trim = h.trim();
        if !h_trim.contains(':') {
            if let Ok(port) = p.trim().parse::<u16>() {
                if port > 0 && !h_trim.is_empty() {
                    return (h_trim, port);
                }
            }
            if !h_trim.is_empty() && p.trim().is_empty() {
                return (h_trim, fallback_port);
            }
        }
    }

    let host = if s.is_empty() { "127.0.0.1" } else { s };
    (host, fallback_port)
}

/// Resolves the Antigravity install directory that owns the proxy DLL: an explicit override,
/// else the first detected installation, else the first covered directory.
pub fn resolve_antigravity_dir(explicit_dir: Option<&Path>) -> Result<PathBuf, String> {
    match explicit_dir {
        Some(d) => Ok(d.to_path_buf()),
        None => {
            let dirs = process_win::antigravity_covered_dirs();
            pick_installed_antigravity_dir(&dirs)
                .cloned()
                .or_else(|| dirs.into_iter().next())
                .ok_or_else(|| "本机未检测到 Antigravity 安装目录，无法执行热修复注入".to_string())
        }
    }
}

/// One-click verified hot re-injector: fetches latest `yuaotian/antigravity-proxy` release asset
/// strictly through `NetworkPolicy` (never falls back to direct when proxy configured), verifies
/// `version.dll` binary signature, and atomically repairs `<AntigravityDir>\version.dll` + `config.json`.
pub fn repair_antigravity_proxy(
    route: &crate::probe_http::ProbeRoute,
    proxy_port: u16,
    explicit_dir: Option<&Path>,
) -> Result<AntigravityRepairReport, String> {
    let dir = resolve_antigravity_dir(explicit_dir)?;

    let policy = match route {
        crate::probe_http::ProbeRoute::Proxy(addr) => {
            let (host, port) = parse_proxy_route_addr(addr, proxy_port);
            crate::probe_http::NetworkPolicy::with_proxy(host, port)
        }
        crate::probe_http::ProbeRoute::Direct => crate::probe_http::NetworkPolicy::direct(),
        crate::probe_http::ProbeRoute::Skip(reason) => {
            return Err(format!("当前代理通道不可用，已阻止直连下载：{reason}"));
        }
    };

    let release = crate::update_check::fetch_github_latest_release(
        route,
        crate::update_check::ANTIGRAVITY_PROXY_REPO,
        &[".zip", ".dll"],
        std::time::Duration::from_secs(15),
    )
    .map_err(|e| format!("获取 antigravity-proxy 最新版本失败：{e}"))?;

    let asset_url = release
        .asset_url
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "最新 Release 未包含可下载的 Windows 注入包资产".to_string())?;

    let mut downloaded = Vec::new();
    crate::probe_http::download_release_asset(
        &policy,
        asset_url,
        None,
        32 * 1024 * 1024,
        std::time::Duration::from_secs(45),
        &mut downloaded,
        &mut |_, _| {},
    )
    .map_err(|e| format!("下载 antigravity-proxy 资产失败：{e}"))?;

    let is_zip =
        asset_url.to_ascii_lowercase().ends_with(".zip") || downloaded.starts_with(b"PK\x03\x04");
    install_verified_proxy_bytes_into_dir(&dir, &downloaded, is_zip, proxy_port, &release.version)
}

/// Cache file holding the last verified antigravity-proxy DLL.
pub fn proxy_dll_cache_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("version.dll")
}

/// Repairs the injection preferring a previously verified DLL from `cache_dir`, so an Antigravity
/// self-update does not force another release download; refreshes the cache after a download.
pub fn repair_antigravity_proxy_cached(
    route: &crate::probe_http::ProbeRoute,
    proxy_port: u16,
    explicit_dir: Option<&Path>,
    cache_dir: &Path,
) -> Result<AntigravityRepairReport, String> {
    let dir = resolve_antigravity_dir(explicit_dir)?;
    let cache_file = proxy_dll_cache_path(cache_dir);
    if let Ok(bytes) = std::fs::read(&cache_file) {
        if validate_antigravity_proxy_dll_bytes(&bytes) {
            let tag = std::fs::read_to_string(cache_dir.join("release_tag.txt"))
                .map(|s| s.trim().to_string())
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "cache".to_string());
            // A validated cache entry is byte-identical to what a download would yield, so a
            // failed install means the target is locked; retrying over the network cannot help.
            return install_verified_proxy_bytes_into_dir(&dir, &bytes, false, proxy_port, &tag);
        }
    }

    let report = repair_antigravity_proxy(route, proxy_port, Some(&dir))?;
    let _ = cache_proxy_dll_from_dir(&dir, cache_dir, &report.release_tag);
    Ok(report)
}

/// Copies the installed (already verified) `version.dll` into `cache_dir` so a later injection can
/// be repaired without network access. Returns whether the cache now holds a verified DLL.
pub fn cache_proxy_dll_from_dir(install_dir: &Path, cache_dir: &Path, release_tag: &str) -> bool {
    let Ok(bytes) = std::fs::read(install_dir.join("version.dll")) else {
        return false;
    };
    if !validate_antigravity_proxy_dll_bytes(&bytes) || std::fs::create_dir_all(cache_dir).is_err()
    {
        return false;
    }
    if atomic_write_verified_file(cache_dir, "version.dll", &bytes).is_err() {
        return false;
    }
    let tag = release_tag.trim();
    if !tag.is_empty() {
        let _ = std::fs::write(cache_dir.join("release_tag.txt"), tag.as_bytes());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_proxy_dll_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 40 * 1024];
        buf[0] = b'M';
        buf[1] = b'Z';
        let marker = b"Antigravity-Proxy v2.6.3 config.json child_injection socks5";
        buf[512..512 + marker.len()].copy_from_slice(marker);
        buf
    }

    fn synthetic_system_version_dll_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 56 * 1024];
        buf[0] = b'M';
        buf[1] = b'Z';
        let marker = b"Microsoft Windows Operating System GetFileVersionInfoW";
        buf[256..256 + marker.len()].copy_from_slice(marker);
        buf
    }

    #[test]
    fn zip_install_accepts_cli_bundle_layout_with_antigravity_proxy_dll() {
        let dll = synthetic_proxy_dll_bytes();
        let archive = crate::zip_util::build_zip_archive(&[
            ("cli/agy-acp-proxy.exe", b"MZ-cli-launcher".as_slice()),
            ("cli/config.json", b"{}".as_slice()),
            ("cli/dbghelp.dll", b"MZ-dbghelp-not-a-proxy".as_slice()),
            ("cli/antigravity_proxy.dll", dll.as_slice()),
        ])
        .expect("build cli-layout zip");

        let dir = unique_temp_dir("cli-layout-install");
        let rep = install_verified_proxy_bytes_into_dir(&dir, &archive, true, 7890, "v2.6.6")
            .expect("cli bundle layout must install version.dll");
        assert_eq!(rep.proxy_port, 7890);
        assert_eq!(std::fs::read(dir.join("version.dll")).unwrap(), dll);

        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(cfg["_version"], "2.6.6");
        assert_eq!(cfg["child_injection"], true);
        assert_eq!(cfg["proxy"]["port"], 7890);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zip_install_prefers_version_dll_entry_over_other_dll_entries() {
        let version_bytes = synthetic_proxy_dll_bytes();
        let mut decoy = version_bytes.clone();
        decoy[1024] = b'X';
        let archive = crate::zip_util::build_zip_archive(&[
            ("ide/antigravity_proxy.dll", decoy.as_slice()),
            ("ide/version.dll", version_bytes.as_slice()),
        ])
        .expect("build ide-layout zip");

        let dir = unique_temp_dir("ide-layout-install");
        install_verified_proxy_bytes_into_dir(&dir, &archive, true, 7890, "v2.6.6")
            .expect("ide bundle layout must install version.dll");
        assert_eq!(
            std::fs::read(dir.join("version.dll")).unwrap(),
            version_bytes
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zip_install_reports_archive_contents_when_no_proxy_dll_matches() {
        let archive = crate::zip_util::build_zip_archive(&[
            ("launcher/start.exe", b"MZ-launcher".as_slice()),
            ("cli/dbghelp.dll", b"MZ-dbghelp".as_slice()),
        ])
        .expect("build dll-less zip");

        let dir = unique_temp_dir("no-proxy-dll");
        let err = install_verified_proxy_bytes_into_dir(&dir, &archive, true, 7890, "v2.6.6")
            .expect_err("must reject an archive without the proxy dll");
        assert!(
            err.contains("dbghelp.dll"),
            "error should list archive entries: {err}"
        );
        assert!(
            err.contains("version.dll"),
            "error should name the expected file: {err}"
        );
        assert!(!dir.join("version.dll").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn valid_config_json(port: u16, child_injection: bool) -> String {
        format!(
            r#"{{
                "_version": "2.6.3",
                "child_injection": {child_injection},
                "proxy": {{
                    "type": "socks5",
                    "host": "127.0.0.1",
                    "port": {port}
                }}
            }}"#
        )
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "cg-ag-proxy-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn dll_signature_distinguishes_proxy_dll_from_microsoft_system_dll() {
        assert!(validate_antigravity_proxy_dll_bytes(
            &synthetic_proxy_dll_bytes()
        ));
        assert!(!validate_antigravity_proxy_dll_bytes(
            &synthetic_system_version_dll_bytes()
        ));
        // Too small (< 32 KiB)
        assert!(!validate_antigravity_proxy_dll_bytes(
            &synthetic_proxy_dll_bytes()[..16 * 1024]
        ));
        // Missing MZ header
        let mut no_mz = synthetic_proxy_dll_bytes();
        no_mz[0] = b'P';
        assert!(!validate_antigravity_proxy_dll_bytes(&no_mz));
    }

    #[test]
    fn inspect_in_dir_reports_healthy_static_and_runtime_hooked() {
        let dir = unique_temp_dir("healthy");
        std::fs::write(dir.join("version"), "44.9.1\n").unwrap();
        std::fs::write(dir.join("version.dll"), synthetic_proxy_dll_bytes()).unwrap();
        std::fs::write(dir.join("config.json"), valid_config_json(7890, true)).unwrap();

        // Static ready (not running)
        let st_idle = inspect_antigravity_proxy_in_dir(
            &dir,
            7890,
            Some("44.9.1"),
            &[],
            &[],
            |_, _| false,
            99,
        );
        assert_eq!(st_idle.state, AntigravityProxyState::Healthy);
        assert!(st_idle.installed);
        assert_eq!(st_idle.antigravity_version.as_deref(), Some("44.9.1"));
        assert!(st_idle.version_changed_from.is_none());
        assert!(st_idle.dll_present && st_idle.dll_valid);
        assert_eq!(st_idle.injector_version.as_deref(), Some("2.6.3"));
        assert_eq!(st_idle.proxy_port, Some(7890));
        assert!(st_idle.port_matches_guard);
        assert!(!st_idle.runtime_running);
        assert!(st_idle.is_ready_for_launch());

        // Live runtime hooked on both main & language_server
        let st_live = inspect_antigravity_proxy_in_dir(
            &dir,
            7890,
            Some("44.9.1"),
            &[100],
            &[200, 201],
            |_pid, dll| dll.ends_with("version.dll"),
            100,
        );
        assert_eq!(st_live.state, AntigravityProxyState::Healthy);
        assert!(st_live.runtime_running);
        assert!(st_live.runtime_dll_loaded_main);
        assert!(st_live.runtime_dll_loaded_ls);
        assert!(st_live.summary.contains("v2.6.3 注入生效"));
        assert!(st_live.summary.contains("language_server 内存已挂载"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inspect_in_dir_detects_missing_dll_after_client_upgrade() {
        let dir = unique_temp_dir("upgrade-wipe");
        std::fs::write(dir.join("version"), "45.0.0").unwrap();
        // No version.dll (wiped by Antigravity installer update!)
        std::fs::write(dir.join("config.json"), valid_config_json(7890, true)).unwrap();

        let st = inspect_antigravity_proxy_in_dir(
            &dir,
            7890,
            Some("44.9.1"),
            &[],
            &[],
            |_, _| false,
            50,
        );
        assert_eq!(st.state, AntigravityProxyState::MissingDll);
        assert!(!st.dll_present);
        assert!(!st.dll_valid);
        assert_eq!(st.antigravity_version.as_deref(), Some("45.0.0"));
        assert_eq!(st.version_changed_from.as_deref(), Some("44.9.1"));
        assert!(!st.is_ready_for_launch());
        assert!(st.summary.contains("44.9.1") && st.summary.contains("45.0.0"));

        // Also test bogus/system version.dll copied by mistake
        std::fs::write(
            dir.join("version.dll"),
            synthetic_system_version_dll_bytes(),
        )
        .unwrap();
        let st_bad = inspect_antigravity_proxy_in_dir(
            &dir,
            7890,
            Some("45.0.0"),
            &[],
            &[],
            |_, _| false,
            51,
        );
        assert_eq!(st_bad.state, AntigravityProxyState::MissingDll);
        assert!(st_bad.dll_present);
        assert!(!st_bad.dll_valid);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inspect_in_dir_detects_invalid_config_port_mismatch_and_runtime_unhooked() {
        let dir = unique_temp_dir("states");
        std::fs::write(dir.join("version"), "44.9.1").unwrap();
        std::fs::write(dir.join("version.dll"), synthetic_proxy_dll_bytes()).unwrap();

        // 1. Missing config.json -> MissingOrInvalidConfig
        let st_no_cfg =
            inspect_antigravity_proxy_in_dir(&dir, 7890, None, &[], &[], |_, _| false, 10);
        assert_eq!(
            st_no_cfg.state,
            AntigravityProxyState::MissingOrInvalidConfig
        );

        // 2. child_injection == false -> MissingOrInvalidConfig
        std::fs::write(dir.join("config.json"), valid_config_json(7890, false)).unwrap();
        let st_no_child =
            inspect_antigravity_proxy_in_dir(&dir, 7890, None, &[], &[], |_, _| false, 11);
        assert_eq!(
            st_no_child.state,
            AntigravityProxyState::MissingOrInvalidConfig
        );
        assert_eq!(st_no_child.child_injection, Some(false));

        // 3. Port mismatch (config=10808 vs guard=7890) -> PortMismatch
        std::fs::write(dir.join("config.json"), valid_config_json(10808, true)).unwrap();
        let st_port =
            inspect_antigravity_proxy_in_dir(&dir, 7890, None, &[], &[], |_, _| false, 12);
        assert_eq!(st_port.state, AntigravityProxyState::PortMismatch);
        assert!(!st_port.port_matches_guard);
        // expected_proxy_port == 0 accepts any valid non-zero port
        let st_port_any =
            inspect_antigravity_proxy_in_dir(&dir, 0, None, &[], &[], |_, _| false, 13);
        assert_eq!(st_port_any.state, AntigravityProxyState::Healthy);

        // 4. RuntimeUnhooked when language_server PID does not have <dir>\version.dll loaded
        std::fs::write(dir.join("config.json"), valid_config_json(7890, true)).unwrap();
        let st_unhooked_ls = inspect_antigravity_proxy_in_dir(
            &dir,
            7890,
            None,
            &[100],
            &[200, 201],
            |pid, _| pid != 201, // second language_server is unhooked!
            14,
        );
        assert_eq!(st_unhooked_ls.state, AntigravityProxyState::RuntimeUnhooked);
        assert!(st_unhooked_ls.runtime_dll_loaded_main);
        assert!(!st_unhooked_ls.runtime_dll_loaded_ls);

        // 5. RuntimeUnhooked when only main PID is running and lacks <dir>\version.dll
        let st_unhooked_main =
            inspect_antigravity_proxy_in_dir(&dir, 7890, None, &[100], &[], |_, _| false, 15);
        assert_eq!(
            st_unhooked_main.state,
            AntigravityProxyState::RuntimeUnhooked
        );

        // 6. Missing directory -> NotInstalled
        let st_missing = inspect_antigravity_proxy_in_dir(
            &dir.join("does-not-exist"),
            7890,
            None,
            &[],
            &[],
            |_, _| false,
            16,
        );
        assert_eq!(st_missing.state, AntigravityProxyState::NotInstalled);
        assert!(!st_missing.installed);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_toolhelp32_module_inspection_on_self_process_is_accurate() {
        let self_pid = std::process::id();
        let self_exe = std::env::current_exe().unwrap();
        assert!(is_process_still_alive(self_pid));
        assert!(!is_process_still_alive(0));
        assert!(is_module_loaded_in_process(self_pid, &self_exe));
        assert!(!is_module_loaded_in_process(
            self_pid,
            Path::new(r"C:\DefinitelyMissing\antigravity\version.dll")
        ));
        assert!(!is_module_loaded_in_process(0, &self_exe));
    }

    #[test]
    fn repair_proxy_url_parsing_strips_schemes_and_prevents_double_http() {
        assert_eq!(
            parse_proxy_route_addr("http://127.0.0.1:7890", 10808),
            ("127.0.0.1", 7890)
        );
        assert_eq!(
            parse_proxy_route_addr("HTTP://http://198.51.100.10:7897/", 7890),
            ("198.51.100.10", 7897)
        );
        assert_eq!(
            parse_proxy_route_addr("https://203.0.113.25:8443/pac", 7890),
            ("203.0.113.25", 8443)
        );
        assert_eq!(
            parse_proxy_route_addr("socks5://198.51.100.42:10808/", 7890),
            ("198.51.100.42", 10808)
        );
        assert_eq!(
            parse_proxy_route_addr("socks5h://203.0.113.99:10809/", 7890),
            ("203.0.113.99", 10809)
        );
        assert_eq!(
            parse_proxy_route_addr("198.51.100.77", 7890),
            ("198.51.100.77", 7890)
        );
        assert_eq!(parse_proxy_route_addr("[::1]:7890", 1080), ("[::1]", 7890));
        assert_eq!(
            parse_proxy_route_addr("http://alice:p@ss:w0rd@127.0.0.1:7897/", 1080),
            ("127.0.0.1", 7897)
        );
        assert_eq!(
            parse_proxy_route_addr("socks5://user:sec@[::1]:10808/", 7890),
            ("[::1]", 10808)
        );

        // End-to-end check with NetworkPolicy::with_proxy -> never produces http://http://
        let (h, p) = parse_proxy_route_addr("http://198.51.100.10:7890/", 7890);
        assert_eq!(
            crate::probe_http::NetworkPolicy::with_proxy(h, p).route(),
            crate::probe_http::Route::Proxy("http://198.51.100.10:7890".into())
        );

        // Verify atomic randomized install & ensure_no_reparse_points
        let install_dir = unique_temp_dir("atomic-install");
        let rep = install_verified_proxy_bytes_into_dir(
            &install_dir,
            &synthetic_proxy_dll_bytes(),
            false,
            7890,
            "v2.6.3",
        )
        .expect("verified atomic install");
        assert_eq!(rep.proxy_port, 7890);
        assert!(install_dir.join("version.dll").is_file());
        assert!(install_dir.join("config.json").is_file());
        assert!(ensure_no_reparse_points(&install_dir.join("version.dll")).is_ok());
        std::fs::remove_dir_all(&install_dir).unwrap();

        // Verify pick_installed_antigravity_dir skips empty candidate and selects real install dir
        let empty_cand = unique_temp_dir("empty-cand");
        let real_cand = unique_temp_dir("real-cand");
        std::fs::write(real_cand.join("Antigravity.exe"), b"MZ").unwrap();
        let candidates = vec![empty_cand.clone(), real_cand.clone()];
        assert_eq!(
            pick_installed_antigravity_dir(&candidates),
            Some(&real_cand)
        );
        std::fs::remove_dir_all(&empty_cand).unwrap();
        std::fs::remove_dir_all(&real_cand).unwrap();
    }

    #[test]
    fn cached_dll_reinstalls_without_release_download() {
        let install_dir = unique_temp_dir("cache-install");
        let cache_dir = unique_temp_dir("cache-store");
        let bytes = synthetic_proxy_dll_bytes();
        std::fs::write(cache_dir.join("version.dll"), &bytes).unwrap();
        std::fs::write(cache_dir.join("release_tag.txt"), b"v2.6.6").unwrap();

        // Skip route would refuse a download, so a successful repair proves the cache was used.
        let report = repair_antigravity_proxy_cached(
            &crate::probe_http::ProbeRoute::Skip("未开启系统代理且未检测到 TUN 网卡".into()),
            7891,
            Some(&install_dir),
            &cache_dir,
        )
        .expect("cached install");
        assert_eq!(report.proxy_port, 7891);
        assert_eq!(report.release_tag, "v2.6.6");
        assert_eq!(
            std::fs::read(install_dir.join("version.dll")).unwrap(),
            bytes
        );
        let cfg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(install_dir.join("config.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(cfg["child_injection"], serde_json::json!(true));
        assert_eq!(cfg["proxy"]["port"], serde_json::json!(7891));
        assert_eq!(cfg["_version"], serde_json::json!("2.6.6"));
        std::fs::remove_dir_all(&install_dir).unwrap();
        std::fs::remove_dir_all(&cache_dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn locked_valid_version_dll_hot_repairs_config_json_while_locked_invalid_dll_errors() {
        use sha2::{Digest, Sha256};
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x0000_0001;

        // 1. Valid `version.dll` locked without `FILE_SHARE_DELETE` + wrong port `1080` in `config.json`:
        //    `install_verified_proxy_bytes_into_dir` must hot-repair `config.json` to `7890`.
        let valid_dir = unique_temp_dir("locked-valid-dll");
        let existing_dll = synthetic_proxy_dll_bytes();
        let mut candidate_dll = existing_dll.clone();
        candidate_dll[2048] = b'N';

        let valid_dll_path = valid_dir.join("version.dll");
        std::fs::write(&valid_dll_path, &existing_dll).unwrap();
        std::fs::write(
            valid_dir.join("config.json"),
            valid_config_json(1080, false),
        )
        .unwrap();

        let lock_valid = std::fs::File::options()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&valid_dll_path)
            .expect("open locked valid version.dll");

        let report = install_verified_proxy_bytes_into_dir(
            &valid_dir,
            &candidate_dll,
            false,
            7890,
            "v2.7.0",
        )
        .expect("locked valid version.dll should allow lock-free config.json hot repair");

        assert_eq!(report.proxy_port, 7890);
        assert!(
            report
                .summary
                .contains("免重启热修复 config.json 代理端口 :7890"),
            "unexpected summary: {}",
            report.summary
        );

        let expected_sha = {
            let digest = Sha256::digest(&existing_dll);
            let mut hex = String::with_capacity(64);
            for b in digest {
                hex.push_str(&format!("{b:02x}"));
            }
            hex
        };
        assert_eq!(report.sha256_hex, expected_sha);
        assert_eq!(std::fs::read(&valid_dll_path).unwrap(), existing_dll);

        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(valid_dir.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(cfg["proxy"]["port"], serde_json::json!(7890));
        assert_eq!(cfg["child_injection"], serde_json::json!(true));
        assert_eq!(cfg["_version"], serde_json::json!("2.6.3"));

        drop(lock_valid);
        std::fs::remove_dir_all(&valid_dir).unwrap();

        // 2. Invalid/system `version.dll` locked without `FILE_SHARE_DELETE`:
        //    must fail with the close-client hint and must NOT silently succeed.
        let invalid_dir = unique_temp_dir("locked-invalid-dll");
        let invalid_dll_path = invalid_dir.join("version.dll");
        std::fs::write(&invalid_dll_path, synthetic_system_version_dll_bytes()).unwrap();
        std::fs::write(
            invalid_dir.join("config.json"),
            valid_config_json(1080, true),
        )
        .unwrap();

        let lock_invalid = std::fs::File::options()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&invalid_dll_path)
            .expect("open locked invalid version.dll");

        let err = install_verified_proxy_bytes_into_dir(
            &invalid_dir,
            &candidate_dll,
            false,
            7890,
            "v2.7.0",
        )
        .expect_err("locked invalid version.dll must fail");
        assert!(
            err.contains("请先关闭客户端后重试"),
            "error must contain close-client hint: {err}"
        );

        drop(lock_invalid);
        std::fs::remove_dir_all(&invalid_dir).unwrap();
    }
}
