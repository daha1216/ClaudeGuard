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
    use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

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
        let _ = CloseHandle(snap);
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
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const STILL_ACTIVE_CODE: u32 = 259;

    if pid == 0 {
        return false;
    }
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut code: u32 = 0;
        let alive = GetExitCodeProcess(handle, &mut code).is_ok() && code == STILL_ACTIVE_CODE;
        let _ = CloseHandle(handle);
        alive
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

/// Validates and atomically installs `version.dll` (raw DLL or `.zip` containing `version.dll`)
/// and synchronizes `config.json` (`proxy.port = proxy_port`, `child_injection = true`).
pub fn install_verified_proxy_bytes_into_dir(
    dir: &Path,
    raw_bytes: &[u8],
    is_zip: bool,
    proxy_port: u16,
    release_tag: &str,
) -> Result<AntigravityRepairReport, String> {
    let dll_bytes = if is_zip {
        let (_name, bytes) = crate::zip_util::extract_file_from_zip(raw_bytes, "version.dll")?;
        bytes
    } else {
        raw_bytes.to_vec()
    };

    if !validate_antigravity_proxy_dll_bytes(&dll_bytes) {
        return Err(
            "下载的 version.dll 未通过 antigravity-proxy 二进制特征校验，已拒绝写入".into(),
        );
    }

    // Compute SHA-256 of verified DLL bytes for audit trail
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&dll_bytes);
    let mut sha256_hex = String::with_capacity(64);
    for b in digest {
        sha256_hex.push_str(&format!("{b:02x}"));
    }

    // Atomic write `version.dll` via sibling temp file
    let dll_path = dir.join("version.dll");
    let tmp_dll = dir.join("version.dll.cg-tmp");
    std::fs::write(&tmp_dll, &dll_bytes)
        .map_err(|e| format!("写入临时 version.dll 失败：{e}"))?;
    if let Err(rename_err) = std::fs::rename(&tmp_dll, &dll_path) {
        let _ = std::fs::remove_file(&tmp_dll);
        return Err(format!(
            "替换 version.dll 失败（请先关闭正在运行的 Antigravity 客户端后重试）：{rename_err}"
        ));
    }

    // Preserve existing `config.json` fields while aligning `child_injection: true` & `proxy.port`.
    let cfg_path = dir.join("config.json");
    let mut cfg_val: serde_json::Value = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .filter(|v: &serde_json::Value| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = cfg_val.as_object_mut() {
        if !release_tag.trim().is_empty() {
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
    let tmp_cfg = dir.join("config.json.cg-tmp");
    std::fs::write(&tmp_cfg, &cfg_bytes)
        .map_err(|e| format!("写入临时 config.json 失败：{e}"))?;
    std::fs::rename(&tmp_cfg, &cfg_path).map_err(|e| format!("替换 config.json 失败：{e}"))?;

    Ok(AntigravityRepairReport {
        install_dir: dir.to_path_buf(),
        release_tag: release_tag.to_string(),
        sha256_hex: sha256_hex.clone(),
        proxy_port,
        summary: format!(
            "已安装并验签 antigravity-proxy {release_tag}（SHA256 {}…），同步代理端口 :{proxy_port}",
            &sha256_hex[..12]
        ),
    })
}

/// One-click verified hot re-injector: fetches latest `yuaotian/antigravity-proxy` release asset
/// strictly through `NetworkPolicy` (never falls back to direct when proxy configured), verifies
/// `version.dll` binary signature, and atomically repairs `<AntigravityDir>\version.dll` + `config.json`.
pub fn repair_antigravity_proxy(
    route: &crate::probe_http::ProbeRoute,
    proxy_port: u16,
    explicit_dir: Option<&Path>,
) -> Result<AntigravityRepairReport, String> {
    let dir = match explicit_dir {
        Some(d) => d.to_path_buf(),
        None => {
            let dirs = process_win::antigravity_covered_dirs();
            dirs.into_iter()
                .next()
                .ok_or_else(|| "本机未检测到 Antigravity 安装目录，无法执行热修复注入".to_string())?
        }
    };

    let policy = match route {
        crate::probe_http::ProbeRoute::Proxy(addr) => {
            let (host, port) = addr
                .rsplit_once(':')
                .and_then(|(h, p)| p.parse::<u16>().ok().map(|port| (h, port)))
                .unwrap_or(("127.0.0.1", proxy_port));
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

    let is_zip = asset_url.to_ascii_lowercase().ends_with(".zip")
        || downloaded.starts_with(b"PK\x03\x04");
    install_verified_proxy_bytes_into_dir(
        &dir,
        &downloaded,
        is_zip,
        proxy_port,
        &release.version,
    )
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
}
