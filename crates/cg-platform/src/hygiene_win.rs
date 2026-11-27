//! M3: Zero-WMI Electron/Chromium command-line auditor (`NtQueryInformationProcess(60)`)
//! and 100% byte-reversible `IShellLinkW` shortcut hygiene patcher with SHA-256 backup
//! and full ancestor reparse-point protection.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use cg_protocol::ElectronHygieneReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::traits::{PlatformError, PlatformResult};

/// Parsed Chromium/Electron anti-leak hygiene flags from a live process command line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParsedElectronFlags {
    pub webrtc_flag_enforced: bool,
    pub quic_disabled_flag: bool,
    pub host_resolver_enforced: bool,
}

impl ParsedElectronFlags {
    /// Whether baseline WebRTC UDP + QUIC leak protections are both present.
    pub fn baseline_protected(self) -> bool {
        self.webrtc_flag_enforced && self.quic_disabled_flag
    }
}

/// Inspect a raw process command line for Chromium/Electron anti-leak hygiene switches.
pub fn inspect_electron_cmdline(cmdline: &str) -> ParsedElectronFlags {
    let low = cmdline.to_ascii_lowercase();
    let webrtc_flag_enforced = low
        .contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        || low.contains("--force-webrtc-ip-handling-policy=\"disable_non_proxied_udp\"")
        || low.contains("--force-webrtc-ip-handling-policy='disable_non_proxied_udp'");

    let quic_disabled_flag = low.split_whitespace().any(|tok| {
        let clean = tok.trim_matches(['"', '\'']);
        clean == "--disable-quic"
    });

    let host_resolver_enforced = low.contains("--host-resolver-rules=");

    ParsedElectronFlags {
        webrtc_flag_enforced,
        quic_disabled_flag,
        host_resolver_enforced,
    }
}

/// Pure aggregator converting observed `(agent_id, pid, Option<cmdline>)` tuples into an
/// `ElectronHygieneReport`.
pub fn evaluate_electron_hygiene_from_cmdlines(
    observed: &[(String, u32, Option<String>)],
    now_secs: u64,
) -> ElectronHygieneReport {
    if observed.is_empty() {
        return ElectronHygieneReport {
            checked_at: now_secs,
            webrtc_flag_enforced: true,
            quic_disabled_flag: true,
            host_resolver_enforced: true,
            unguarded_running_agents: Vec::new(),
            summary: "当前未检测到运行中的 Electron 客户端进程".to_string(),
        };
    }

    let mut all_webrtc = true;
    let mut all_quic = true;
    let mut all_host_resolver = true;
    let mut unguarded: Vec<String> = Vec::new();
    let mut seen_unguarded: HashSet<String> = HashSet::new();
    let mut readable_count = 0usize;

    for (agent_id, _pid, cmd_opt) in observed {
        match cmd_opt {
            Some(cmd) => {
                readable_count += 1;
                let flags = inspect_electron_cmdline(cmd);
                if !flags.webrtc_flag_enforced {
                    all_webrtc = false;
                }
                if !flags.quic_disabled_flag {
                    all_quic = false;
                }
                if !flags.host_resolver_enforced {
                    all_host_resolver = false;
                }
                if !flags.baseline_protected() {
                    let key = agent_id.to_ascii_lowercase();
                    if seen_unguarded.insert(key) {
                        unguarded.push(agent_id.clone());
                    }
                }
            }
            None => {
                all_webrtc = false;
                all_quic = false;
                all_host_resolver = false;
                let key = agent_id.to_ascii_lowercase();
                if seen_unguarded.insert(key) {
                    unguarded.push(agent_id.clone());
                }
            }
        }
    }

    let summary = if unguarded.is_empty() {
        format!("已核验 {readable_count} 个运行中客户端进程，WebRTC 与 QUIC 防漏参数均已生效")
    } else {
        format!(
            "检测到 {} 未启用完整 Electron 防漏参数（缺少 WebRTC UDP 锁或 --disable-quic），建议通过安全启动台拉起",
            unguarded.join("、")
        )
    };

    ElectronHygieneReport {
        checked_at: now_secs,
        webrtc_flag_enforced: all_webrtc,
        quic_disabled_flag: all_quic,
        host_resolver_enforced: all_host_resolver,
        unguarded_running_agents: unguarded,
        summary,
    }
}

/// Zero-WMI, minimal-privilege (`PROCESS_QUERY_LIMITED_INFORMATION` only) live command-line reader
/// backed by `ntdll!NtQueryInformationProcess(ProcessCommandLineInformation = 60)`.
#[cfg(windows)]
pub fn query_process_command_line_fast(pid: u32) -> PlatformResult<String> {
    use core::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
    const STATUS_BUFFER_TOO_SMALL: i32 = -1073741789i32; // 0xC0000023
    const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820i32; // 0xC0000004

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: HANDLE,
            process_information_class: i32,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() && !self.0 .0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| PlatformError::AccessDenied(format!("OpenProcess({pid}): {e}")))?;
    let _guard = HandleGuard(handle);

    let mut needed: u32 = 0;
    let st = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            core::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if st != STATUS_BUFFER_TOO_SMALL && st != STATUS_INFO_LENGTH_MISMATCH && st < 0 {
        return Err(PlatformError::Io(format!(
            "NtQueryInformationProcess(60) probe failed: 0x{:08X}",
            st as u32
        )));
    }

    let cap = (needed as usize).clamp(512, 65_536);
    let words = cap.div_ceil(8);
    let mut buf: Vec<u64> = vec![0u64; words];
    let buf_byte_len = buf.len() * core::mem::size_of::<u64>();
    let st2 = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast(),
            buf_byte_len as u32,
            &mut needed,
        )
    };
    if st2 < 0 {
        return Err(PlatformError::Io(format!(
            "NtQueryInformationProcess(60) read failed: 0x{:08X}",
            st2 as u32
        )));
    }

    if buf_byte_len < core::mem::size_of::<UNICODE_STRING>() {
        return Ok(String::new());
    }
    let ustr = unsafe { &*buf.as_ptr().cast::<UNICODE_STRING>() };
    if ustr.Length == 0 || ustr.Buffer.is_null() {
        return Ok(String::new());
    }
    let unit_len = (ustr.Length as usize) / 2;
    let byte_len = unit_len * 2;
    let buf_start = buf.as_ptr() as usize;
    let buf_end = buf_start.saturating_add(buf_byte_len);
    let str_start = ustr.Buffer.0 as usize;
    let str_end = str_start.saturating_add(byte_len);
    if str_start < buf_start || str_end > buf_end || !(str_start - buf_start).is_multiple_of(2) {
        return Err(PlatformError::Io(
            "NtQueryInformationProcess(60) returned out-of-bounds UNICODE_STRING".to_string(),
        ));
    }

    let slice = unsafe { core::slice::from_raw_parts(ustr.Buffer.0, unit_len) };
    Ok(String::from_utf16_lossy(slice))
}

#[cfg(not(windows))]
pub fn query_process_command_line_fast(_pid: u32) -> PlatformResult<String> {
    Err(PlatformError::unsupported(
        "electron_hygiene",
        "NtQueryInformationProcess(60) is only supported on Windows",
    ))
}

/// Audit a list of running `(agent_id, pid)` targets via `NtQueryInformationProcess(60)`,
/// falling back gracefully on `AccessDenied` or exited PIDs.
pub fn audit_running_electron_hygiene(
    agent_pids: &[(String, u32)],
    now_secs: u64,
) -> ElectronHygieneReport {
    let observed: Vec<(String, u32, Option<String>)> = agent_pids
        .iter()
        .map(|(agent_id, pid)| {
            let cmd = query_process_command_line_fast(*pid).ok();
            (agent_id.clone(), *pid, cmd)
        })
        .collect();
    evaluate_electron_hygiene_from_cmdlines(&observed, now_secs)
}

// ---------- Reparse-Point Guard & SHA-256 Helper ----------

/// Compute lowercase hex SHA-256 digest of `bytes`.
pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(windows)]
fn path_has_reparse_point(path: &Path) -> PlatformResult<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Ok(false);
    }
    Ok((attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0)
}

#[cfg(not(windows))]
fn path_has_reparse_point(path: &Path) -> PlatformResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.file_type().is_symlink()),
        Err(_) => Ok(false),
    }
}

/// Walk EVERY ancestor component (and leaf if present) of `path` and reject any symlink,
/// NTFS junction, or mount point (`FILE_ATTRIBUTE_REPARSE_POINT`) to defeat symlink attacks.
pub fn ensure_no_reparse_point_in_ancestors(path: &Path) -> PlatformResult<()> {
    let mut acc = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(PlatformError::InvalidInput(format!(
                    "路径不允许包含父级遍历片段 `..`：{}",
                    path.display()
                )));
            }
            Component::Prefix(p) => acc.push(p.as_os_str()),
            Component::RootDir => acc.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::Normal(seg) => {
                acc.push(seg);
                if path_has_reparse_point(&acc)? {
                    return Err(PlatformError::AccessDenied(format!(
                        "安全拦截：路径包含重解析点/符号链接/目录联接，已拒绝写入：{}",
                        acc.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Convenience boolean wrapper returning `true` when `path` or any of its ancestors contains a
/// symlink, NTFS junction, mount point, or `..` parent traversal segment.
pub fn has_reparse_point_in_chain(path: &Path) -> bool {
    ensure_no_reparse_point_in_ancestors(path).is_err()
}

// ---------- Reversible IShellLinkW Shortcut Hygiene Patcher ----------

/// Extracted metadata from a Windows `.lnk` Shell Link file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LnkMetadata {
    pub target_path: String,
    pub arguments: String,
    pub icon_path: String,
    pub icon_index: i32,
}

/// Lossless byte-level backup record for one patched `.lnk` shortcut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShortcutBackupRecord {
    pub lnk_path: String,
    pub agent_id: String,
    pub original_sha256: String,
    pub original_bytes_b64: String,
    pub original_target: String,
    pub original_args: String,
    pub original_icon_path: String,
    pub original_icon_index: i32,
    pub patched_at: u64,
}

/// Persisted JSON manifest storing byte-level `.lnk` backups for atomic rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShortcutHygieneBackupFile {
    pub schema_version: u32,
    #[serde(default)]
    pub entries: Vec<ShortcutBackupRecord>,
}

impl Default for ShortcutHygieneBackupFile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            entries: Vec::new(),
        }
    }
}

fn collect_subdirs_bounded(root: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    if !root.is_dir() || has_reparse_point_in_chain(root) {
        return;
    }
    if !out.contains(&root.to_path_buf()) {
        out.push(root.to_path_buf());
    }
    if max_depth == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() && !has_reparse_point_in_chain(&p) {
            collect_subdirs_bounded(&p, max_depth - 1, out);
        }
    }
}

/// Return standard per-user shortcut directories scanned for hygiene patching:
/// Desktop, Start Menu Programs, Taskbar User Pinned, `%USERPROFILE%\TuckPane` (2-level),
/// and `%APPDATA%\TuckPane` (2-level).
pub fn default_shortcut_scan_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for home in crate::process_win::user_home_dirs() {
        let roaming = home.join("AppData").join("Roaming");
        for cand in [
            home.join("Desktop"),
            roaming
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs"),
            roaming
                .join("Microsoft")
                .join("Internet Explorer")
                .join("Quick Launch")
                .join("User Pinned")
                .join("TaskBar"),
        ] {
            if cand.is_dir() && !has_reparse_point_in_chain(&cand) && !dirs.contains(&cand) {
                dirs.push(cand);
            }
        }
        collect_subdirs_bounded(&home.join("TuckPane"), 2, &mut dirs);
        collect_subdirs_bounded(&roaming.join("TuckPane"), 2, &mut dirs);
    }
    dirs
}

/// Returns `true` when a shortcut's target executable already delegates to an external proxy
/// launcher (`AntigravityProxy.exe`), which must NEVER be overwritten so Taskbar `AppUserModelID`
/// pinning and proxy launcher injection remain intact.
pub fn should_skip_shortcut_hygiene_target(target_path: &str) -> bool {
    let norm = target_path.trim().trim_matches('"').replace('/', "\\");
    let lower = norm.to_ascii_lowercase();
    if lower.contains(r"\antigravity-launcher\") {
        return true;
    }
    Path::new(&norm)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("antigravityproxy.exe"))
}

/// Extracts benign user flags that must survive Safe Launch shortcut wrapping (currently
/// `--remote-debugging-port=<u16>`, preserving `DevToolsActivePort` for CDP plugins/capsules).
pub fn extract_preserved_shortcut_flags(original_args: &str) -> Vec<String> {
    let mut preserved = Vec::new();
    let tokens: Vec<&str> = original_args.split_whitespace().collect();
    let mut i = 0usize;
    while i < tokens.len() {
        let tok = tokens[i].trim_matches(['"', '\'']);
        let low = tok.to_ascii_lowercase();
        if let Some(val) = low.strip_prefix("--remote-debugging-port=") {
            if let Ok(port) = val.parse::<u16>() {
                let flag = format!("--remote-debugging-port={port}");
                if !preserved.contains(&flag) {
                    preserved.push(flag);
                }
            }
        } else if low == "--remote-debugging-port" {
            if let Some(next_tok) = tokens.get(i + 1) {
                if let Ok(port) = next_tok.trim_matches(['"', '\'']).parse::<u16>() {
                    let flag = format!("--remote-debugging-port={port}");
                    if !preserved.contains(&flag) {
                        preserved.push(flag);
                    }
                    i += 1;
                }
            }
        }
        i += 1;
    }
    preserved
}

#[cfg(windows)]
fn wide_buf_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(windows)]
fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Read target path, arguments, and icon metadata from a Windows `.lnk` file via `IShellLinkW`.
#[cfg(windows)]
pub fn read_lnk_metadata(lnk_path: &Path) -> PlatformResult<LnkMetadata> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, IPersistFile, CLSCTX_INPROC_SERVER, STGM_READ,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink, SLGP_RAWPATH};

    ensure_no_reparse_point_in_ancestors(lnk_path)?;
    if !lnk_path.is_file() {
        return Err(PlatformError::InvalidInput(format!(
            "快捷方式文件不存在：{}",
            lnk_path.display()
        )));
    }

    let _com = crate::com::ComGuard::init_mta()?;
    let wide_lnk: Vec<u16> = lnk_path.as_os_str().encode_wide().chain(Some(0)).collect();

    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| crate::com::map_win_err(e, "CoCreateInstance(ShellLink)"))?;
        let persist: IPersistFile = link
            .cast()
            .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::cast(IPersistFile)"))?;
        persist
            .Load(PCWSTR(wide_lnk.as_ptr()), STGM_READ)
            .map_err(|e| crate::com::map_win_err(e, "IPersistFile::Load"))?;

        let mut target_buf = vec![0u16; 4096];
        link.GetPath(
            &mut target_buf,
            core::ptr::null_mut(),
            SLGP_RAWPATH.0 as u32,
        )
        .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::GetPath"))?;

        let mut args_buf = vec![0u16; 4096];
        let _ = link.GetArguments(&mut args_buf);

        let mut icon_buf = vec![0u16; 4096];
        let mut icon_idx: i32 = 0;
        let _ = link.GetIconLocation(&mut icon_buf, &mut icon_idx);

        Ok(LnkMetadata {
            target_path: wide_buf_to_string(&target_buf),
            arguments: wide_buf_to_string(&args_buf),
            icon_path: wide_buf_to_string(&icon_buf),
            icon_index: icon_idx,
        })
    }
}

#[cfg(not(windows))]
pub fn read_lnk_metadata(_lnk_path: &Path) -> PlatformResult<LnkMetadata> {
    Err(PlatformError::unsupported(
        "shortcut_hygiene",
        "IShellLinkW is only supported on Windows",
    ))
}

/// Create a Windows `.lnk` shortcut via COM `IShellLinkW` + `IPersistFile` (with ancestor reparse-point check).
#[cfg(windows)]
pub fn create_shortcut_lnk(
    lnk_path: &Path,
    target_exe: &Path,
    arguments: &str,
    icon_path: Option<&Path>,
    icon_index: i32,
    description: &str,
) -> PlatformResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{CoCreateInstance, IPersistFile, CLSCTX_INPROC_SERVER};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

    ensure_no_reparse_point_in_ancestors(lnk_path)?;
    if let Some(parent) = lnk_path.parent() {
        ensure_no_reparse_point_in_ancestors(parent)?;
    }

    let _imp = crate::access_win::ImpersonateInteractiveUserGuard::impersonate_if_session_zero()
        .map_err(PlatformError::AccessDenied)?;
    let _com = crate::com::ComGuard::init_mta()?;
    let target_w: Vec<u16> = target_exe
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let args_w = to_wide_z(arguments);
    let desc_w = to_wide_z(description);
    let lnk_w: Vec<u16> = lnk_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let workdir_w: Option<Vec<u16>> = target_exe
        .parent()
        .map(|d| d.as_os_str().encode_wide().chain(Some(0)).collect());
    let icon_w: Option<Vec<u16>> =
        icon_path.map(|p| p.as_os_str().encode_wide().chain(Some(0)).collect());

    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| crate::com::map_win_err(e, "CoCreateInstance(ShellLink)"))?;
        link.SetPath(PCWSTR(target_w.as_ptr()))
            .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::SetPath"))?;
        link.SetArguments(PCWSTR(args_w.as_ptr()))
            .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::SetArguments"))?;
        if let Some(ref wd) = workdir_w {
            let _ = link.SetWorkingDirectory(PCWSTR(wd.as_ptr()));
        }
        if !description.is_empty() {
            let _ = link.SetDescription(PCWSTR(desc_w.as_ptr()));
        }
        if let Some(ref ic) = icon_w {
            link.SetIconLocation(PCWSTR(ic.as_ptr()), icon_index)
                .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::SetIconLocation"))?;
        }
        let persist: IPersistFile = link
            .cast()
            .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::cast(IPersistFile)"))?;
        persist
            .Save(PCWSTR(lnk_w.as_ptr()), true)
            .map_err(|e| crate::com::map_win_err(e, "IPersistFile::Save"))?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn create_shortcut_lnk(
    _lnk_path: &Path,
    _target_exe: &Path,
    _arguments: &str,
    _icon_path: Option<&Path>,
    _icon_index: i32,
    _description: &str,
) -> PlatformResult<()> {
    Err(PlatformError::unsupported(
        "shortcut_hygiene",
        "IShellLinkW is only supported on Windows",
    ))
}

fn atomic_write_bytes(dest: &Path, bytes: &[u8]) -> PlatformResult<()> {
    use std::io::Write;

    ensure_no_reparse_point_in_ancestors(dest)?;
    let parent = dest
        .parent()
        .ok_or_else(|| PlatformError::InvalidInput("目标路径缺少父目录".into()))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PlatformError::Io(format!("创建父目录失败：{} ({e})", parent.display()))
        })?;
    }
    ensure_no_reparse_point_in_ancestors(dest)?;

    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());

    let mut tmp_opt = None;
    for _ in 0..8 {
        let nonce =
            crate::crypto_win::random_hex(8).unwrap_or_else(|_| format!("{}", std::process::id()));
        let cand = parent.join(format!(".{file_name}.cg-tmp-{nonce}"));
        ensure_no_reparse_point_in_ancestors(&cand)?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&cand)
        {
            Ok(f) => {
                tmp_opt = Some((cand, f));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(PlatformError::Io(format!(
                    "创建临时文件失败：{} ({e})",
                    cand.display()
                )))
            }
        }
    }
    let Some((tmp, mut f)) = tmp_opt else {
        return Err(PlatformError::Io(format!(
            "创建独占临时文件失败：{}",
            dest.display()
        )));
    };
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(&tmp);
        return Err(PlatformError::Io(format!(
            "写入临时文件失败：{} ({e})",
            tmp.display()
        )));
    }
    drop(f);

    ensure_no_reparse_point_in_ancestors(dest)?;
    crate::vault_win::clear_readonly_if_needed(dest);

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let src_w: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let dst_w: Vec<u16> = dest.as_os_str().encode_wide().chain(Some(0)).collect();
        if let Err(e) = unsafe {
            MoveFileExW(
                PCWSTR(src_w.as_ptr()),
                PCWSTR(dst_w.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } {
            let _ = std::fs::remove_file(&tmp);
            return Err(PlatformError::Io(format!(
                "原子替换文件失败：{} ({e})",
                dest.display()
            )));
        }
    }
    #[cfg(not(windows))]
    {
        if let Err(e) = std::fs::rename(&tmp, dest) {
            let _ = std::fs::remove_file(&tmp);
            return Err(PlatformError::Io(format!(
                "原子替换文件失败：{} ({e})",
                dest.display()
            )));
        }
    }
    Ok(())
}

fn load_backup_file(backup_json_path: &Path) -> PlatformResult<ShortcutHygieneBackupFile> {
    if !backup_json_path.exists() {
        return Ok(ShortcutHygieneBackupFile::default());
    }
    ensure_no_reparse_point_in_ancestors(backup_json_path)?;
    let raw = std::fs::read_to_string(backup_json_path)
        .map_err(|e| PlatformError::Io(format!("读取快捷方式备份清单失败：{e}")))?;
    serde_json::from_str(&raw)
        .map_err(|e| PlatformError::Io(format!("解析快捷方式备份清单失败：{e}")))
}

fn save_backup_file(
    backup_json_path: &Path,
    file: &ShortcutHygieneBackupFile,
) -> PlatformResult<()> {
    let serialized = serde_json::to_vec_pretty(file)
        .map_err(|e| PlatformError::Io(format!("序列化快捷方式备份清单失败：{e}")))?;
    atomic_write_bytes(backup_json_path, &serialized)
}

fn validate_safe_agent_id(agent_id: &str) -> PlatformResult<String> {
    let clean = agent_id.trim().to_ascii_lowercase();
    if clean.is_empty()
        || !clean
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(PlatformError::InvalidInput(format!(
            "非法 agent_id：`{agent_id}`"
        )));
    }
    Ok(clean)
}

/// Patch an existing Windows `.lnk` shortcut to route through `launcher_exe --safe-launch <agent_id>`
/// while locking the icon to the original target executable and saving a byte-exact SHA-256 backup
/// in `backup_json_path`.
#[cfg(windows)]
pub fn patch_shortcut_for_safe_launch(
    lnk_path: &Path,
    agent_id: &str,
    launcher_exe: &Path,
    backup_json_path: &Path,
    now_secs: u64,
) -> PlatformResult<ShortcutBackupRecord> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, IPersistFile, CLSCTX_INPROC_SERVER, STGM_READWRITE,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

    let clean_agent = validate_safe_agent_id(agent_id)?;
    if !lnk_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
    {
        return Err(PlatformError::InvalidInput(format!(
            "仅允许修改 .lnk 快捷方式文件：{}",
            lnk_path.display()
        )));
    }
    ensure_no_reparse_point_in_ancestors(lnk_path)?;
    ensure_no_reparse_point_in_ancestors(backup_json_path)?;

    let _imp = crate::access_win::ImpersonateInteractiveUserGuard::impersonate_if_session_zero()
        .map_err(PlatformError::AccessDenied)?;
    if !lnk_path.is_file() {
        return Err(PlatformError::InvalidInput(format!(
            "快捷方式不存在：{}",
            lnk_path.display()
        )));
    }

    let raw_bytes = std::fs::read(lnk_path)
        .map_err(|e| PlatformError::Io(format!("读取快捷方式原始字节失败：{e}")))?;
    let sha256 = compute_sha256_hex(&raw_bytes);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
    let meta = read_lnk_metadata(lnk_path)?;
    if should_skip_shortcut_hygiene_target(&meta.target_path) {
        return Err(PlatformError::InvalidInput(format!(
            "跳过外部代理启动器快捷方式（已由外部封装保护）：{}",
            lnk_path.display()
        )));
    }

    let lnk_key = lnk_path.to_string_lossy().into_owned();
    let mut backup_file = load_backup_file(backup_json_path)?;
    let record = if let Some(existing) = backup_file
        .entries
        .iter()
        .find(|e| e.lnk_path.eq_ignore_ascii_case(&lnk_key))
        .cloned()
    {
        // Preserve the true original bytes if re-patched so rollback always restores the pristine .lnk!
        existing
    } else {
        let rec = ShortcutBackupRecord {
            lnk_path: lnk_key.clone(),
            agent_id: clean_agent.clone(),
            original_sha256: sha256,
            original_bytes_b64: b64,
            original_target: meta.target_path.clone(),
            original_args: meta.arguments.clone(),
            original_icon_path: meta.icon_path.clone(),
            original_icon_index: meta.icon_index,
            patched_at: now_secs,
        };
        backup_file.entries.push(rec.clone());
        save_backup_file(backup_json_path, &backup_file)?;
        rec
    };

    let _com = crate::com::ComGuard::init_mta()?;
    let lnk_w: Vec<u16> = lnk_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let launcher_w: Vec<u16> = launcher_exe
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let preserved_flags = extract_preserved_shortcut_flags(&record.original_args);
    let safe_launch_args = if preserved_flags.is_empty() {
        format!("--safe-launch {clean_agent}")
    } else {
        format!(
            "--safe-launch {clean_agent} -- {}",
            preserved_flags.join(" ")
        )
    };
    let args_w = to_wide_z(&safe_launch_args);
    let icon_src = if !record.original_icon_path.trim().is_empty() {
        record.original_icon_path.clone()
    } else {
        record.original_target.clone()
    };
    let icon_idx = if !record.original_icon_path.trim().is_empty() {
        record.original_icon_index
    } else {
        0
    };
    let icon_w = to_wide_z(&icon_src);

    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| crate::com::map_win_err(e, "CoCreateInstance(ShellLink)"))?;
        let persist: IPersistFile = link
            .cast()
            .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::cast(IPersistFile)"))?;
        persist
            .Load(PCWSTR(lnk_w.as_ptr()), STGM_READWRITE)
            .map_err(|e| crate::com::map_win_err(e, "IPersistFile::Load(RW)"))?;

        link.SetPath(PCWSTR(launcher_w.as_ptr()))
            .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::SetPath"))?;
        link.SetArguments(PCWSTR(args_w.as_ptr()))
            .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::SetArguments"))?;
        if !icon_src.is_empty() {
            link.SetIconLocation(PCWSTR(icon_w.as_ptr()), icon_idx)
                .map_err(|e| crate::com::map_win_err(e, "IShellLinkW::SetIconLocation"))?;
        }
        persist
            .Save(PCWSTR(lnk_w.as_ptr()), true)
            .map_err(|e| crate::com::map_win_err(e, "IPersistFile::Save"))?;
    }

    Ok(record)
}

#[cfg(not(windows))]
pub fn patch_shortcut_for_safe_launch(
    _lnk_path: &Path,
    _agent_id: &str,
    _launcher_exe: &Path,
    _backup_json_path: &Path,
    _now_secs: u64,
) -> PlatformResult<ShortcutBackupRecord> {
    Err(PlatformError::unsupported(
        "shortcut_hygiene",
        "IShellLinkW shortcut patching is only supported on Windows",
    ))
}

/// Restore one specific `.lnk` (when `lnk_path = Some(...)`) or all backed-up `.lnk` shortcuts
/// from `backup_json_path`, strictly verifying SHA-256 integrity and ancestor reparse-point safety.
pub fn restore_shortcut_from_backup(
    backup_json_path: &Path,
    lnk_path: Option<&Path>,
) -> PlatformResult<usize> {
    if !backup_json_path.exists() {
        return Ok(0);
    }
    ensure_no_reparse_point_in_ancestors(backup_json_path)?;
    let mut backup = load_backup_file(backup_json_path)?;
    let filter_key = lnk_path.map(|p| p.to_string_lossy().into_owned());

    let mut restored = 0usize;
    let mut remaining = Vec::new();
    for entry in backup.entries.drain(..) {
        let should_restore = match filter_key.as_deref() {
            Some(target) => entry.lnk_path.eq_ignore_ascii_case(target),
            None => true,
        };
        if !should_restore {
            remaining.push(entry);
            continue;
        }

        let target_path = PathBuf::from(&entry.lnk_path);
        ensure_no_reparse_point_in_ancestors(&target_path)?;

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(entry.original_bytes_b64.as_bytes())
            .map_err(|e| {
                PlatformError::Io(format!(
                    "快捷方式备份 Base64 解码失败（{}）：{e}",
                    entry.lnk_path
                ))
            })?;
        let actual_sha = compute_sha256_hex(&decoded);
        if !actual_sha.eq_ignore_ascii_case(&entry.original_sha256) {
            return Err(PlatformError::Io(format!(
                "快捷方式备份 SHA-256 校验失败（{}）：期望 {}，实际 {}",
                entry.lnk_path, entry.original_sha256, actual_sha
            )));
        }

        {
            let _imp =
                crate::access_win::ImpersonateInteractiveUserGuard::impersonate_if_session_zero()
                    .map_err(PlatformError::AccessDenied)?;
            atomic_write_bytes(&target_path, &decoded)?;
        }
        restored += 1;
    }

    backup.entries = remaining;
    save_backup_file(backup_json_path, &backup)?;
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "cg-hygiene-{tag}-{}-{}",
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
    fn inspects_electron_hygiene_command_lines_and_reports_bare_agents() {
        let full_cmd = r#""C:\Users\mjq\AppData\Local\Programs\Claude\Claude.exe" --disable-quic --force-webrtc-ip-handling-policy=disable_non_proxied_udp --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE localhost""#;
        let full = inspect_electron_cmdline(full_cmd);
        assert!(full.webrtc_flag_enforced);
        assert!(full.quic_disabled_flag);
        assert!(full.host_resolver_enforced);
        assert!(full.baseline_protected());

        let partial = inspect_electron_cmdline(r#""Claude.exe" --disable-quic"#);
        assert!(partial.quic_disabled_flag);
        assert!(!partial.webrtc_flag_enforced);
        assert!(!partial.baseline_protected());

        let bare = inspect_electron_cmdline(r#""C:\App\Claude.exe""#);
        assert!(!bare.webrtc_flag_enforced);
        assert!(!bare.quic_disabled_flag);
        assert!(!bare.host_resolver_enforced);

        let report_empty = evaluate_electron_hygiene_from_cmdlines(&[], 100);
        assert!(report_empty.unguarded_running_agents.is_empty());
        assert!(report_empty.webrtc_flag_enforced);
        assert!(report_empty.quic_disabled_flag);

        let report_mixed = evaluate_electron_hygiene_from_cmdlines(
            &[
                ("claude".into(), 1001, Some(full_cmd.to_string())),
                (
                    "antigravity".into(),
                    2002,
                    Some(r#""Antigravity.exe""#.to_string()),
                ),
            ],
            200,
        );
        assert_eq!(report_mixed.unguarded_running_agents, vec!["antigravity"]);
        assert!(!report_mixed.webrtc_flag_enforced);
        assert!(!report_mixed.quic_disabled_flag);
    }

    #[cfg(windows)]
    #[test]
    fn nt_query_command_line_reads_current_process_without_wmi() {
        let cmd = query_process_command_line_fast(std::process::id())
            .expect("NtQueryInformationProcess(60) should read current process cmdline");
        assert!(
            !cmd.trim().is_empty(),
            "current test binary command line should be non-empty"
        );
    }

    #[cfg(windows)]
    #[test]
    fn shortcut_patch_and_sha256_byte_exact_restore_roundtrip() {
        let dir = unique_temp_dir("lnk-roundtrip");
        let lnk = dir.join("Antigravity.lnk");
        let backup = dir.join("hygiene_lnk_backup.json");
        let orig_target = PathBuf::from(r"C:\Windows\System32\notepad.exe");
        let launcher = PathBuf::from(r"C:\Windows\System32\cmd.exe");

        create_shortcut_lnk(
            &lnk,
            &orig_target,
            "--original-arg",
            None,
            0,
            "Antigravity Test Shortcut",
        )
        .expect("create test .lnk");
        let original_bytes = std::fs::read(&lnk).unwrap();
        let original_sha = compute_sha256_hex(&original_bytes);

        let rec = patch_shortcut_for_safe_launch(&lnk, "antigravity", &launcher, &backup, 5555)
            .expect("patch shortcut");
        assert_eq!(rec.original_sha256, original_sha);
        assert_eq!(rec.agent_id, "antigravity");

        let patched_meta = read_lnk_metadata(&lnk).expect("read patched .lnk");
        assert!(patched_meta
            .target_path
            .to_ascii_lowercase()
            .ends_with("cmd.exe"));
        assert_eq!(patched_meta.arguments, "--safe-launch antigravity");
        assert!(patched_meta
            .icon_path
            .to_ascii_lowercase()
            .ends_with("notepad.exe"));

        // Corrupt SHA-256 in backup -> restore MUST reject tampered payload!
        let mut bad_backup = load_backup_file(&backup).unwrap();
        bad_backup.entries[0].original_sha256 = "0".repeat(64);
        let bad_path = dir.join("bad_backup.json");
        save_backup_file(&bad_path, &bad_backup).unwrap();
        assert!(restore_shortcut_from_backup(&bad_path, Some(&lnk)).is_err());

        // Restore from valid backup -> exact byte-for-byte identity with original .lnk!
        let restored = restore_shortcut_from_backup(&backup, Some(&lnk)).expect("restore .lnk");
        assert_eq!(restored, 1);
        let after_bytes = std::fs::read(&lnk).unwrap();
        assert_eq!(after_bytes, original_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reparse_guard_rejects_parent_traversal() {
        assert!(ensure_no_reparse_point_in_ancestors(Path::new(r"C:\foo\..\bar.lnk")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn shortcut_patch_preserves_cdp_flag_and_skips_proxy_launcher_target() {
        assert_eq!(
            extract_preserved_shortcut_flags("--remote-debugging-port=0 --other-flag"),
            vec!["--remote-debugging-port=0"]
        );
        assert_eq!(
            extract_preserved_shortcut_flags("--remote-debugging-port 9222"),
            vec!["--remote-debugging-port=9222"]
        );
        assert!(should_skip_shortcut_hygiene_target(
            r"C:\Tools\AntigravityProxy.exe"
        ));
        assert!(should_skip_shortcut_hygiene_target(
            r"C:\Tools\antigravity-launcher\launcher.exe"
        ));
        assert!(!should_skip_shortcut_hygiene_target(
            r"C:\Users\mjq\AppData\Local\Programs\Antigravity\Antigravity.exe"
        ));

        let dir = unique_temp_dir("lnk-cdp");
        let lnk = dir.join("Antigravity CDP.lnk");
        let backup = dir.join("hygiene_cdp_backup.json");
        let orig_target = PathBuf::from(r"C:\Windows\System32\notepad.exe");
        let launcher = PathBuf::from(r"C:\Windows\System32\cmd.exe");

        create_shortcut_lnk(
            &lnk,
            &orig_target,
            "--remote-debugging-port=0 --unity-launch",
            None,
            0,
            "Antigravity CDP Shortcut",
        )
        .expect("create cdp .lnk");

        patch_shortcut_for_safe_launch(&lnk, "antigravity", &launcher, &backup, 7777)
            .expect("patch cdp shortcut");
        let patched_meta = read_lnk_metadata(&lnk).expect("read patched cdp .lnk");
        assert_eq!(
            patched_meta.arguments,
            "--safe-launch antigravity -- --remote-debugging-port=0"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
