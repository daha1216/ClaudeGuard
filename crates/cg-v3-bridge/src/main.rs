#![cfg_attr(not(test), windows_subsystem = "windows")]

//! Seamless ClaudeGuard v3 -> v4 self-update bridge binary.
//!
//! Why this exists:
//! - Legacy v3 (`src/update.rs`) is a single-exe updater whose `Release::exe_asset()` only accepts
//!   `.exe` assets containing `"ClaudeGuard"` and NOT containing `"-setup"`, and replaces
//!   `{app}\ClaudeGuard.exe` in place before executing it.
//! - Directly renaming the v4 Inno Setup installer to `ClaudeGuard-v4.0.0.exe` would fail because
//!   v4 `claude-guard.iss` executes `taskkill /F /IM ClaudeGuard.exe` during `PrepareToInstall`.
//! - This bridge satisfies v3's asset & SHA-256 verification rules, copies legacy `%APPDATA%`
//!   configuration into `%ProgramData%\ClaudeGuard` when absent, extracts the embedded v4
//!   installer into a staging directory, spawns a staging-side waiter outside `{app}`, exits
//!   immediately so `{app}\ClaudeGuard.exe` is unlocked, waits for installation completion, and
//!   cleans up legacy `{app}\ClaudeGuard.exe` + `.exe.old` artifacts once v4 is installed.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(cg_has_embedded_setup)]
const EMBEDDED_SETUP: &[u8] = include_bytes!(env!("CG_EMBEDDED_SETUP_PATH"));
#[cfg(not(cg_has_embedded_setup))]
const EMBEDDED_SETUP: &[u8] = &[];

const WAITER_FLAG: &str = "--cg-wait";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_JSON_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct WaiterArgs {
    app_exe: PathBuf,
    old_exe: PathBuf,
    setup_exe: PathBuf,
}

/// Pure-Rust FIPS 180-4 SHA-256 implementation (zero external crate dependencies).
struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bits: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bits: 0,
        }
    }

    fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (&wi, &ki) in w.iter().zip(Self::K.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(ki)
                .wrapping_add(wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((data.len() as u64) * 8);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buf;
            Self::compress_block(&mut self.state, &block);
            self.buf_len = 0;
            data = &data[need..];
        }
        let (blocks, rem) = data.as_chunks::<64>();
        for block in blocks {
            Self::compress_block(&mut self.state, block);
        }
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bits;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buf;
            Self::compress_block(&mut self.state, &block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        Self::compress_block(&mut self.state, &block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn sha256_file(file: &mut File) -> Result<[u8; 32], String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("读取安装包校验偏移失败：{e}"))?;
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; 65_536];
    loop {
        let n = file
            .read(&mut chunk)
            .map_err(|e| format!("读取安装包校验数据失败：{e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    Ok(hasher.finalize())
}

/// Opens `setup_exe` with `FILE_SHARE_READ` (`1`) only, preventing external processes from
/// writing, truncating, deleting, or renaming the staged binary while allowing OS image execution.
fn open_setup_read_locked(setup_exe: &Path) -> Result<File, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ_ONLY: u32 = 1;
        opts.share_mode(FILE_SHARE_READ_ONLY);
    }
    opts.open(setup_exe)
        .map_err(|e| format!("锁定升级安装包失败（{}）：{e}", setup_exe.display()))
}

fn verify_locked_setup_sha256(file: &mut File, expected_bytes: &[u8]) -> Result<(), String> {
    if expected_bytes.is_empty() {
        return Err("内嵌安装包摘要为空，拒绝执行升级安装包".into());
    }
    let expected = sha256_bytes(expected_bytes);
    let actual = sha256_file(file)?;
    if actual != expected {
        return Err("升级安装包 SHA-256 完整性校验失败（疑似被篡改或损坏），已中止执行".into());
    }
    Ok(())
}

struct JsonScan<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonScan<'a> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_string(&mut self) -> bool {
        if self.peek() != Some(b'"') {
            return false;
        }
        self.pos += 1;
        while let Some(&b) = self.bytes.get(self.pos) {
            self.pos += 1;
            match b {
                b'"' => return true,
                0x00..=0x1F => return false,
                b'\\' => {
                    let Some(&esc) = self.bytes.get(self.pos) else {
                        return false;
                    };
                    self.pos += 1;
                    match esc {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                let Some(&hex) = self.bytes.get(self.pos) else {
                                    return false;
                                };
                                if !hex.is_ascii_hexdigit() {
                                    return false;
                                }
                                self.pos += 1;
                            }
                        }
                        _ => return false,
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn parse_number(&mut self) -> bool {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while self.peek().is_some_and(|d| d.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return false,
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !self.peek().is_some_and(|d| d.is_ascii_digit()) {
                return false;
            }
            while self.peek().is_some_and(|d| d.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !self.peek().is_some_and(|d| d.is_ascii_digit()) {
                return false;
            }
            while self.peek().is_some_and(|d| d.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        true
    }

    fn parse_literal(&mut self, lit: &[u8]) -> bool {
        let Some(slice) = self.bytes.get(self.pos..self.pos + lit.len()) else {
            return false;
        };
        if slice == lit {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    fn parse_array(&mut self, depth: usize) -> bool {
        if depth > MAX_JSON_DEPTH || self.peek() != Some(b'[') {
            return false;
        }
        self.pos += 1;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return true;
        }
        loop {
            if !self.parse_value(depth + 1) {
                return false;
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.pos += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> bool {
        if depth > MAX_JSON_DEPTH || self.peek() != Some(b'{') {
            return false;
        }
        self.pos += 1;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return true;
        }
        loop {
            self.skip_ws();
            if !self.parse_string() {
                return false;
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return false;
            }
            self.pos += 1;
            if !self.parse_value(depth + 1) {
                return false;
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> bool {
        if depth > MAX_JSON_DEPTH {
            return false;
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => self.parse_string(),
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => false,
        }
    }
}

fn is_valid_json_object(text: &str) -> bool {
    let mut scan = JsonScan {
        bytes: text.as_bytes(),
        pos: 0,
    };
    scan.skip_ws();
    if !scan.parse_object(0) {
        return false;
    }
    scan.skip_ws();
    scan.pos == scan.bytes.len()
}

fn parse_waiter_args(args: &[String]) -> Option<WaiterArgs> {
    if args.len() != 4 || args[0] != WAITER_FLAG {
        return None;
    }
    Some(WaiterArgs {
        app_exe: PathBuf::from(&args[1]),
        old_exe: PathBuf::from(&args[2]),
        setup_exe: PathBuf::from(&args[3]),
    })
}

fn non_empty_env_dir(var_name: &str) -> Option<PathBuf> {
    std::env::var_os(var_name)
        .filter(|v| !v.to_string_lossy().trim().is_empty())
        .map(PathBuf::from)
}

/// Picks a staging directory (`%ProgramData%\ClaudeGuard\staging` first, else `%TEMP%\ClaudeGuard-upgrade`).
fn pick_staging_dir(program_data: Option<PathBuf>, temp_dir: PathBuf) -> PathBuf {
    if let Some(pd) = program_data {
        return pd.join("ClaudeGuard").join("staging");
    }
    temp_dir.join("ClaudeGuard-upgrade")
}

/// Resolves and ensures a writable staging directory.
fn ensure_staging_dir() -> Result<PathBuf, String> {
    let primary = pick_staging_dir(non_empty_env_dir("ProgramData"), std::env::temp_dir());
    if fs::create_dir_all(&primary).is_ok() {
        return Ok(primary);
    }
    let fallback = std::env::temp_dir().join("ClaudeGuard-upgrade");
    fs::create_dir_all(&fallback)
        .map_err(|e| format!("无法创建升级暂存目录（{}）：{e}", fallback.display()))?;
    Ok(fallback)
}

/// Copies legacy v3 `%APPDATA%\ClaudeGuard\config.json` into `%ProgramData%\ClaudeGuard\config.json`
/// ONLY when the destination does not already exist, stripping UTF-8 BOM and verifying valid JSON object.
fn migrate_config_if_absent(appdata_dir: Option<&Path>, programdata_dir: Option<&Path>) -> bool {
    let (Some(src_base), Some(dst_base)) = (appdata_dir, programdata_dir) else {
        return false;
    };
    let src = src_base.join("ClaudeGuard").join("config.json");
    let dst_dir = dst_base.join("ClaudeGuard");
    let dst = dst_dir.join("config.json");

    if !src.is_file() || dst.exists() {
        return false;
    }
    let Ok(bytes) = fs::read(&src) else {
        return false;
    };
    let stripped = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    let Ok(text) = std::str::from_utf8(stripped) else {
        return false;
    };
    if !is_valid_json_object(text) {
        return false;
    }
    if fs::create_dir_all(&dst_dir).is_err() {
        return false;
    }
    let Ok(tmp) = write_unique_file(&dst_dir, "config.json.v3mig", "tmp", stripped) else {
        return false;
    };
    if dst.exists() || fs::rename(&tmp, &dst).is_err() {
        let _ = fs::remove_file(&tmp);
        return false;
    }
    true
}

fn unique_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{}-{:08x}", process::id(), nanos & 0xffff_ffff)
}

fn write_unique_file(dir: &Path, prefix: &str, ext: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let pid = process::id();
    for attempt in 0..8u32 {
        let path = dir.join(format!("{prefix}-{pid}-{attempt}-{}.{ext}", unique_tag()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(format!("写入临时文件失败（{}）：{e}", path.display()));
                }
                return Ok(path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "创建临时文件失败（{}）：{e}",
                    path.display(),
                    e = err
                ));
            }
        }
    }
    Err("创建临时升级文件失败：重试次数耗尽".into())
}

fn remove_file_with_retry(path: &Path) {
    for attempt in 0..6 {
        match fs::remove_file(path) {
            Ok(()) => return,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) if attempt < 5 => thread::sleep(Duration::from_millis(250)),
            Err(_) => return,
        }
    }
}

fn is_v4_installed(app_exe: &Path, program_files: Option<&Path>) -> bool {
    if app_exe
        .parent()
        .map(|dir| dir.join("claudeguard-gui.exe").is_file())
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(pf) = program_files {
        if pf.join("ClaudeGuard").join("claudeguard-gui.exe").is_file() {
            return true;
        }
    }
    false
}

fn cleanup_legacy_v3_shortcuts(user_profile: Option<&Path>, appdata: Option<&Path>) {
    if let Some(home) = user_profile {
        remove_file_with_retry(&home.join("Desktop").join("ClaudeGuard.lnk"));
    }
    if let Some(roaming) = appdata {
        remove_file_with_retry(
            &roaming
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("ClaudeGuard.lnk"),
        );
    }
}

fn cleanup_post_install_with(
    args: &WaiterArgs,
    setup_succeeded: bool,
    program_files: Option<&Path>,
    user_profile: Option<&Path>,
    appdata: Option<&Path>,
) {
    remove_file_with_retry(&args.setup_exe);
    let installed = setup_succeeded || is_v4_installed(&args.app_exe, program_files);
    if installed {
        remove_file_with_retry(&args.app_exe);
        remove_file_with_retry(&args.old_exe);
        if let Some(app_dir) = args.app_exe.parent() {
            if !app_dir.join("claudeguard-gui.exe").is_file() {
                let _ = fs::remove_dir(app_dir);
            }
        }
        cleanup_legacy_v3_shortcuts(user_profile, appdata);
    }
}

fn cleanup_post_install(args: &WaiterArgs, setup_succeeded: bool) {
    let pf = non_empty_env_dir("ProgramFiles");
    let user_profile = non_empty_env_dir("USERPROFILE");
    let appdata = non_empty_env_dir("APPDATA");
    cleanup_post_install_with(
        args,
        setup_succeeded,
        pf.as_deref(),
        user_profile.as_deref(),
        appdata.as_deref(),
    );
}

fn schedule_waiter_self_cleanup(waiter_exe: &Path) {
    // Rely strictly on Win32 MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT) + Inno Setup ssPostInstall
    // cleanup (zero cmd.exe /C shell command construction).
    win_api::schedule_delete_on_reboot(waiter_exe);
    if let Some(dir) = waiter_exe.parent() {
        if dir
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("staging"))
        {
            win_api::schedule_delete_on_reboot(dir);
        }
    }
}

#[cfg(windows)]
mod win_api {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONERROR: u32 = 0x0000_0010;
    const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x0000_0004;
    const SW_SHOWNORMAL: i32 = 1;
    const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
    const INFINITE: u32 = 0xFFFF_FFFF;

    #[repr(C)]
    pub(super) struct ShellExecuteInfoW {
        cb_size: u32,
        f_mask: u32,
        hwnd: *mut c_void,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: *mut c_void,
        lp_id_list: *mut c_void,
        lp_class: *const u16,
        hkey_class: *mut c_void,
        dw_hot_key: u32,
        h_icon_or_monitor: *mut c_void,
        h_process: *mut c_void,
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, utype: u32)
            -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(handle: *mut c_void, exit_code: *mut u32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteExW(exec_info: *mut ShellExecuteInfoW) -> i32;
    }

    struct ProcessHandleGuard(*mut c_void);

    impl Drop for ProcessHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn wide_null(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn show_error(title: &str, msg: &str) {
        let t = wide_null(OsStr::new(title));
        let m = wide_null(OsStr::new(msg));
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                m.as_ptr(),
                t.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    pub fn schedule_delete_on_reboot(path: &Path) {
        let p = wide_null(path.as_os_str());
        unsafe {
            MoveFileExW(p.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }

    /// Launches setup elevated via UAC and waits for it to finish, returning whether exit code == 0.
    pub fn run_elevated_setup_and_wait(setup_exe: &Path) -> Result<bool, String> {
        let op = wide_null(OsStr::new("runas"));
        let file = wide_null(setup_exe.as_os_str());
        let params = wide_null(OsStr::new("/SP-"));
        let mut sei = ShellExecuteInfoW {
            cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: SEE_MASK_NOCLOSEPROCESS,
            hwnd: std::ptr::null_mut(),
            lp_verb: op.as_ptr(),
            lp_file: file.as_ptr(),
            lp_parameters: params.as_ptr(),
            lp_directory: std::ptr::null(),
            n_show: SW_SHOWNORMAL,
            h_inst_app: std::ptr::null_mut(),
            lp_id_list: std::ptr::null_mut(),
            lp_class: std::ptr::null(),
            hkey_class: std::ptr::null_mut(),
            dw_hot_key: 0,
            h_icon_or_monitor: std::ptr::null_mut(),
            h_process: std::ptr::null_mut(),
        };
        let ok = unsafe { ShellExecuteExW(&mut sei) };
        if ok == 0 {
            return Err(format!(
                "无法以管理员权限启动安装程序（请确认 UAC 授权或手动运行）：{}",
                setup_exe.display()
            ));
        }
        if sei.h_process.is_null() {
            return Ok(false);
        }
        let _proc_guard = ProcessHandleGuard(sei.h_process);
        let mut exit_code: u32 = 1;
        unsafe {
            WaitForSingleObject(sei.h_process, INFINITE);
            GetExitCodeProcess(sei.h_process, &mut exit_code);
        }
        Ok(exit_code == 0)
    }
}

#[cfg(not(windows))]
mod win_api {
    use std::path::Path;
    pub fn show_error(title: &str, msg: &str) {
        eprintln!("{title}: {msg}");
    }
    pub fn schedule_delete_on_reboot(_path: &Path) {}
    pub fn run_elevated_setup_and_wait(_setup_exe: &Path) -> Result<bool, String> {
        Err("仅支持 Windows 平台".into())
    }
}

fn spawn_detached(cmd: &mut Command) -> std::io::Result<process::Child> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn run_waiter(args: WaiterArgs) -> Result<(), String> {
    // Hold a FILE_SHARE_READ-only handle across the 350ms sleep and UAC launch to prevent TOCTOU tampering.
    let mut setup_lock = open_setup_read_locked(&args.setup_exe)?;

    // Allow brief window for the launching bridge (`ClaudeGuard.exe`) and old v3 daemon to exit.
    thread::sleep(Duration::from_millis(350));

    if let Err(err) = verify_locked_setup_sha256(&mut setup_lock, EMBEDDED_SETUP) {
        drop(setup_lock);
        remove_file_with_retry(&args.setup_exe);
        return Err(err);
    }

    match Command::new(&args.setup_exe)
        .arg("/SP-")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            let status_res = child.wait();
            drop(setup_lock);
            let status = status_res.map_err(|e| format!("等待安装程序完成失败：{e}"))?;
            cleanup_post_install(&args, status.success());
            Ok(())
        }
        Err(err) if err.raw_os_error() == Some(740) => {
            // Non-elevated v3 updater: prompt UAC via ShellExecuteExW("runas") while holding
            // the read-locked file handle, then release handle right before post-install cleanup.
            let run_res = win_api::run_elevated_setup_and_wait(&args.setup_exe);
            drop(setup_lock);
            match run_res {
                Ok(ok) => {
                    cleanup_post_install(&args, ok);
                    Ok(())
                }
                Err(e) => {
                    remove_file_with_retry(&args.setup_exe);
                    Err(e)
                }
            }
        }
        Err(err) => {
            drop(setup_lock);
            remove_file_with_retry(&args.setup_exe);
            Err(format!(
                "启动安装程序失败（{}）：{err}",
                args.setup_exe.display()
            ))
        }
    }
}

fn run_primary() -> Result<(), String> {
    let cur_exe = std::env::current_exe().map_err(|e| format!("无法定位当前升级程序路径：{e}"))?;
    let app_dir = cur_exe
        .parent()
        .ok_or_else(|| "无法识别安装目录".to_string())?;
    let old_exe = cur_exe.with_extension("exe.old");

    // If v4 is already installed alongside this file (e.g. legacy shortcut left behind),
    // clean up v3 `.old` residue and hand off directly to `claudeguard-gui.exe`.
    let gui_exe = app_dir.join("claudeguard-gui.exe");
    if gui_exe.is_file() {
        remove_file_with_retry(&old_exe);
        let _ = spawn_detached(&mut Command::new(&gui_exe));
        win_api::schedule_delete_on_reboot(&cur_exe);
        return Ok(());
    }

    if EMBEDDED_SETUP.is_empty() {
        return Err(
            "当前升级引导包未内嵌安装包正文，请从 GitHub Releases 下载完整 setup.exe 安装。".into(),
        );
    }

    // Preserve existing v3 settings from `%APPDATA%\ClaudeGuard\config.json` into `%ProgramData%\ClaudeGuard\config.json`.
    let appdata = non_empty_env_dir("APPDATA");
    let programdata = non_empty_env_dir("ProgramData");
    let _ = migrate_config_if_absent(appdata.as_deref(), programdata.as_deref());

    let staging = ensure_staging_dir()?;
    let setup_path = write_unique_file(
        &staging,
        &format!("ClaudeGuard-v{APP_VERSION}-setup"),
        "exe",
        EMBEDDED_SETUP,
    )?;

    // Copy this bridge binary out of `{app}\ClaudeGuard.exe` into staging so `{app}` stays unlocked
    // and Inno Setup's `taskkill /IM ClaudeGuard.exe` never hits the waiter.
    let waiter_path = staging.join(format!("cg-v3-waiter-{}.exe", unique_tag()));
    if fs::copy(&cur_exe, &waiter_path).is_ok() {
        let mut cmd = Command::new(&waiter_path);
        cmd.arg(WAITER_FLAG)
            .arg(&cur_exe)
            .arg(&old_exe)
            .arg(&setup_path);
        if spawn_detached(&mut cmd).is_ok() {
            win_api::schedule_delete_on_reboot(&waiter_path);
            return Ok(());
        }
        let _ = fs::remove_file(&waiter_path);
    }

    // Direct fallback if waiter copy could not be spawned: lock & verify SHA-256 before execution.
    let mut setup_lock = match open_setup_read_locked(&setup_path) {
        Ok(f) => f,
        Err(e) => {
            remove_file_with_retry(&setup_path);
            return Err(e);
        }
    };
    if let Err(err) = verify_locked_setup_sha256(&mut setup_lock, EMBEDDED_SETUP) {
        drop(setup_lock);
        remove_file_with_retry(&setup_path);
        return Err(err);
    }

    match spawn_detached(Command::new(&setup_path).arg("/SP-")) {
        Ok(_) => {
            drop(setup_lock);
            win_api::schedule_delete_on_reboot(&setup_path);
            Ok(())
        }
        Err(err) if err.raw_os_error() == Some(740) => {
            let run_res = win_api::run_elevated_setup_and_wait(&setup_path);
            drop(setup_lock);
            remove_file_with_retry(&setup_path);
            let _ = run_res?;
            Ok(())
        }
        Err(err) => {
            drop(setup_lock);
            remove_file_with_retry(&setup_path);
            Err(format!(
                "启动安装程序失败（{}）：{err}",
                setup_path.display()
            ))
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = if let Some(waiter) = parse_waiter_args(&args) {
        let r = run_waiter(waiter);
        if let Ok(waiter_exe) = std::env::current_exe() {
            schedule_waiter_self_cleanup(&waiter_exe);
        }
        r
    } else {
        run_primary()
    };

    if let Err(msg) = res {
        win_api::show_error(&format!("ClaudeGuard v{APP_VERSION} 升级引导"), &msg);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn sha256_matches_nist_vectors_and_detects_tampering_under_read_lock() {
        assert_eq!(
            hex_lower(&sha256_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_lower(&sha256_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let multi_block = vec![b'x'; 130_000];
        let dir = std::env::temp_dir().join(format!("cg-v3-sha-{}", unique_tag()));
        fs::create_dir_all(&dir).unwrap();
        let staged = write_unique_file(&dir, "setup", "exe", &multi_block).unwrap();

        let mut lock = open_setup_read_locked(&staged).expect("open read-locked setup");
        verify_locked_setup_sha256(&mut lock, &multi_block).expect("digest matches");
        assert!(verify_locked_setup_sha256(&mut lock, b"tampered").is_err());

        #[cfg(windows)]
        {
            // While `lock` is open with share_mode(1), external write and delete MUST fail!
            assert!(
                OpenOptions::new().write(true).open(&staged).is_err(),
                "share_mode(1) must block concurrent write open"
            );
            assert!(
                fs::remove_file(&staged).is_err(),
                "share_mode(1) must block concurrent unlink"
            );
        }

        drop(lock);
        remove_file_with_retry(&staged);
        assert!(!staged.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_waiter_args_with_spaces_and_unicode() {
        let args = vec![
            WAITER_FLAG.to_string(),
            r"C:\Program Files\ClaudeGuard\ClaudeGuard.exe".to_string(),
            r"C:\Program Files\ClaudeGuard\ClaudeGuard.exe.old".to_string(),
            r"C:\ProgramData\ClaudeGuard\staging\安装包 v4.0.0.exe".to_string(),
        ];
        let parsed = parse_waiter_args(&args).expect("waiter args should parse");
        assert_eq!(
            parsed.app_exe,
            PathBuf::from(r"C:\Program Files\ClaudeGuard\ClaudeGuard.exe")
        );
        assert_eq!(
            parsed.setup_exe,
            PathBuf::from(r"C:\ProgramData\ClaudeGuard\staging\安装包 v4.0.0.exe")
        );
        assert!(parse_waiter_args(&["--other".to_string()]).is_none());
    }

    #[test]
    fn migrates_v3_config_stripping_bom_and_rejecting_corrupt_or_non_object_json() {
        let base = std::env::temp_dir().join(format!("cg-v3-bridge-mig-{}", unique_tag()));
        let appdata = base.join("roaming");
        let progdata = base.join("progdata");
        fs::create_dir_all(appdata.join("ClaudeGuard")).unwrap();

        // 1) Corrupt JSON and JSON array are rejected.
        for invalid in [&b"{not-json"[..], &b"[1, 2, 3]"[..], &b"\"str\""[..]] {
            fs::write(appdata.join("ClaudeGuard").join("config.json"), invalid).unwrap();
            assert!(!migrate_config_if_absent(Some(&appdata), Some(&progdata)));
            assert!(!progdata.join("ClaudeGuard").join("config.json").exists());
        }

        // 2) UTF-8 BOM + valid nested JSON object is stripped of BOM and migrated atomically.
        let legacy_body = br#"{"version":3,"proxy_port":7890,"first_run":false,"targets":[{"id":"claude","expect_regions":["US"]}]}"#;
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(legacy_body);
        fs::write(appdata.join("ClaudeGuard").join("config.json"), &with_bom).unwrap();

        assert!(migrate_config_if_absent(Some(&appdata), Some(&progdata)));
        let migrated = fs::read(progdata.join("ClaudeGuard").join("config.json")).unwrap();
        assert_eq!(migrated, legacy_body, "UTF-8 BOM must be stripped");
        assert!(appdata.join("ClaudeGuard").join("config.json").is_file());

        // 3) Never overwrites an already-existing v4 config.json.
        let newer_cfg = br#"{"version":4,"proxy_port":17890}"#;
        fs::write(progdata.join("ClaudeGuard").join("config.json"), newer_cfg).unwrap();
        assert!(!migrate_config_if_absent(Some(&appdata), Some(&progdata)));
        assert_eq!(
            fs::read(progdata.join("ClaudeGuard").join("config.json")).unwrap(),
            newer_cfg
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn post_install_cleanup_preserves_bridge_on_cancel_and_removes_on_install() {
        let base = std::env::temp_dir().join(format!("cg-v3-bridge-clean-{}", unique_tag()));
        let app = base.join("app");
        let stage = base.join("staging");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&stage).unwrap();

        let app_exe = app.join("ClaudeGuard.exe");
        let old_exe = app.join("ClaudeGuard.exe.old");
        let setup_exe = stage.join("setup.exe");
        fs::write(&app_exe, b"bridge").unwrap();
        fs::write(&old_exe, b"old-v3").unwrap();
        fs::write(&setup_exe, b"setup").unwrap();

        let waiter_args = WaiterArgs {
            app_exe: app_exe.clone(),
            old_exe: old_exe.clone(),
            setup_exe: setup_exe.clone(),
        };

        let fake_pf = base.join("pf");
        let fake_home = base.join("home");
        let fake_roaming = base.join("roaming");
        fs::create_dir_all(fake_home.join("Desktop")).unwrap();
        fs::create_dir_all(
            fake_roaming
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs"),
        )
        .unwrap();
        let desktop_lnk = fake_home.join("Desktop").join("ClaudeGuard.lnk");
        let start_lnk = fake_roaming
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("ClaudeGuard.lnk");
        fs::write(&desktop_lnk, b"lnk").unwrap();
        fs::write(&start_lnk, b"lnk").unwrap();

        // Canceled install (non-zero status and no claudeguard-gui.exe): delete setup, keep bridge & shortcuts.
        cleanup_post_install_with(
            &waiter_args,
            false,
            Some(&fake_pf),
            Some(&fake_home),
            Some(&fake_roaming),
        );
        assert!(!setup_exe.exists());
        assert!(app_exe.is_file());
        assert!(old_exe.is_file());
        assert!(desktop_lnk.is_file());
        assert!(start_lnk.is_file());

        // Completed install (setup succeeded or claudeguard-gui.exe present): clean legacy residue & shortcuts.
        fs::write(&setup_exe, b"setup").unwrap();
        cleanup_post_install_with(
            &waiter_args,
            true,
            Some(&fake_pf),
            Some(&fake_home),
            Some(&fake_roaming),
        );
        assert!(!setup_exe.exists());
        assert!(!app_exe.exists());
        assert!(!old_exe.exists());
        assert!(!app.exists());
        assert!(!desktop_lnk.exists());
        assert!(!start_lnk.exists());

        #[cfg(all(windows, target_pointer_width = "64"))]
        assert_eq!(std::mem::size_of::<win_api::ShellExecuteInfoW>(), 112);

        let _ = fs::remove_dir_all(&base);
    }
}
