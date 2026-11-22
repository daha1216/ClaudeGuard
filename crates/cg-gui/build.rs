use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_rc_exe() -> Option<PathBuf> {
    if let Ok(path) = env::var("PATH") {
        for dir in env::split_paths(&path) {
            let candidate = dir.join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    for prog_env in ["ProgramFiles(x86)", "ProgramFiles"] {
        let Ok(base) = env::var(prog_env) else {
            continue;
        };
        let bin_root = Path::new(&base).join("Windows Kits").join("10").join("bin");
        let Ok(entries) = fs::read_dir(&bin_root) else {
            continue;
        };
        let mut candidates: Vec<(String, PathBuf)> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                let rc = e.path().join("x64").join("rc.exe");
                if rc.is_file() { Some((name, rc)) } else { None }
            })
            .collect();
        candidates.sort_by(|a, b| b.0.cmp(&a.0));
        if let Some((_, rc)) = candidates.into_iter().next() {
            return Some(rc);
        }
    }

    None
}

/// Resolves a path and strips the Windows `\\?\` extended-length prefix that `rc.exe` rejects.
fn clean_rc_path(path: &Path) -> PathBuf {
    let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = resolved.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{unc}"))
    } else if let Some(stripped) = text.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        resolved
    }
}

fn compile_gui_res(
    rc_exe: &Path,
    out_dir: &Path,
    assets_dir: &Path,
    has_icon: bool,
    major: u32,
    minor: u32,
    patch: u32,
) -> Option<PathBuf> {
    let version_str = format!("{major}.{minor}.{patch}");
    let version_4_str = format!("{major}.{minor}.{patch}.0");
    let rc_path = out_dir.join("claudeguard_gui.rc");
    let res_path = out_dir.join("claudeguard_gui.res");

    let icon_line = if has_icon {
        "1 ICON \"claude.ico\"\n"
    } else {
        ""
    };

    // Intentionally omits `RT_MANIFEST`: `gpui` (`windows-manifest` feature enabled via
    // `gpui_platform`) already embeds `gpui.manifest.xml` (`level="asInvoker"`, `PerMonitorV2`,
    // `Common-Controls` v6, `SegmentHeap`) into `gpui.lib`. Adding `RT_MANIFEST #1` here would
    // trigger MSVC `CVTRES CVT1100` (duplicate resource).
    let rc_content = format!(
        r#"#pragma code_page(65001)
{icon_line}1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "daha1216\0"
            VALUE "FileDescription", "ClaudeGuard v4 Native GPUI Console & Tray HUD\0"
            VALUE "FileVersion", "{version_4_str}\0"
            VALUE "InternalName", "claudeguard-gui\0"
            VALUE "OriginalFilename", "claudeguard-gui.exe\0"
            VALUE "ProductName", "ClaudeGuard\0"
            VALUE "ProductVersion", "{version_str}\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#
    );

    if let Err(err) = fs::write(&rc_path, rc_content) {
        println!("cargo:warning=failed to write {}: {err}", rc_path.display());
        return None;
    }

    let mut cmd = Command::new(rc_exe);
    cmd.arg("/nologo");
    if has_icon {
        cmd.arg("/I").arg(assets_dir);
    }
    cmd.arg("/fo").arg(&res_path).arg(&rc_path);

    match cmd.status() {
        Ok(status) if status.success() && res_path.is_file() => Some(res_path),
        Ok(status) => {
            println!(
                "cargo:warning=rc.exe failed with exit status {status}; claudeguard-gui built without PE resources"
            );
            None
        }
        Err(err) => {
            println!(
                "cargo:warning=failed to invoke rc.exe ({err}); claudeguard-gui built without PE resources"
            );
            None
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=../../assets/claude.ico");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }

    let Some(rc_exe) = find_rc_exe() else {
        println!(
            "cargo:warning=Windows SDK rc.exe not found; claudeguard-gui built without ICON/VERSIONINFO resources"
        );
        return;
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));
    let assets_dir = clean_rc_path(&manifest_dir.join("..").join("..").join("assets"));
    let has_icon = assets_dir.join("claude.ico").is_file();
    if !has_icon {
        println!(
            "cargo:warning=assets/claude.ico not found at {}; claudeguard-gui built without embedded icon",
            assets_dir.display()
        );
    }

    let major: u32 = env::var("CARGO_PKG_VERSION_MAJOR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let minor: u32 = env::var("CARGO_PKG_VERSION_MINOR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let patch: u32 = env::var("CARGO_PKG_VERSION_PATCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if let Some(res) = compile_gui_res(
        &rc_exe,
        &out_dir,
        &assets_dir,
        has_icon,
        major,
        minor,
        patch,
    ) {
        println!("cargo:rustc-link-arg-bin=claudeguard-gui={}", res.display());
    }
}
