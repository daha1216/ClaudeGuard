use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type SdkVersion = (u32, u32, u32, u32);

fn parse_sdk_version(name: &str) -> Option<SdkVersion> {
    let mut parts = name.split('.');
    let a = parts.next()?.parse().ok()?;
    let b = parts.next()?.parse().ok()?;
    let c = parts.next()?.parse().ok()?;
    let d = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c, d))
}

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
        let mut candidates: Vec<(Option<SdkVersion>, String, PathBuf)> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                let rc = e.path().join("x64").join("rc.exe");
                if rc.is_file() {
                    Some((parse_sdk_version(&name), name, rc))
                } else {
                    None
                }
            })
            .collect();
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        if let Some((_, _, rc)) = candidates.into_iter().next() {
            return Some(rc);
        }
    }

    None
}

fn compile_version_res(
    rc_exe: &Path,
    out_dir: &Path,
    bin_name: &str,
    description: &str,
    major: u32,
    minor: u32,
    patch: u32,
) -> Option<PathBuf> {
    let version_str = format!("{major}.{minor}.{patch}");
    let version_4_str = format!("{major}.{minor}.{patch}.0");
    let exe_name = format!("{bin_name}.exe");
    let rc_path = out_dir.join(format!("{bin_name}_version.rc"));
    let res_path = out_dir.join(format!("{bin_name}_version.res"));

    let rc_content = format!(
        r#"#pragma code_page(65001)
1 VERSIONINFO
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
            VALUE "FileDescription", "{description}\0"
            VALUE "FileVersion", "{version_4_str}\0"
            VALUE "InternalName", "{bin_name}\0"
            VALUE "OriginalFilename", "{exe_name}\0"
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

    fs::write(&rc_path, rc_content).ok()?;
    let status = Command::new(rc_exe)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_path)
        .arg(&rc_path)
        .status()
        .ok()?;
    if status.success() && res_path.is_file() {
        Some(res_path)
    } else {
        None
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }

    let Some(rc_exe) = find_rc_exe() else {
        println!(
            "cargo:warning=Windows SDK rc.exe not found; binaries built without VERSIONINFO resource"
        );
        return;
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));
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

    if let Some(res) = compile_version_res(
        &rc_exe,
        &out_dir,
        "claudeguard-daemon",
        "ClaudeGuard v4 Network Egress Daemon Service",
        major,
        minor,
        patch,
    ) {
        println!(
            "cargo:rustc-link-arg-bin=claudeguard-daemon={}",
            res.display()
        );
    }

    if let Some(res) = compile_version_res(
        &rc_exe,
        &out_dir,
        "claudeguard-cli",
        "ClaudeGuard v4 CLI & Emergency Recovery Tool",
        major,
        minor,
        patch,
    ) {
        println!("cargo:rustc-link-arg-bin=claudeguard-cli={}", res.display());
    }
}
