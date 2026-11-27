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

fn compile_res(
    rc_exe: &Path,
    out_dir: &Path,
    icon_path: &Path,
    major: u32,
    minor: u32,
    patch: u32,
) -> Option<PathBuf> {
    let version_str = format!("{major}.{minor}.{patch}");
    let version_4_str = format!("{major}.{minor}.{patch}.0");
    let rc_path = out_dir.join("bridge_version.rc");
    let res_path = out_dir.join("bridge_version.res");

    let icon_line = if icon_path.is_file() {
        format!(
            "1 ICON \"{}\"\n",
            icon_path.display().to_string().replace('\\', "\\\\")
        )
    } else {
        String::new()
    };

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
            VALUE "FileDescription", "ClaudeGuard Upgrade Bridge\0"
            VALUE "FileVersion", "{version_4_str}\0"
            VALUE "InternalName", "ClaudeGuard-upgrade\0"
            VALUE "OriginalFilename", "ClaudeGuard-v{version_str}-upgrade.exe\0"
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
    println!("cargo::rustc-check-cfg=cfg(cg_has_embedded_setup)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=CG_V3_BRIDGE_SETUP_EXE");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "5.0.0".into());

    let setup_candidate = env::var_os("CG_V3_BRIDGE_SETUP_EXE")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            manifest_dir
                .join("..")
                .join("..")
                .join("installer")
                .join(format!("ClaudeGuard-v{ver}-setup.exe"))
        });

    if setup_candidate.is_file() {
        let abs = fs::canonicalize(&setup_candidate).unwrap_or(setup_candidate);
        println!("cargo:rerun-if-changed={}", abs.display());
        println!("cargo:rustc-cfg=cg_has_embedded_setup");
        println!("cargo:rustc-env=CG_EMBEDDED_SETUP_PATH={}", abs.display());
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }

    let Some(rc_exe) = find_rc_exe() else {
        return;
    };
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let icon_path = manifest_dir
        .join("..")
        .join("..")
        .join("assets")
        .join("claude.ico");
    let major: u32 = env::var("CARGO_PKG_VERSION_MAJOR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let minor: u32 = env::var("CARGO_PKG_VERSION_MINOR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let patch: u32 = env::var("CARGO_PKG_VERSION_PATCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if let Some(res) = compile_res(&rc_exe, &out_dir, &icon_path, major, minor, patch) {
        println!(
            "cargo:rustc-link-arg-bin=claudeguard-v3-bridge={}",
            res.display()
        );
    }
}
