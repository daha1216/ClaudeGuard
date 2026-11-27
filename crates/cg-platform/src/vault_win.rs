//! M4: Sovereign Multi-Account Isolated Vaults filesystem, machine-id seeding,
//! MSIX lockfile strategy, launch planning, and shortcut generator.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use cg_protocol::{is_valid_vault_id, AccountVault, MsixIsolationMode, VaultAppTarget};
use serde::{Deserialize, Serialize};

use crate::crypto_win;

/// Directory name used to archive soft-deleted vaults safely without data loss.
pub const ARCHIVED_VAULTS_DIR: &str = "_archived";

/// All isolated physical paths belonging to a single Sovereign Account Vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPaths {
    pub vault_id: String,
    pub vault_root: PathBuf,
    pub meta_json: PathBuf,
    pub state_json: PathBuf,
    pub geo_ledger_json: PathBuf,
    pub claude_desktop: PathBuf,
    pub chatgpt_desktop: PathBuf,
    pub antigravity_ide: PathBuf,
    pub antigravity_extensions: PathBuf,
    pub claude_code_home: PathBuf,
    pub codex_home: PathBuf,
    pub codex_sqlite_home: PathBuf,
    pub shortcuts_dir: PathBuf,
}

impl VaultPaths {
    /// Derive deterministic isolated paths rooted under `vault_root`.
    pub fn from_root(vault_id: &str, vault_root: PathBuf) -> Self {
        let antigravity_ide = vault_root.join("antigravity_ide");
        let codex_home = vault_root.join("codex_home");
        Self {
            vault_id: vault_id.to_string(),
            meta_json: vault_root.join("meta.json"),
            state_json: vault_root.join("vault_state.json"),
            geo_ledger_json: vault_root.join("geo_ledger.json"),
            claude_desktop: vault_root.join("claude_desktop"),
            chatgpt_desktop: vault_root.join("chatgpt_desktop"),
            antigravity_extensions: antigravity_ide.join("extensions"),
            antigravity_ide,
            claude_code_home: vault_root.join("claude_code_home"),
            codex_sqlite_home: codex_home.join("sqlite"),
            codex_home,
            shortcuts_dir: vault_root.join("shortcuts"),
            vault_root,
        }
    }

    fn all_isolated_dirs(&self) -> Vec<&Path> {
        vec![
            &self.vault_root,
            &self.claude_desktop,
            &self.chatgpt_desktop,
            &self.antigravity_ide,
            &self.antigravity_extensions,
            &self.claude_code_home,
            &self.codex_home,
            &self.codex_sqlite_home,
            &self.shortcuts_dir,
        ]
    }
}

/// Persisted metadata written to `<vault_root>\meta.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDiskMeta {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub accent_hex: String,
    pub pinned_regions: Vec<String>,
    pub pinned_ips: Vec<String>,
    pub pinned_asn: Option<u32>,
    pub dedicated_proxy_port: Option<u16>,
    pub share_ide_extensions: bool,
    pub msix_isolation_mode: MsixIsolationMode,
}

/// Execution strategy for MSIX-packaged Electron desktop apps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum MsixLaunchStrategy {
    /// Non-MSIX app (CLI or standard unpackaged IDE).
    NotApplicable,
    /// Direct unpackaged binary launch with `--user-data-dir` + post-launch lockfile verification.
    DirectUnpackagedWithLockVerify { lock_candidates: Vec<PathBuf> },
    /// Strict single-instance exclusive profile swap lock (prevents concurrent cross-account VFS bleed).
    ExclusiveSwapLock {
        active_lock_file: PathBuf,
        package_cache_hint: String,
    },
}

/// Complete launch specification produced for one `(vault, app)` pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultLaunchSpec {
    pub vault_id: String,
    pub app: VaultAppTarget,
    pub user_data_dir: Option<PathBuf>,
    pub extensions_dir: Option<PathBuf>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub working_dir: Option<PathBuf>,
    pub effective_proxy_port: u16,
    pub msix_isolation_mode: MsixIsolationMode,
    pub msix_strategy: MsixLaunchStrategy,
}

/// Rejects any NTFS junction, mount point, or symbolic link (`FILE_ATTRIBUTE_REPARSE_POINT`)
/// across EVERY existing ancestor component and the target path itself, while also blocking
/// `..` traversal components and embedded NUL characters.
pub fn ensure_no_reparse_points_chain(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("路径为空，已拒绝磁盘操作".into());
    }
    if path.to_string_lossy().contains('\0') {
        return Err("路径包含非法 NUL 字符，已拒绝磁盘操作".into());
    }

    let mut cur = PathBuf::new();
    let mut missing_seen = false;
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(format!(
                "安全拦截：路径包含父级穿越组件 `..`（{}），已拒绝操作",
                path.display()
            ));
        }
        cur.push(comp.as_os_str());
        if matches!(
            comp,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        if missing_seen {
            continue;
        }
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing_seen = true;
            }
            Err(e) => {
                return Err(format!("校验路径安全性失败（{}）：{e}", cur.display()));
            }
        }
    }
    Ok(())
}

/// Safely creates directory tree component-by-component, rejecting reparse points at every level.
pub fn safe_create_dir_all_no_reparse(path: &Path) -> Result<(), String> {
    ensure_no_reparse_points_chain(path)?;
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp.as_os_str());
        if matches!(
            comp,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_reparse_or_symlink(&meta) {
                    return Err(format!(
                        "安全拦截：目录链路中检测到重解析点（{}）",
                        cur.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!("目标路径已存在同名非目录文件：{}", cur.display()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur)
                    .map_err(|err| format!("创建目录失败（{}）：{err}", cur.display()))?;
                // Re-verify immediately after creation.
                ensure_no_reparse_points_chain(&cur)?;
            }
            Err(e) => {
                return Err(format!("检查目录失败（{}）：{e}", cur.display()));
            }
        }
    }
    Ok(())
}

/// Safely removes a file or directory tree without EVER recursing through NTFS junctions or symlinks.
pub fn safe_remove_path_no_reparse(path: &Path) -> Result<(), String> {
    ensure_no_reparse_points_chain(path.parent().unwrap_or(path))?;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("读取目标元数据失败（{}）：{e}", path.display())),
    };
    if is_reparse_or_symlink(&meta) {
        return Err(format!(
            "安全拦截：目标路径为符号链接或重解析点（{}），拒绝递归删除",
            path.display()
        ));
    }
    if meta.is_file() {
        std::fs::remove_file(path)
            .map_err(|e| format!("删除文件失败（{}）：{e}", path.display()))?;
        return Ok(());
    }
    if meta.is_dir() {
        let entries = std::fs::read_dir(path)
            .map_err(|e| format!("读取目录失败（{}）：{e}", path.display()))?;
        for entry_res in entries {
            let entry =
                entry_res.map_err(|e| format!("遍历目录项失败（{}）：{e}", path.display()))?;
            let child = entry.path();
            let cmeta = std::fs::symlink_metadata(&child)
                .map_err(|e| format!("读取子项元数据失败（{}）：{e}", child.display()))?;
            if is_reparse_or_symlink(&cmeta) {
                // Remove only the link/junction stub itself; NEVER recurse into its target!
                if cmeta.is_dir() {
                    let _ = std::fs::remove_dir(&child);
                } else {
                    let _ = std::fs::remove_file(&child);
                }
            } else if cmeta.is_dir() {
                safe_remove_path_no_reparse(&child)?;
            } else {
                std::fs::remove_file(&child)
                    .map_err(|e| format!("删除子文件失败（{}）：{e}", child.display()))?;
            }
        }
        std::fs::remove_dir(path)
            .map_err(|e| format!("删除空目录失败（{}）：{e}", path.display()))?;
    }
    Ok(())
}

pub(crate) fn is_reparse_or_symlink(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Atomically writes `bytes` to `target_path` using a randomized temp file in the same directory
/// after verifying zero reparse points along the entire ancestor chain.
pub(crate) fn atomic_write_no_reparse(target_path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = target_path
        .parent()
        .ok_or_else(|| format!("目标路径缺少父目录：{}", target_path.display()))?;
    safe_create_dir_all_no_reparse(parent)?;
    ensure_no_reparse_points_chain(target_path)?;

    let suffix = crypto_win::random_hex(6).unwrap_or_else(|_| "tmp".into());
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let tmp_path = parent.join(format!(".{file_name}.cg-tmp-{suffix}"));
    ensure_no_reparse_points_chain(&tmp_path)?;

    std::fs::write(&tmp_path, bytes)
        .map_err(|e| format!("写入临时文件失败（{}）：{e}", tmp_path.display()))?;

    // Re-check target path before replacing without following symlinks.
    ensure_no_reparse_points_chain(target_path)?;
    if std::fs::symlink_metadata(target_path).is_ok() {
        let _ = std::fs::remove_file(target_path);
    }
    if let Err(e) = std::fs::rename(&tmp_path, target_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!(
            "原子替换文件失败（{}）：{e}",
            target_path.display()
        ));
    }
    Ok(())
}

/// Validate a `vault_id` strictly using `cg_protocol::is_valid_vault_id`.
pub fn validate_vault_id(vault_id: &str) -> Result<(), String> {
    if !is_valid_vault_id(vault_id) {
        return Err(format!(
            "非法的账号仓标识 `{vault_id}`：仅允许 2-32 位小写字母、数字、`-`、`_`，且禁止保留设备名与路径穿越"
        ));
    }
    Ok(())
}

/// Computes `<home>\AppData\Local\ClaudeGuard\Vaults` for a resolved interactive user home.
pub fn vaults_root_for_user_home(home: &Path) -> PathBuf {
    home.join("AppData")
        .join("Local")
        .join("ClaudeGuard")
        .join("Vaults")
}

fn is_service_profile_path(path: &Path) -> bool {
    let low = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    low.contains(r"\windows\system32\config\systemprofile")
        || low.contains(r"\windows\syswow64\config\systemprofile")
        || low.contains(r"\windows\serviceprofiles\")
}

/// Resolves the default `%LOCALAPPDATA%\ClaudeGuard\Vaults` root directory, routing to the
/// interactive user's profile when invoked from Session 0 (`LocalSystem`) or a service profile.
pub fn default_vaults_root() -> Result<PathBuf, String> {
    let root = if crate::access_win::is_session_zero() {
        let home = crate::process_win::user_home_dirs()
            .into_iter()
            .next()
            .ok_or_else(|| {
                "服务会话未检测到交互式用户主目录，无法定位主权隔离仓目录".to_string()
            })?;
        vaults_root_for_user_home(&home)
    } else {
        let env_local = std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| !is_service_profile_path(p))
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
                    .filter(|h| !is_service_profile_path(h))
                    .map(|h| h.join("AppData").join("Local"))
            });
        match env_local {
            Some(base) => base.join("ClaudeGuard").join("Vaults"),
            None => {
                let home = crate::process_win::user_home_dirs()
                    .into_iter()
                    .next()
                    .ok_or_else(|| "无法解析 LOCALAPPDATA 或 USERPROFILE 环境变量".to_string())?;
                vaults_root_for_user_home(&home)
            }
        }
    };
    ensure_no_reparse_points_chain(&root)?;
    Ok(root)
}

/// Safely resolves `%LOCALAPPDATA%\ClaudeGuard\Vaults\<vault_id>` with strict ID and reparse validation.
pub fn resolve_vault_root(vault_id: &str) -> Result<PathBuf, String> {
    let base = default_vaults_root()?;
    resolve_vault_root_under(&base, vault_id)
}

/// Safely resolves `<vaults_root>\<vault_id>` with strict ID and ancestor reparse-point validation.
pub fn resolve_vault_root_under(vaults_root: &Path, vault_id: &str) -> Result<PathBuf, String> {
    validate_vault_id(vault_id)?;
    ensure_no_reparse_points_chain(vaults_root)?;
    let vault_root = vaults_root.join(vault_id);
    ensure_no_reparse_points_chain(&vault_root)?;
    Ok(vault_root)
}

/// Creates the complete Sovereign Vault directory layout under `%LOCALAPPDATA%\ClaudeGuard\Vaults\<id>`,
/// writes `meta.json`, and seeds unique randomized IDE telemetry fingerprints (`storage.json`).
pub fn ensure_vault_layout(vault: &AccountVault) -> Result<VaultPaths, String> {
    let base = default_vaults_root()?;
    ensure_vault_layout_in(&base, vault)
}

/// Testable variant of [`ensure_vault_layout`] anchored at an explicit `vaults_root`.
pub fn ensure_vault_layout_in(
    vaults_root: &Path,
    vault: &AccountVault,
) -> Result<VaultPaths, String> {
    let vault_root = resolve_vault_root_under(vaults_root, &vault.id)?;
    let paths = VaultPaths::from_root(&vault.id, vault_root);

    for dir in paths.all_isolated_dirs() {
        safe_create_dir_all_no_reparse(dir)?;
    }

    // Seed unique randomized machine IDs for Antigravity IDE (idempotent: preserves existing IDs).
    seed_isolated_ide_telemetry_ids(&paths.antigravity_ide)?;

    // Seed a fresh uncorrelated anonymousId in Claude Code isolated home if not yet initialized.
    seed_isolated_claude_code_state(&paths.claude_code_home)?;

    // Persist vault metadata atomically.
    let meta = VaultDiskMeta {
        schema_version: 1,
        id: vault.id.clone(),
        name: vault.name.clone(),
        accent_hex: vault.accent_hex.clone(),
        pinned_regions: vault.pinned_regions.clone(),
        pinned_ips: vault.pinned_ips.clone(),
        pinned_asn: vault.pinned_asn,
        dedicated_proxy_port: vault.dedicated_proxy_port,
        share_ide_extensions: vault.share_ide_extensions,
        msix_isolation_mode: vault.msix_isolation_mode,
    };
    let meta_bytes = serde_json::to_vec_pretty(&meta)
        .map_err(|e| format!("序列化账号仓 meta.json 失败：{e}"))?;
    atomic_write_no_reparse(&paths.meta_json, &meta_bytes)?;

    Ok(paths)
}

/// Seeds unique cryptographically random `telemetry.machineId`, `telemetry.macMachineId`,
/// `telemetry.devDeviceId`, and `telemetry.sqmId` into `<ide_user_data_dir>\User\globalStorage\storage.json`.
///
/// Idempotent: preserves existing telemetry keys and unrelated user settings if already present.
pub fn seed_isolated_ide_telemetry_ids(ide_user_data_dir: &Path) -> Result<PathBuf, String> {
    let storage_dir = ide_user_data_dir.join("User").join("globalStorage");
    safe_create_dir_all_no_reparse(&storage_dir)?;
    let storage_path = storage_dir.join("storage.json");
    ensure_no_reparse_points_chain(&storage_path)?;

    let mut root_obj = if storage_path.exists() {
        let raw = std::fs::read(&storage_path).map_err(|e| {
            format!(
                "读取 IDE storage.json 失败（{}）：{e}",
                storage_path.display()
            )
        })?;
        serde_json::from_slice::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
    } else {
        serde_json::Map::new()
    };

    let mut changed = !storage_path.exists();
    if !has_non_empty_str(&root_obj, "telemetry.machineId") {
        root_obj.insert(
            "telemetry.machineId".into(),
            serde_json::Value::String(crypto_win::random_hex(32)?),
        );
        changed = true;
    }
    if !has_non_empty_str(&root_obj, "telemetry.macMachineId") {
        root_obj.insert(
            "telemetry.macMachineId".into(),
            serde_json::Value::String(crypto_win::random_hex(32)?),
        );
        changed = true;
    }
    if !has_non_empty_str(&root_obj, "telemetry.devDeviceId") {
        root_obj.insert(
            "telemetry.devDeviceId".into(),
            serde_json::Value::String(crypto_win::random_uuid_v4()?),
        );
        changed = true;
    }
    if !has_non_empty_str(&root_obj, "telemetry.sqmId") {
        let sqm = format!("{{{}}}", crypto_win::random_uuid_v4()?.to_ascii_uppercase());
        root_obj.insert("telemetry.sqmId".into(), serde_json::Value::String(sqm));
        changed = true;
    }

    if changed {
        let payload = serde_json::to_vec_pretty(&serde_json::Value::Object(root_obj))
            .map_err(|e| format!("序列化 storage.json 失败：{e}"))?;
        atomic_write_no_reparse(&storage_path, &payload)?;
    }

    Ok(storage_path)
}

fn seed_isolated_claude_code_state(claude_code_home: &Path) -> Result<PathBuf, String> {
    safe_create_dir_all_no_reparse(claude_code_home)?;
    let state_path = claude_code_home.join(".claude.json");
    ensure_no_reparse_points_chain(&state_path)?;
    if !state_path.exists() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "anonymousId".into(),
            serde_json::Value::String(crypto_win::random_uuid_v4()?),
        );
        let bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(obj))
            .map_err(|e| format!("序列化仓内 .claude.json 失败：{e}"))?;
        atomic_write_no_reparse(&state_path, &bytes)?;
    }
    Ok(state_path)
}

fn has_non_empty_str(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    map.get(key)
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty())
}

/// Plans isolated CLI arguments, environment variables, proxy overrides, and MSIX isolation strategy
/// for launching `app` inside `vault`.
pub fn plan_vault_launch_env_and_args(
    vault: &AccountVault,
    app: VaultAppTarget,
    proxy_host: &str,
    default_proxy_port: u16,
    extra_args: &[String],
) -> Result<VaultLaunchSpec, String> {
    let base = default_vaults_root()?;
    let home = if crate::access_win::is_session_zero() {
        crate::process_win::user_home_dirs().into_iter().next()
    } else {
        std::env::var_os("USERPROFILE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|h| !is_service_profile_path(h))
            .or_else(|| crate::process_win::user_home_dirs().into_iter().next())
    };
    plan_vault_launch_env_and_args_in(
        &base,
        home.as_deref(),
        vault,
        app,
        proxy_host,
        default_proxy_port,
        extra_args,
    )
}

/// Testable variant of [`plan_vault_launch_env_and_args`] using explicit `vaults_root` & `user_home`.
pub fn plan_vault_launch_env_and_args_in(
    vaults_root: &Path,
    user_home: Option<&Path>,
    vault: &AccountVault,
    app: VaultAppTarget,
    proxy_host: &str,
    default_proxy_port: u16,
    extra_args: &[String],
) -> Result<VaultLaunchSpec, String> {
    let vault_root = resolve_vault_root_under(vaults_root, &vault.id)?;
    let paths = VaultPaths::from_root(&vault.id, vault_root);

    let host = proxy_host.trim();
    if host.contains('\0') || host.contains('\n') || host.contains('\r') {
        return Err("代理主机地址包含非法控制字符".into());
    }
    for arg in extra_args {
        if arg.contains('\0') {
            return Err("启动附加参数包含非法 NUL 字符".into());
        }
    }

    let effective_proxy_port = vault
        .dedicated_proxy_port
        .filter(|&p| p > 0)
        .unwrap_or(default_proxy_port);

    let mut env = BTreeMap::new();
    env.insert("CG_VAULT_ID".into(), vault.id.clone());

    if !host.is_empty() && effective_proxy_port > 0 {
        let http_proxy = format!("http://{host}:{effective_proxy_port}");
        let socks_proxy = format!("socks5h://{host}:{effective_proxy_port}");
        env.insert("HTTP_PROXY".into(), http_proxy.clone());
        env.insert("HTTPS_PROXY".into(), http_proxy.clone());
        env.insert("http_proxy".into(), http_proxy.clone());
        env.insert("https_proxy".into(), http_proxy);
        env.insert("ALL_PROXY".into(), socks_proxy);
        env.insert("NO_PROXY".into(), "localhost,127.0.0.1,::1".into());
    }

    let mut args = Vec::new();
    let mut user_data_dir = None;
    let mut extensions_dir = None;
    let mut msix_strategy = MsixLaunchStrategy::NotApplicable;

    match app {
        VaultAppTarget::ClaudeDesktop => {
            user_data_dir = Some(paths.claude_desktop.clone());
            args.push(format!(
                "--user-data-dir={}",
                paths.claude_desktop.display()
            ));
            msix_strategy = build_msix_strategy(
                vaults_root,
                "claude",
                &paths.claude_desktop,
                vault.msix_isolation_mode,
                r"Packages\Claude_*\LocalCache\Roaming\Claude",
            );
        }
        VaultAppTarget::ChatgptDesktop => {
            user_data_dir = Some(paths.chatgpt_desktop.clone());
            args.push(format!(
                "--user-data-dir={}",
                paths.chatgpt_desktop.display()
            ));
            msix_strategy = build_msix_strategy(
                vaults_root,
                "chatgpt",
                &paths.chatgpt_desktop,
                vault.msix_isolation_mode,
                r"Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT",
            );
        }
        VaultAppTarget::AntigravityIde => {
            configure_vscode_family_launch(
                &paths.antigravity_ide,
                &paths.antigravity_extensions,
                user_home,
                ".antigravity",
                vault.share_ide_extensions,
                &mut user_data_dir,
                &mut extensions_dir,
                &mut args,
            );
        }
        VaultAppTarget::ClaudeCodeCli => {
            env.insert(
                "CLAUDE_CONFIG_DIR".into(),
                paths.claude_code_home.to_string_lossy().to_string(),
            );
        }
        VaultAppTarget::CodexCli => {
            env.insert(
                "CODEX_HOME".into(),
                paths.codex_home.to_string_lossy().to_string(),
            );
            env.insert(
                "CODEX_SQLITE_HOME".into(),
                paths.codex_sqlite_home.to_string_lossy().to_string(),
            );
        }
    }

    for extra in extra_args {
        args.push(extra.clone());
    }

    Ok(VaultLaunchSpec {
        vault_id: vault.id.clone(),
        app,
        user_data_dir,
        extensions_dir,
        args,
        env,
        working_dir: Some(paths.vault_root),
        effective_proxy_port,
        msix_isolation_mode: vault.msix_isolation_mode,
        msix_strategy,
    })
}

#[allow(clippy::too_many_arguments)]
fn configure_vscode_family_launch(
    ide_dir: &Path,
    isolated_ext_dir: &Path,
    user_home: Option<&Path>,
    dot_dir_name: &str,
    share_ide_extensions: bool,
    user_data_dir: &mut Option<PathBuf>,
    extensions_dir: &mut Option<PathBuf>,
    args: &mut Vec<String>,
) {
    *user_data_dir = Some(ide_dir.to_path_buf());
    args.push(format!("--user-data-dir={}", ide_dir.display()));

    let chosen_ext = if share_ide_extensions {
        user_home
            .map(|h| h.join(dot_dir_name).join("extensions"))
            .filter(|p| ensure_no_reparse_points_chain(p).is_ok())
            .unwrap_or_else(|| isolated_ext_dir.to_path_buf())
    } else {
        isolated_ext_dir.to_path_buf()
    };
    args.push(format!("--extensions-dir={}", chosen_ext.display()));
    *extensions_dir = Some(chosen_ext);
}

fn build_msix_strategy(
    vaults_root: &Path,
    agent_id: &str,
    user_data_dir: &Path,
    mode: MsixIsolationMode,
    package_cache_hint: &str,
) -> MsixLaunchStrategy {
    match mode {
        MsixIsolationMode::AutoVerifyLock => MsixLaunchStrategy::DirectUnpackagedWithLockVerify {
            lock_candidates: vec![
                user_data_dir.join("lockfile"),
                user_data_dir.join("SingletonLock"),
                user_data_dir.join("SingletonCookie"),
            ],
        },
        MsixIsolationMode::ExclusiveSwapLock => MsixLaunchStrategy::ExclusiveSwapLock {
            active_lock_file: vaults_root.join(format!(".msix_active_{agent_id}.lock")),
            package_cache_hint: package_cache_hint.to_string(),
        },
    }
}

/// Returns `true` when `exe_path` resides inside a Windows Store / MSIX container path.
pub fn detect_msix_install_path(exe_path: &Path) -> bool {
    let norm = exe_path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    norm.contains(r"\windowsapps\") || norm.contains(r"\appdata\local\packages\")
}

/// Checks whether Chromium/Electron created or holds a profile lockfile inside `user_data_dir`,
/// proving `--user-data-dir` isolation actually took effect on disk.
pub fn verify_vault_lockfile_active(user_data_dir: &Path) -> bool {
    if ensure_no_reparse_points_chain(user_data_dir).is_err() {
        return false;
    }
    for name in ["lockfile", "SingletonLock", "SingletonCookie"] {
        let p = user_data_dir.join(name);
        if let Ok(meta) = std::fs::symlink_metadata(&p) {
            if !is_reparse_or_symlink(&meta) {
                return true;
            }
        }
    }
    false
}

/// Acquires an exclusive single-instance MSIX lock for `(agent_id, vault_id)`.
/// Rejects launch if another vault currently owns the active MSIX container.
pub fn acquire_msix_exclusive_lock(
    vaults_root: &Path,
    agent_id: &str,
    vault_id: &str,
    now_secs: u64,
) -> Result<PathBuf, String> {
    validate_vault_id(vault_id)?;
    let safe_agent = sanitize_filename_component(agent_id);
    if safe_agent.is_empty() {
        return Err("非法的 MSIX 应用标识".into());
    }
    safe_create_dir_all_no_reparse(vaults_root)?;
    let lock_path = vaults_root.join(format!(".msix_active_{safe_agent}.lock"));
    ensure_no_reparse_points_chain(&lock_path)?;

    if lock_path.exists() {
        let raw = std::fs::read_to_string(&lock_path).unwrap_or_default();
        if let Some(holder) = raw.lines().next().map(str::trim).filter(|s| !s.is_empty()) {
            if holder != vault_id {
                return Err(format!(
                    "检测到 MSIX 版客户端受系统沙箱单实例限制，当前由账号仓 `{holder}` 独占运行，请先关闭后再启动 `{vault_id}`"
                ));
            }
        }
    }

    let payload = format!("{vault_id}\n{now_secs}\n");
    atomic_write_no_reparse(&lock_path, payload.as_bytes())?;
    Ok(lock_path)
}

/// Releases an exclusive single-instance MSIX lock if currently held by `vault_id`.
pub fn release_msix_exclusive_lock(
    vaults_root: &Path,
    agent_id: &str,
    vault_id: &str,
) -> Result<(), String> {
    validate_vault_id(vault_id)?;
    let safe_agent = sanitize_filename_component(agent_id);
    let lock_path = vaults_root.join(format!(".msix_active_{safe_agent}.lock"));
    ensure_no_reparse_points_chain(&lock_path)?;
    if !lock_path.exists() {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&lock_path).unwrap_or_default();
    let holder = raw.lines().next().map(str::trim).unwrap_or("");
    if holder.is_empty() || holder == vault_id {
        std::fs::remove_file(&lock_path)
            .map_err(|e| format!("释放 MSIX 独占锁失败（{}）：{e}", lock_path.display()))?;
    }
    Ok(())
}

/// Generates PowerShell/CMD vault shims and desktop `.lnk` direct-launch shortcuts (via Win32
/// `IShellLinkW`, falling back cleanly to `.cmd` if COM shortcut creation is unavailable).
pub fn generate_vault_shortcuts(
    vault: &AccountVault,
    cli_exe: &Path,
    desktop_dir: &Path,
) -> Result<Vec<PathBuf>, String> {
    let base = default_vaults_root()?;
    generate_vault_shortcuts_in(&base, vault, cli_exe, desktop_dir)
}

/// Testable variant of [`generate_vault_shortcuts`] anchored at an explicit `vaults_root`.
pub fn generate_vault_shortcuts_in(
    vaults_root: &Path,
    vault: &AccountVault,
    cli_exe: &Path,
    desktop_dir: &Path,
) -> Result<Vec<PathBuf>, String> {
    let paths = ensure_vault_layout_in(vaults_root, vault)?;
    ensure_no_reparse_points_chain(desktop_dir)?;
    safe_create_dir_all_no_reparse(desktop_dir)?;

    let cli_str = cli_exe.to_string_lossy();
    if cli_str.trim().is_empty() || cli_str.contains('\0') {
        return Err("无效的 claudeguard-cli 可执行文件路径".into());
    }

    let safe_label = {
        let s = sanitize_filename_component(&vault.name);
        if s.is_empty() {
            vault.id.clone()
        } else {
            s
        }
    };

    let mut generated = Vec::new();

    // 1. PowerShell 7 / Windows PowerShell 5.1 compatible vault environment init script (UTF-8 BOM + CRLF).
    let ps1_path = paths.shortcuts_dir.join("vault-shell-init.ps1");
    let proxy_line = match vault.dedicated_proxy_port.filter(|&p| p > 0) {
        Some(port) => format!(
            "$env:HTTP_PROXY = 'http://127.0.0.1:{port}'\r\n$env:HTTPS_PROXY = 'http://127.0.0.1:{port}'\r\n$env:ALL_PROXY = 'socks5h://127.0.0.1:{port}'\r\n$env:NO_PROXY = 'localhost,127.0.0.1,::1'\r\n"
        ),
        None => String::new(),
    };
    let ps1_body = format!(
        "# ClaudeGuard v5 主权账号仓终端环境脚本\r\n\
         # Vault: {id} ({name})\r\n\
         $env:CG_VAULT_ID = '{id_esc}'\r\n\
         $env:CLAUDE_CONFIG_DIR = '{claude_dir}'\r\n\
         $env:CODEX_HOME = '{codex_dir}'\r\n\
         $env:CODEX_SQLITE_HOME = '{codex_sql}'\r\n\
         {proxy_line}\
         Write-Host \"[ClaudeGuard Vault] 已切换至主权隔离仓: {name_esc} ({id_esc})\" -ForegroundColor Cyan\r\n",
        id = vault.id,
        name = safe_label,
        id_esc = escape_ps_single_quoted(&vault.id),
        name_esc = escape_ps_single_quoted(&safe_label),
        claude_dir = escape_ps_single_quoted(&paths.claude_code_home.to_string_lossy()),
        codex_dir = escape_ps_single_quoted(&paths.codex_home.to_string_lossy()),
        codex_sql = escape_ps_single_quoted(&paths.codex_sqlite_home.to_string_lossy()),
        proxy_line = proxy_line,
    );
    let mut ps1_bytes = vec![0xEF, 0xBB, 0xBF];
    ps1_bytes.extend_from_slice(ps1_body.as_bytes());
    atomic_write_no_reparse(&ps1_path, &ps1_bytes)?;
    generated.push(ps1_path);

    // 2. CMD launch shim inside the vault's shortcuts directory.
    let shim_cmd_path = paths.shortcuts_dir.join("launch-vault.cmd");
    let shim_cmd = format!(
        "@echo off\r\n\
         setlocal\r\n\
         set \"APP=%~1\"\r\n\
         if \"%APP%\"==\"\" set \"APP=claude_desktop\"\r\n\
         \"{cli}\" vault launch --vault \"{id}\" --app \"%APP%\"\r\n",
        cli = cli_str.replace('"', ""),
        id = vault.id,
    );
    atomic_write_no_reparse(&shim_cmd_path, shim_cmd.as_bytes())?;
    generated.push(shim_cmd_path);

    // 3. Desktop direct-launch shortcuts (.lnk via Win32 COM IShellLinkW, or .cmd fallback).
    let targets = [
        ("Claude", "claude_desktop", "启动 Claude Desktop 主权隔离仓"),
        (
            "Claude Code",
            "claude_code_cli",
            "启动 Claude Code 主权隔离仓",
        ),
    ];
    for (prefix, app_flag, desc) in targets {
        let base_name = format!("{prefix} ({safe_label})");
        let lnk_path = desktop_dir.join(format!("{base_name}.lnk"));
        let args = format!("vault launch --vault {} --app {}", vault.id, app_flag);
        let full_desc = format!("ClaudeGuard - {desc} ({})", vault.id);

        ensure_no_reparse_points_chain(&lnk_path)?;
        match create_windows_shell_link(&lnk_path, cli_exe, &args, &paths.vault_root, &full_desc) {
            Ok(()) => {
                generated.push(lnk_path);
            }
            Err(_) => {
                let fallback_cmd = desktop_dir.join(format!("{base_name}.cmd"));
                let body = format!(
                    "@echo off\r\n\"{cli}\" {args}\r\n",
                    cli = cli_str.replace('"', ""),
                    args = args,
                );
                atomic_write_no_reparse(&fallback_cmd, body.as_bytes())?;
                generated.push(fallback_cmd);
            }
        }
    }

    Ok(generated)
}

#[cfg(windows)]
fn create_windows_shell_link(
    lnk_path: &Path,
    target_exe: &Path,
    arguments: &str,
    working_dir: &Path,
    description: &str,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{CoCreateInstance, IPersistFile, CLSCTX_INPROC_SERVER};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

    ensure_no_reparse_points_chain(lnk_path)?;
    let _com = crate::com::ComGuard::init_mta().map_err(|e| e.to_string())?;

    let to_wide = |s: &std::ffi::OsStr| -> Vec<u16> { s.encode_wide().chain(Some(0)).collect() };
    let wide_exe = to_wide(target_exe.as_os_str());
    let wide_args = to_wide(std::ffi::OsStr::new(arguments));
    let wide_wd = to_wide(working_dir.as_os_str());
    let wide_desc = to_wide(std::ffi::OsStr::new(description));
    let wide_lnk = to_wide(lnk_path.as_os_str());

    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("CoCreateInstance(ShellLink) failed: {e}"))?;
        link.SetPath(PCWSTR::from_raw(wide_exe.as_ptr()))
            .map_err(|e| format!("IShellLinkW::SetPath failed: {e}"))?;
        link.SetArguments(PCWSTR::from_raw(wide_args.as_ptr()))
            .map_err(|e| format!("IShellLinkW::SetArguments failed: {e}"))?;
        link.SetWorkingDirectory(PCWSTR::from_raw(wide_wd.as_ptr()))
            .map_err(|e| format!("IShellLinkW::SetWorkingDirectory failed: {e}"))?;
        link.SetDescription(PCWSTR::from_raw(wide_desc.as_ptr()))
            .map_err(|e| format!("IShellLinkW::SetDescription failed: {e}"))?;

        let persist: IPersistFile = link
            .cast()
            .map_err(|e| format!("QueryInterface(IPersistFile) failed: {e}"))?;
        persist
            .Save(PCWSTR::from_raw(wide_lnk.as_ptr()), true)
            .map_err(|e| format!("IPersistFile::Save failed: {e}"))?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn create_windows_shell_link(
    _lnk_path: &Path,
    _target_exe: &Path,
    _arguments: &str,
    _working_dir: &Path,
    _description: &str,
) -> Result<(), String> {
    Err("IShellLinkW shortcuts are only available on Windows".into())
}

/// Removes or safely archives a Sovereign Vault's files on disk.
///
/// When `purge_disk_data == false`, moves the vault directory cleanly into
/// `Vaults\_archived\<vault_id>-<timestamp>` so no user data is lost accidentally.
pub fn remove_vault_files(
    vault_id: &str,
    purge_disk_data: bool,
) -> Result<Option<PathBuf>, String> {
    let base = default_vaults_root()?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    remove_vault_files_in(&base, vault_id, purge_disk_data, now_secs)
}

/// Testable variant of [`remove_vault_files`] anchored at an explicit `vaults_root`.
pub fn remove_vault_files_in(
    vaults_root: &Path,
    vault_id: &str,
    purge_disk_data: bool,
    now_secs: u64,
) -> Result<Option<PathBuf>, String> {
    let vault_dir = resolve_vault_root_under(vaults_root, vault_id)?;
    if !vault_dir.exists() {
        return Ok(None);
    }

    if purge_disk_data {
        safe_remove_path_no_reparse(&vault_dir)?;
        return Ok(None);
    }

    let archive_root = vaults_root.join(ARCHIVED_VAULTS_DIR);
    safe_create_dir_all_no_reparse(&archive_root)?;
    let mut dest = archive_root.join(format!("{vault_id}-{now_secs}"));
    if dest.exists() {
        let suffix = crypto_win::random_hex(3).unwrap_or_else(|_| "dup".into());
        dest = archive_root.join(format!("{vault_id}-{now_secs}-{suffix}"));
    }
    ensure_no_reparse_points_chain(&dest)?;
    std::fs::rename(&vault_dir, &dest).map_err(|e| {
        format!(
            "归档账号仓目录失败（{} -> {}）：{e}",
            vault_dir.display(),
            dest.display()
        )
    })?;
    Ok(Some(dest))
}

fn sanitize_filename_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(48));
    for ch in raw.chars() {
        if ch.is_control()
            || matches!(
                ch,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0'
            )
        {
            continue;
        }
        out.push(ch);
        if out.chars().count() >= 48 {
            break;
        }
    }
    out.trim_matches([' ', '.']).to_string()
}

fn escape_ps_single_quoted(raw: &str) -> String {
    raw.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vault(id: &str, name: &str) -> AccountVault {
        AccountVault {
            id: id.into(),
            name: name.into(),
            accent_hex: "#5B69D0".into(),
            enabled: true,
            pinned_regions: vec!["US".into()],
            pinned_ips: vec![],
            pinned_asn: Some(7922),
            dedicated_proxy_port: None,
            preferred_mihomo_group: None,
            preferred_mihomo_node: None,
            auto_align_mihomo_on_vault_launch: false,
            min_safety_score: 80,
            cooldown_after_ip_change_secs: 900,
            share_ide_extensions: true,
            msix_isolation_mode: MsixIsolationMode::AutoVerifyLock,
        }
    }

    fn temp_test_dir(tag: &str) -> PathBuf {
        let nonce = crypto_win::random_hex(6).unwrap_or_else(|_| "001122".into());
        let dir = std::env::temp_dir().join(format!("cg-vault-test-{tag}-{nonce}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn vault_id_and_traversal_validation_rejects_malicious_inputs() {
        let root = temp_test_dir("traversal");
        for bad in [
            "",
            "a",
            "../escape",
            "..\\escape",
            "foo/bar",
            "foo\\bar",
            "WorkUpper",
            "con",
            "nul",
            "com1",
            "lpt9",
            "-leading-dash",
        ] {
            assert!(
                resolve_vault_root_under(&root, bad).is_err(),
                "must reject vault_id `{bad}`"
            );
            let bad_vault = sample_vault(bad, "Bad");
            assert!(ensure_vault_layout_in(&root, &bad_vault).is_err());
            assert!(remove_vault_files_in(&root, bad, false, 1000).is_err());
        }
        assert!(ensure_no_reparse_points_chain(Path::new(r"C:\Temp\..\Windows")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_vault_layout_creates_isolated_dirs_and_unique_machine_ids() {
        let root = temp_test_dir("layout");
        let v1 = sample_vault("work-us", "Work US");
        let v2 = sample_vault("personal-jp", "Personal JP");

        let p1 = ensure_vault_layout_in(&root, &v1).expect("create v1 layout");
        let p2 = ensure_vault_layout_in(&root, &v2).expect("create v2 layout");

        for dir in [
            &p1.claude_desktop,
            &p1.chatgpt_desktop,
            &p1.antigravity_ide,
            &p1.antigravity_extensions,
            &p1.claude_code_home,
            &p1.codex_home,
            &p1.codex_sqlite_home,
        ] {
            assert!(dir.is_dir(), "expected dir {}", dir.display());
        }
        assert!(p1.meta_json.is_file());

        let read_storage = |ide_dir: &Path| -> serde_json::Value {
            let p = ide_dir
                .join("User")
                .join("globalStorage")
                .join("storage.json");
            let raw = std::fs::read_to_string(&p).expect("read storage.json");
            serde_json::from_str(&raw).expect("parse storage.json")
        };

        let s1 = read_storage(&p1.antigravity_ide);
        let s2 = read_storage(&p2.antigravity_ide);
        assert_eq!(
            s1["telemetry.machineId"].as_str().unwrap().len(),
            64,
            "machineId must be 64-char hex"
        );
        assert_eq!(s1["telemetry.macMachineId"].as_str().unwrap().len(), 64);
        assert!(s1["telemetry.sqmId"].as_str().unwrap().starts_with('{'));
        assert_ne!(s1["telemetry.machineId"], s2["telemetry.machineId"]);
        assert_ne!(s1["telemetry.macMachineId"], s2["telemetry.macMachineId"]);
        assert_ne!(s1["telemetry.sqmId"], s2["telemetry.sqmId"]);

        // Re-running ensure_vault_layout_in must be idempotent and keep existing IDs stable.
        ensure_vault_layout_in(&root, &v1).expect("re-run layout");
        let s1_again = read_storage(&p1.antigravity_ide);
        assert_eq!(s1["telemetry.machineId"], s1_again["telemetry.machineId"]);
        assert_eq!(s1["telemetry.sqmId"], s1_again["telemetry.sqmId"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn plan_vault_launch_handles_cli_ide_dedicated_proxy_and_msix_modes() {
        let root = temp_test_dir("plan");
        let fake_home = root.join("home");
        std::fs::create_dir_all(&fake_home).unwrap();

        let mut v = sample_vault("team-us-01", "Team US");
        v.dedicated_proxy_port = Some(7892);
        v.msix_isolation_mode = MsixIsolationMode::ExclusiveSwapLock;

        // Claude Desktop with dedicated port + ExclusiveSwapLock
        let cd = plan_vault_launch_env_and_args_in(
            &root,
            Some(&fake_home),
            &v,
            VaultAppTarget::ClaudeDesktop,
            "127.0.0.1",
            7890,
            &["--disable-quic".into()],
        )
        .expect("plan claude desktop");
        assert_eq!(cd.effective_proxy_port, 7892);
        assert_eq!(
            cd.env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:7892")
        );
        assert!(cd.args.iter().any(|a| a.starts_with("--user-data-dir=")));
        assert!(cd.args.iter().any(|a| a == "--disable-quic"));
        assert!(matches!(
            cd.msix_strategy,
            MsixLaunchStrategy::ExclusiveSwapLock { .. }
        ));

        // Antigravity IDE sharing host extensions dir vs isolated extensions dir
        let ag_shared = plan_vault_launch_env_and_args_in(
            &root,
            Some(&fake_home),
            &v,
            VaultAppTarget::AntigravityIde,
            "127.0.0.1",
            7890,
            &[],
        )
        .expect("plan ag shared");
        assert_eq!(
            ag_shared.extensions_dir,
            Some(fake_home.join(".antigravity").join("extensions"))
        );

        v.share_ide_extensions = false;
        let ag_iso = plan_vault_launch_env_and_args_in(
            &root,
            Some(&fake_home),
            &v,
            VaultAppTarget::AntigravityIde,
            "127.0.0.1",
            7890,
            &[],
        )
        .expect("plan ag iso");
        assert_eq!(
            ag_iso.extensions_dir,
            Some(
                root.join("team-us-01")
                    .join("antigravity_ide")
                    .join("extensions")
            )
        );

        // CLI env isolation matrix
        let cc = plan_vault_launch_env_and_args_in(
            &root,
            Some(&fake_home),
            &v,
            VaultAppTarget::ClaudeCodeCli,
            "127.0.0.1",
            7890,
            &[],
        )
        .expect("plan claude code");
        assert!(cc.env.contains_key("CLAUDE_CONFIG_DIR"));
        assert_eq!(
            cc.env.get("CG_VAULT_ID").map(String::as_str),
            Some("team-us-01")
        );

        let codex = plan_vault_launch_env_and_args_in(
            &root,
            Some(&fake_home),
            &v,
            VaultAppTarget::CodexCli,
            "127.0.0.1",
            7890,
            &[],
        )
        .expect("plan codex");
        assert!(codex.env.contains_key("CODEX_HOME"));
        assert!(codex.env.contains_key("CODEX_SQLITE_HOME"));

        // Reject NUL in extra args
        assert!(plan_vault_launch_env_and_args_in(
            &root,
            Some(&fake_home),
            &v,
            VaultAppTarget::ClaudeCodeCli,
            "127.0.0.1",
            7890,
            &["bad\0arg".into()],
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn msix_exclusive_lock_blocks_second_vault_and_releases_cleanly() {
        let root = temp_test_dir("msix-lock");
        let lock = acquire_msix_exclusive_lock(&root, "claude", "vault-a", 1000)
            .expect("vault-a acquires lock");
        assert!(lock.is_file());

        // Same vault re-acquiring is idempotent.
        acquire_msix_exclusive_lock(&root, "claude", "vault-a", 1005).expect("vault-a re-acquire");

        // Second vault must be hard-blocked.
        assert!(acquire_msix_exclusive_lock(&root, "claude", "vault-b", 1010).is_err());

        // Releasing from wrong vault does not remove vault-a's lock.
        release_msix_exclusive_lock(&root, "claude", "vault-b").expect("ignore wrong owner");
        assert!(lock.is_file());

        // Releasing from vault-a unlocks for vault-b.
        release_msix_exclusive_lock(&root, "claude", "vault-a").expect("release vault-a");
        assert!(!lock.exists());
        acquire_msix_exclusive_lock(&root, "claude", "vault-b", 1020)
            .expect("vault-b now acquires lock");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shortcuts_and_archive_vs_purge_removal_work_safely() {
        let root = temp_test_dir("shortcuts");
        let desktop = root.join("desktop");
        std::fs::create_dir_all(&desktop).unwrap();

        let v = sample_vault("jp-max", "主力 Max (JP)");
        let cli = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("claudeguard-cli.exe"));
        let created =
            generate_vault_shortcuts_in(&root, &v, &cli, &desktop).expect("generate shortcuts");
        assert!(
            created.len() >= 4,
            "expected ps1, cmd, and desktop shortcuts"
        );

        let ps1 = root
            .join("jp-max")
            .join("shortcuts")
            .join("vault-shell-init.ps1");
        let raw_ps1 = std::fs::read(&ps1).expect("read ps1");
        assert!(
            raw_ps1.starts_with(&[0xEF, 0xBB, 0xBF]),
            "ps1 must have UTF-8 BOM"
        );
        let ps1_text = String::from_utf8_lossy(&raw_ps1[3..]);
        assert!(ps1_text.contains("\r\n"), "ps1 must use CRLF");
        assert!(ps1_text.contains("CLAUDE_CONFIG_DIR"));

        // Soft remove moves to _archived/<id>-<ts> preserving all data!
        let archived = remove_vault_files_in(&root, "jp-max", false, 1_700_000_123)
            .expect("archive vault")
            .expect("archived path");
        assert!(archived.is_dir());
        assert!(archived.join("meta.json").is_file());
        assert!(!root.join("jp-max").exists());

        // Create second vault and hard purge.
        let v2 = sample_vault("temp-purge", "Temp Purge");
        ensure_vault_layout_in(&root, &v2).expect("create v2");
        assert!(root.join("temp-purge").is_dir());
        let purged =
            remove_vault_files_in(&root, "temp-purge", true, 1_700_000_200).expect("purge vault");
        assert!(purged.is_none());
        assert!(!root.join("temp-purge").exists());

        let _ = std::fs::remove_dir_all(&root);
    }
}
