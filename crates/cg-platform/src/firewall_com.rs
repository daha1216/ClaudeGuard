//! Native Windows Firewall COM engine (`INetFwPolicy2` / `INetFwRules` / `INetFwRule`).
//!
//! Zero `powershell.exe` / `netsh.exe` / `net.exe` invocations: all profile queries, rule
//! enumeration (`_NewEnum` -> `IEnumVARIANT`), deduplication, per-exe Inbound/Outbound Block
//! creation, global `ClaudeGuard Cut All`, idempotent removal, and post-mutation readback
//! verification go directly over COM.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::traits::{
    Coverage, FirewallEngine, FirewallRuleRecord, FirewallRuleSpec, LockdownStatus, PlatformResult,
    RemoveReport, RuleAction, RuleDirection,
};
#[cfg(any(windows, test))]
use crate::traits::{FirewallProfileStatus, PlatformError};

/// Prefix shared by all firewall rules managed by ClaudeGuard.
pub const CG_RULE_PREFIX: &str = "ClaudeGuard";
/// Outbound isolation rule prefix.
pub const FW_RULE_OUT: &str = "ClaudeGuard Block Out";
/// Inbound isolation rule prefix.
pub const FW_RULE_IN: &str = "ClaudeGuard Block In";
/// Fallback lockdown rule prefix (per-agent outbound block while uncovered).
pub const LOCKDOWN_RULE_PREFIX: &str = "ClaudeGuard Lockdown";
/// Global outbound cut rule name.
pub const CUT_ALL_RULE: &str = "ClaudeGuard Cut All";

/// Canonical per-agent quarantine rule names:
/// `("ClaudeGuard Block Out (<agent>)", "ClaudeGuard Block In (<agent>)")`.
pub fn quarantine_rule_names(agent_id: &str) -> (String, String) {
    (
        format!("{FW_RULE_OUT} ({agent_id})"),
        format!("{FW_RULE_IN} ({agent_id})"),
    )
}

/// Legacy v1/v2/v3 Claude rule names cleaned up alongside `quarantine_rule_names("claude")`.
pub fn quarantine_release_names(agent_id: &str) -> Vec<String> {
    let (out, r#in) = quarantine_rule_names(agent_id);
    let mut names = vec![out, r#in];
    if agent_id.eq_ignore_ascii_case("claude") {
        names.push(FW_RULE_OUT.to_string());
        names.push(FW_RULE_IN.to_string());
    }
    names
}

/// Canonical per-agent lockdown rule name: `"ClaudeGuard Lockdown (<agent>)"`.
pub fn lockdown_rule_name(agent_id: &str) -> String {
    format!("{LOCKDOWN_RULE_PREFIX} ({agent_id})")
}

fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix_ascii: &str) -> Option<&'a str> {
    if !prefix_ascii.is_ascii() {
        return None;
    }
    let head = s.as_bytes().get(..prefix_ascii.len())?;
    head.eq_ignore_ascii_case(prefix_ascii.as_bytes())
        .then(|| s.get(prefix_ascii.len()..))
        .flatten()
}

fn strip_verbatim_win32_prefix(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(unc) = strip_ascii_prefix_ci(trimmed, r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(dos) = trimmed.strip_prefix(r"\\?\") {
        dos.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolve an executable path via `GetFinalPathNameByHandleW(..., VOLUME_NAME_DOS)` on Windows
/// (stripping `\\?\` / `\\?\UNC\` so `INetFwRule::SetApplicationName` never rejects extended-length
/// or junction paths), falling back to prefix-stripped path in mock/offline tests.
pub fn resolve_program_path_for_firewall(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, VOLUME_NAME_DOS,
        };

        struct HandleGuard(HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if let Ok(h) = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        } {
            if h != INVALID_HANDLE_VALUE {
                let _guard = HandleGuard(h);
                let mut buf = vec![0u16; 4096];
                let len =
                    unsafe { GetFinalPathNameByHandleW(h, &mut buf, VOLUME_NAME_DOS) } as usize;
                if len > 0 && len < buf.len() {
                    let resolved = String::from_utf16_lossy(&buf[..len]);
                    let cleaned = strip_verbatim_win32_prefix(&resolved).replace('/', "\\");
                    if !cleaned.is_empty() {
                        return PathBuf::from(cleaned);
                    }
                }
            }
        }
    }

    let fallback = strip_verbatim_win32_prefix(&path.to_string_lossy()).replace('/', "\\");
    PathBuf::from(fallback)
}

/// Build desired Inbound + Outbound block rules for an agent's discovered executables.
pub fn agent_quarantine_specs(agent_id: &str, exes: &[PathBuf]) -> Vec<FirewallRuleSpec> {
    let (name_out, name_in) = quarantine_rule_names(agent_id);
    let mut specs = Vec::with_capacity(exes.len() * 2);
    for exe in exes {
        let resolved = resolve_program_path_for_firewall(exe);
        specs.push(FirewallRuleSpec::block_out(
            name_out.clone(),
            resolved.clone(),
        ));
        specs.push(FirewallRuleSpec::block_in(name_in.clone(), resolved));
    }
    specs
}

/// Build desired Outbound lockdown rules for an agent's discovered executables.
pub fn agent_lockdown_specs(agent_id: &str, exes: &[PathBuf]) -> Vec<FirewallRuleSpec> {
    let name = lockdown_rule_name(agent_id);
    exes.iter()
        .map(|exe| {
            FirewallRuleSpec::block_out(name.clone(), resolve_program_path_for_firewall(exe))
        })
        .collect()
}

/// Build global outbound cut rule specification (`ClaudeGuard Cut All`).
pub fn global_cut_spec() -> FirewallRuleSpec {
    FirewallRuleSpec::global_block_out(CUT_ALL_RULE)
}

/// Normalize executable paths for case-insensitive, separator-consistent rule comparison.
pub fn normalize_program_path(raw: &str) -> String {
    strip_verbatim_win32_prefix(raw)
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// Pure predicate: does an observed OS rule satisfy a desired `FirewallRuleSpec`?
pub fn rule_matches_spec(record: &FirewallRuleRecord, spec: &FirewallRuleSpec) -> bool {
    if !record.name.trim().eq_ignore_ascii_case(spec.name.trim()) {
        return false;
    }
    if record.direction != spec.direction
        || record.action != spec.action
        || record.enabled != spec.enabled
    {
        return false;
    }
    match &spec.program {
        Some(path) => {
            let resolved = resolve_program_path_for_firewall(path);
            normalize_program_path(&record.program)
                == normalize_program_path(&resolved.to_string_lossy())
        }
        None => record.program.trim().is_empty(),
    }
}

/// Pure verification counter: how many desired rules have a matching active rule in `observed`.
pub fn count_verified(observed: &[FirewallRuleRecord], desired: &[FirewallRuleSpec]) -> usize {
    desired
        .iter()
        .filter(|spec| observed.iter().any(|rec| rule_matches_spec(rec, spec)))
        .count()
}

/// Pure builder for post-mutation `Coverage`.
/// When `query_ok` is `false`, `verified` is never elevated to claim completion.
pub fn build_coverage(
    observed: Option<&[FirewallRuleRecord]>,
    desired: &[FirewallRuleSpec],
    added: usize,
) -> Coverage {
    match observed {
        Some(rules) => Coverage {
            desired: desired.len(),
            verified: count_verified(rules, desired),
            added,
            query_ok: true,
        },
        None => Coverage {
            desired: desired.len(),
            verified: 0,
            added,
            query_ok: false,
        },
    }
}

/// Pure duplicate detector: returns indices of duplicate rules in `rules`
/// (preserving the first instance per `(lowercase_name, lowercase_program, direction, action)`).
pub fn duplicate_rule_indices(rules: &[FirewallRuleRecord]) -> Vec<usize> {
    let mut seen: HashSet<(String, String, RuleDirection, RuleAction)> = HashSet::new();
    let mut dups = Vec::new();
    for (idx, r) in rules.iter().enumerate() {
        let key = (
            r.name.trim().to_ascii_lowercase(),
            normalize_program_path(&r.program),
            r.direction,
            r.action,
        );
        if !seen.insert(key) {
            dups.push(idx);
        }
    }
    dups
}

/// Quarantine all discovered executables of `agent_id` (Inbound + Outbound Block) and verify.
pub fn quarantine_agent(
    engine: &dyn FirewallEngine,
    agent_id: &str,
    exes: &[PathBuf],
) -> PlatformResult<Coverage> {
    if exes.is_empty() {
        return Ok(Coverage::default());
    }
    let _ = engine.ensure_profiles_enabled()?;
    let specs = agent_quarantine_specs(agent_id, exes);
    engine.ensure_rules(&specs)
}

/// Idempotently release quarantine rules for `agent_id` (both v4 scoped and legacy Claude rules).
pub fn release_agent(engine: &dyn FirewallEngine, agent_id: &str) -> PlatformResult<RemoveReport> {
    let names = quarantine_release_names(agent_id);
    engine.remove_rules_by_name(&names)
}

pub(crate) fn is_prunable_managed_rule_name(name_lower: &str) -> bool {
    let n = name_lower.trim();
    n.starts_with(&LOCKDOWN_RULE_PREFIX.to_ascii_lowercase())
        || n.starts_with(&FW_RULE_OUT.to_ascii_lowercase())
        || n.starts_with(&FW_RULE_IN.to_ascii_lowercase())
}

/// Apply per-agent outbound lockdown rules (`ClaudeGuard Lockdown (<agent>)`), prune stale
/// `KNOWN_GUI_AGENT_IDS` lockdown rules not in `agent_exes`, and verify.
pub fn apply_lockdown(
    engine: &dyn FirewallEngine,
    agent_exes: &[(String, Vec<PathBuf>)],
) -> PlatformResult<Coverage> {
    let mut specs = Vec::new();
    let mut active_ids: HashSet<String> = HashSet::new();
    for (agent_id, exes) in agent_exes {
        if !exes.is_empty() {
            active_ids.insert(agent_id.trim().to_ascii_lowercase());
            specs.extend(agent_lockdown_specs(agent_id, exes));
        }
    }

    let stale_names: Vec<String> = cg_protocol::KNOWN_GUI_AGENT_IDS
        .iter()
        .filter(|id| !active_ids.contains(&id.to_ascii_lowercase()))
        .map(|id| lockdown_rule_name(id))
        .collect();

    if specs.is_empty() {
        if !stale_names.is_empty() {
            let _ = engine.remove_rules_by_name(&stale_names);
        }
        return Ok(Coverage::default());
    }
    let _ = engine.ensure_profiles_enabled()?;
    let cov = engine.ensure_rules(&specs)?;
    if !stale_names.is_empty() {
        let _ = engine.remove_rules_by_name(&stale_names);
    }
    Ok(cov)
}

/// Clear all `ClaudeGuard Lockdown*` rules idempotently and verify.
pub fn clear_lockdown(engine: &dyn FirewallEngine) -> PlatformResult<RemoveReport> {
    engine.remove_rules_with_prefix(LOCKDOWN_RULE_PREFIX)
}

/// Query active `ClaudeGuard Lockdown*` rules for CONTRACT §8.8 `LockdownStatus`.
pub fn lockdown_status(engine: &dyn FirewallEngine) -> LockdownStatus {
    match engine.enumerate_rules(LOCKDOWN_RULE_PREFIX) {
        Ok(rules) => {
            let active = rules.iter().filter(|r| r.enabled).count();
            LockdownStatus {
                on: active > 0,
                query_ok: true,
                rules: active,
            }
        }
        Err(_) => LockdownStatus {
            on: false,
            query_ok: false,
            rules: 0,
        },
    }
}

/// Apply global outbound cut rule (`ClaudeGuard Cut All`) and verify.
pub fn apply_global_cut(engine: &dyn FirewallEngine) -> PlatformResult<Coverage> {
    let _ = engine.ensure_profiles_enabled()?;
    engine.ensure_rules(&[global_cut_spec()])
}

/// Clear global outbound cut rule (`ClaudeGuard Cut All`) idempotently and verify.
pub fn clear_global_cut(engine: &dyn FirewallEngine) -> PlatformResult<RemoveReport> {
    engine.remove_rules_by_name(&[CUT_ALL_RULE.to_string()])
}

/// Remove all `ClaudeGuard*` firewall rules idempotently and verify cleanup via readback.
pub fn remove_all_cg_rules(engine: &dyn FirewallEngine) -> PlatformResult<RemoveReport> {
    engine.remove_rules_with_prefix(CG_RULE_PREFIX)
}

/// Deduplicate all `ClaudeGuard*` firewall rules and return the removed duplicate count.
pub fn dedupe_all_cg_rules(engine: &dyn FirewallEngine) -> PlatformResult<usize> {
    engine.dedupe_rules(CG_RULE_PREFIX)
}

/// Check if a path looks like an existing file (used by callers before adding rules).
pub fn filter_existing_exes(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if Path::new(&p).is_file() && !out.iter().any(|x: &PathBuf| x == &p) {
            out.push(p);
        }
    }
    out
}

// ---------- Windows COM Implementation ----------

#[cfg(windows)]
mod win_impl {
    use super::*;
    use crate::com::{map_win_err, ComGuard};
    use windows::core::{IUnknown, Interface, BSTR, GUID, HRESULT, VARIANT};
    use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW,
        NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE_TYPE2, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
    };
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};

    const S_FALSE: i32 = 1;
    const VT_DISPATCH: u16 = 9;
    const VT_UNKNOWN: u16 = 13;

    #[repr(transparent)]
    #[derive(Clone, PartialEq, Eq)]
    struct IEnumVariant(IUnknown);

    #[repr(C)]
    struct IEnumVariantVtbl {
        base: windows::core::IUnknown_Vtbl,
        next: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            u32,
            *mut core::mem::MaybeUninit<VARIANT>,
            *mut u32,
        ) -> HRESULT,
        skip: unsafe extern "system" fn(*mut core::ffi::c_void, u32) -> HRESULT,
        reset: unsafe extern "system" fn(*mut core::ffi::c_void) -> HRESULT,
        clone: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *mut *mut core::ffi::c_void,
        ) -> HRESULT,
    }

    unsafe impl Interface for IEnumVariant {
        type Vtable = IEnumVariantVtbl;
        const IID: GUID = GUID::from_u128(0x00020404_0000_0000_c000_000000000046);
    }

    impl IEnumVariant {
        unsafe fn next(&self, batch: &mut [VARIANT]) -> (HRESULT, usize) {
            let mut fetched: u32 = 0;
            let hr = (Interface::vtable(self).next)(
                Interface::as_raw(self),
                batch.len() as u32,
                batch.as_mut_ptr().cast(),
                &mut fetched,
            );
            (hr, fetched as usize)
        }
    }

    /// Native Windows Defender Firewall backend powered by `INetFwPolicy2` COM.
    ///
    /// Thread-safe (`Send + Sync`): initializes COM MTA on the calling thread per operation
    /// rather than storing apartment-bound COM pointers across threads.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct ComFirewallEngine;

    impl ComFirewallEngine {
        pub fn new() -> Self {
            Self
        }

        fn open_policy() -> PlatformResult<(ComGuard, INetFwPolicy2)> {
            let guard = ComGuard::init_mta()?;
            let policy: INetFwPolicy2 =
                unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL) }
                    .map_err(|e| map_win_err(e, "CoCreateInstance(NetFwPolicy2)"))?;
            Ok((guard, policy))
        }

        fn open_rules() -> PlatformResult<(ComGuard, INetFwPolicy2, INetFwRules)> {
            let (guard, policy) = Self::open_policy()?;
            let rules =
                unsafe { policy.Rules() }.map_err(|e| map_win_err(e, "INetFwPolicy2::Rules"))?;
            Ok((guard, policy, rules))
        }

        fn extract_rule_from_variant(var: &VARIANT) -> Option<INetFwRule> {
            let raw = var.as_raw();
            let vt = unsafe { raw.Anonymous.Anonymous.vt };
            let ptr = unsafe {
                if vt == VT_DISPATCH {
                    raw.Anonymous.Anonymous.Anonymous.pdispVal
                } else if vt == VT_UNKNOWN {
                    raw.Anonymous.Anonymous.Anonymous.punkVal
                } else {
                    core::ptr::null_mut()
                }
            };
            if ptr.is_null() {
                return None;
            }
            let unk = unsafe { IUnknown::from_raw_borrowed(&ptr) }?;
            unk.cast::<INetFwRule>().ok()
        }

        fn read_rule_record(rule: &INetFwRule) -> Option<FirewallRuleRecord> {
            let name = unsafe { rule.Name() }.ok()?.to_string();
            let program = unsafe { rule.ApplicationName() }
                .map(|b| b.to_string())
                .unwrap_or_default();
            let dir_raw = unsafe { rule.Direction() }.ok()?;
            let direction = if dir_raw == NET_FW_RULE_DIR_IN {
                RuleDirection::Inbound
            } else if dir_raw == NET_FW_RULE_DIR_OUT {
                RuleDirection::Outbound
            } else {
                return None;
            };
            let act_raw = unsafe { rule.Action() }.ok()?;
            let action = if act_raw == NET_FW_ACTION_BLOCK {
                RuleAction::Block
            } else if act_raw == NET_FW_ACTION_ALLOW {
                RuleAction::Allow
            } else {
                return None;
            };
            let enabled_raw = unsafe { rule.Enabled() }.ok()?;
            let enabled = enabled_raw != VARIANT_FALSE;
            let profiles = unsafe { rule.Profiles() }.unwrap_or(0);
            Some(FirewallRuleRecord {
                name,
                program,
                direction,
                action,
                enabled,
                profiles,
            })
        }

        fn enumerate_matching(
            rules: &INetFwRules,
            predicate: impl Fn(&str) -> bool,
        ) -> PlatformResult<Vec<(INetFwRule, FirewallRuleRecord)>> {
            let unk =
                unsafe { rules._NewEnum() }.map_err(|e| map_win_err(e, "INetFwRules::_NewEnum"))?;
            let enum_var: IEnumVariant = unk
                .cast()
                .map_err(|e| map_win_err(e, "IUnknown::cast::<IEnumVariant>"))?;

            let mut out = Vec::new();
            let mut batch: Vec<VARIANT> = (0..32).map(|_| VARIANT::new()).collect();
            loop {
                let (hr, fetched) = unsafe { enum_var.next(&mut batch) };
                if hr.is_err() {
                    return Err(PlatformError::Com {
                        code: hr.0,
                        context: "IEnumVARIANT::Next".to_string(),
                    });
                }
                if fetched == 0 {
                    break;
                }
                for slot in &mut batch[..fetched] {
                    if let Some(rule) = Self::extract_rule_from_variant(slot) {
                        if let Some(rec) = Self::read_rule_record(&rule) {
                            if predicate(&rec.name) {
                                out.push((rule, rec));
                            }
                        }
                    }
                    *slot = VARIANT::new();
                }
                if hr.0 == S_FALSE || fetched < batch.len() {
                    break;
                }
            }
            Ok(out)
        }

        pub(crate) fn enumerate_com_rules_with_prefix(
            rules: &INetFwRules,
            prefix: &str,
        ) -> PlatformResult<Vec<(INetFwRule, FirewallRuleRecord)>> {
            let prefix_l = prefix.trim().to_ascii_lowercase();
            Self::enumerate_matching(rules, |name| {
                prefix_l.is_empty() || name.trim().to_ascii_lowercase().starts_with(&prefix_l)
            })
        }

        fn add_single_rule(rules: &INetFwRules, spec: &FirewallRuleSpec) -> PlatformResult<()> {
            let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_ALL) }
                .map_err(|e| map_win_err(e, "CoCreateInstance(NetFwRule)"))?;
            unsafe {
                rule.SetName(&BSTR::from(&spec.name))
                    .map_err(|e| map_win_err(e, "INetFwRule::SetName"))?;
                if let Some(prog) = &spec.program {
                    let resolved = resolve_program_path_for_firewall(prog);
                    let prog_str = resolved.to_string_lossy();
                    if prog_str.trim().is_empty() {
                        return Err(PlatformError::InvalidInput(
                            "refusing to add per-app firewall rule with empty ApplicationName"
                                .to_string(),
                        ));
                    }
                    rule.SetApplicationName(&BSTR::from(prog_str.as_ref()))
                        .map_err(|e| map_win_err(e, "INetFwRule::SetApplicationName"))?;
                }
                let dir = match spec.direction {
                    RuleDirection::Inbound => NET_FW_RULE_DIR_IN,
                    RuleDirection::Outbound => NET_FW_RULE_DIR_OUT,
                };
                rule.SetDirection(dir)
                    .map_err(|e| map_win_err(e, "INetFwRule::SetDirection"))?;
                let act = match spec.action {
                    RuleAction::Block => NET_FW_ACTION_BLOCK,
                    RuleAction::Allow => NET_FW_ACTION_ALLOW,
                };
                rule.SetAction(act)
                    .map_err(|e| map_win_err(e, "INetFwRule::SetAction"))?;
                rule.SetProfiles(spec.profiles)
                    .map_err(|e| map_win_err(e, "INetFwRule::SetProfiles"))?;
                let _ = rule.SetGrouping(&BSTR::from(CG_RULE_PREFIX));
                if let Some(desc) = &spec.description {
                    let _ = rule.SetDescription(&BSTR::from(desc));
                }
                rule.SetEnabled(if spec.enabled {
                    VARIANT_TRUE
                } else {
                    VARIANT_FALSE
                })
                .map_err(|e| map_win_err(e, "INetFwRule::SetEnabled"))?;
                rules
                    .Add(&rule)
                    .map_err(|e| map_win_err(e, "INetFwRules::Add"))?;
            }
            Ok(())
        }

        fn query_profile(
            policy: &INetFwPolicy2,
            profile: NET_FW_PROFILE_TYPE2,
        ) -> PlatformResult<bool> {
            let v = unsafe { policy.get_FirewallEnabled(profile) }
                .map_err(|e| map_win_err(e, "INetFwPolicy2::get_FirewallEnabled"))?;
            Ok(v != VARIANT_FALSE)
        }
    }

    impl FirewallEngine for ComFirewallEngine {
        fn engine_name(&self) -> &'static str {
            "windows-com-netfwpolicy2"
        }

        fn profile_status(&self) -> PlatformResult<FirewallProfileStatus> {
            let (_guard, policy) = Self::open_policy()?;
            Ok(FirewallProfileStatus {
                domain_enabled: Self::query_profile(&policy, NET_FW_PROFILE2_DOMAIN)?,
                private_enabled: Self::query_profile(&policy, NET_FW_PROFILE2_PRIVATE)?,
                public_enabled: Self::query_profile(&policy, NET_FW_PROFILE2_PUBLIC)?,
            })
        }

        fn ensure_profiles_enabled(&self) -> PlatformResult<bool> {
            let (_guard, policy) = Self::open_policy()?;
            for profile in [
                NET_FW_PROFILE2_DOMAIN,
                NET_FW_PROFILE2_PRIVATE,
                NET_FW_PROFILE2_PUBLIC,
            ] {
                let enabled = Self::query_profile(&policy, profile)?;
                if !enabled {
                    // Safety rule: ONLY ever enable disabled profiles; never disable user firewall.
                    unsafe { policy.put_FirewallEnabled(profile, VARIANT_TRUE) }
                        .map_err(|e| map_win_err(e, "INetFwPolicy2::put_FirewallEnabled"))?;
                }
            }
            let after_domain = Self::query_profile(&policy, NET_FW_PROFILE2_DOMAIN)?;
            let after_private = Self::query_profile(&policy, NET_FW_PROFILE2_PRIVATE)?;
            let after_public = Self::query_profile(&policy, NET_FW_PROFILE2_PUBLIC)?;
            Ok(after_domain && after_private && after_public)
        }

        fn enumerate_rules(&self, prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>> {
            let (_guard, _policy, rules) = Self::open_rules()?;
            let prefix_l = prefix.trim().to_ascii_lowercase();
            let items = Self::enumerate_matching(&rules, |name| {
                prefix_l.is_empty() || name.trim().to_ascii_lowercase().starts_with(&prefix_l)
            })?;
            Ok(items.into_iter().map(|(_, rec)| rec).collect())
        }

        fn dedupe_rules(&self, prefix: &str) -> PlatformResult<usize> {
            let (_guard, _policy, rules) = Self::open_rules()?;
            let prefix_l = prefix.trim().to_ascii_lowercase();
            let items = Self::enumerate_matching(&rules, |name| {
                prefix_l.is_empty() || name.trim().to_ascii_lowercase().starts_with(&prefix_l)
            })?;
            let records: Vec<FirewallRuleRecord> =
                items.iter().map(|(_, rec)| rec.clone()).collect();
            let dup_indices = duplicate_rule_indices(&records);
            if dup_indices.is_empty() {
                return Ok(0);
            }

            let mut removed = 0usize;
            let pid = std::process::id();
            for (seq, idx) in dup_indices.iter().enumerate() {
                let (rule, rec) = &items[*idx];
                let sentinel = format!("__CG_DEDUPE_{pid}_{seq}");
                // Rename this exact COM rule instance so Remove() deletes only the duplicate
                // without leaving a gap on any distinct executable sharing the same rule name.
                let rename_ok = unsafe { rule.SetName(&BSTR::from(&sentinel)) }.is_ok();
                if rename_ok {
                    if unsafe { rules.Remove(&BSTR::from(&sentinel)) }.is_ok() {
                        removed += 1;
                    }
                } else if unsafe { rules.Remove(&BSTR::from(&rec.name)) }.is_ok() {
                    removed += 1;
                }
            }
            Ok(removed)
        }

        fn ensure_rules(&self, desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage> {
            if desired.is_empty() {
                return Ok(Coverage::default());
            }
            let (_guard, _policy, rules) = Self::open_rules()?;
            let Ok(before_pairs) = Self::enumerate_matching(&rules, |name| {
                name.trim()
                    .to_ascii_lowercase()
                    .starts_with(&CG_RULE_PREFIX.to_ascii_lowercase())
            }) else {
                return Ok(build_coverage(None, desired, 0));
            };
            let before: Vec<FirewallRuleRecord> =
                before_pairs.iter().map(|(_, rec)| rec.clone()).collect();

            let mut added = 0usize;
            let mut last_err: Option<PlatformError> = None;
            for spec in desired {
                if before.iter().any(|r| rule_matches_spec(r, spec)) {
                    continue;
                }
                match Self::add_single_rule(&rules, spec) {
                    Ok(()) => added += 1,
                    Err(e) => last_err = Some(e),
                }
            }

            // Prune pre-existing rules sharing any managed Lockdown/Quarantine rule name in `desired`
            // whose `program` / direction / action no longer matches `desired` (add-first, zero gap).
            if last_err.is_none() {
                let managed_names: HashSet<String> = desired
                    .iter()
                    .map(|s| s.name.trim().to_ascii_lowercase())
                    .filter(|n| is_prunable_managed_rule_name(n))
                    .collect();
                if !managed_names.is_empty() {
                    let pid = std::process::id();
                    for (seq, (rule, rec)) in before_pairs.iter().enumerate() {
                        let rec_name_l = rec.name.trim().to_ascii_lowercase();
                        if managed_names.contains(&rec_name_l)
                            && !desired.iter().any(|s| rule_matches_spec(rec, s))
                        {
                            let sentinel = format!("__CG_PRUNE_{pid}_{seq}");
                            if unsafe { rule.SetName(&BSTR::from(&sentinel)) }.is_ok() {
                                let _ = unsafe { rules.Remove(&BSTR::from(&sentinel)) };
                            }
                        }
                    }
                }
            }

            let after = Self::enumerate_matching(&rules, |name| {
                name.trim()
                    .to_ascii_lowercase()
                    .starts_with(&CG_RULE_PREFIX.to_ascii_lowercase())
            })
            .ok()
            .map(|pairs| pairs.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>());

            let cov = build_coverage(after.as_deref(), desired, added);
            if !cov.complete() {
                if let Some(err) = last_err {
                    return Err(err);
                }
            }
            Ok(cov)
        }

        fn remove_rules_by_name(&self, names: &[String]) -> PlatformResult<RemoveReport> {
            let (_guard, _policy, rules) = Self::open_rules()?;
            let wants: Vec<String> = names
                .iter()
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect();
            if wants.is_empty() {
                return Ok(RemoveReport {
                    removed: 0,
                    remaining: 0,
                    query_ok: true,
                });
            }
            let matches = Self::enumerate_matching(&rules, |name| {
                let n = name.trim().to_ascii_lowercase();
                wants.iter().any(|w| w == &n)
            })?;
            if matches.is_empty() {
                return Ok(RemoveReport {
                    removed: 0,
                    remaining: 0,
                    query_ok: true,
                });
            }

            for (_, rec) in &matches {
                let _ = unsafe { rules.Remove(&BSTR::from(&rec.name)) };
            }

            let after = Self::enumerate_matching(&rules, |name| {
                let n = name.trim().to_ascii_lowercase();
                wants.iter().any(|w| w == &n)
            });
            match after {
                Ok(left) => Ok(RemoveReport {
                    removed: matches.len().saturating_sub(left.len()),
                    remaining: left.len(),
                    query_ok: true,
                }),
                Err(_) => Ok(RemoveReport {
                    removed: 0,
                    remaining: matches.len(),
                    query_ok: false,
                }),
            }
        }

        fn remove_rules_with_prefix(&self, prefix: &str) -> PlatformResult<RemoveReport> {
            let (_guard, _policy, rules) = Self::open_rules()?;
            let prefix_l = prefix.trim().to_ascii_lowercase();
            if prefix_l.is_empty() {
                return Err(PlatformError::InvalidInput(
                    "refusing to remove firewall rules with an empty prefix".to_string(),
                ));
            }
            let matches = Self::enumerate_matching(&rules, |name| {
                name.trim().to_ascii_lowercase().starts_with(&prefix_l)
            })?;
            if matches.is_empty() {
                return Ok(RemoveReport {
                    removed: 0,
                    remaining: 0,
                    query_ok: true,
                });
            }
            for (_, rec) in &matches {
                let _ = unsafe { rules.Remove(&BSTR::from(&rec.name)) };
            }
            match Self::enumerate_matching(&rules, |name| {
                name.trim().to_ascii_lowercase().starts_with(&prefix_l)
            }) {
                Ok(left) => Ok(RemoveReport {
                    removed: matches.len().saturating_sub(left.len()),
                    remaining: left.len(),
                    query_ok: true,
                }),
                Err(_) => Ok(RemoveReport {
                    removed: 0,
                    remaining: matches.len(),
                    query_ok: false,
                }),
            }
        }
    }
}

#[cfg(windows)]
pub use win_impl::ComFirewallEngine;

#[cfg(not(windows))]
pub type ComFirewallEngine = crate::traits::UnsupportedFirewallEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn rec(
        name: &str,
        program: &str,
        direction: RuleDirection,
        action: RuleAction,
        enabled: bool,
    ) -> FirewallRuleRecord {
        FirewallRuleRecord {
            name: name.to_string(),
            program: program.to_string(),
            direction,
            action,
            enabled,
            profiles: crate::traits::FW_PROFILE_ALL,
        }
    }

    #[derive(Default)]
    struct MockFirewall {
        profiles: Mutex<FirewallProfileStatus>,
        rules: Mutex<Vec<FirewallRuleRecord>>,
        fail_read: Mutex<bool>,
    }

    impl MockFirewall {
        fn with_profiles(domain: bool, private: bool, public: bool) -> Self {
            Self {
                profiles: Mutex::new(FirewallProfileStatus {
                    domain_enabled: domain,
                    private_enabled: private,
                    public_enabled: public,
                }),
                rules: Mutex::new(Vec::new()),
                fail_read: Mutex::new(false),
            }
        }
    }

    impl FirewallEngine for MockFirewall {
        fn engine_name(&self) -> &'static str {
            "mock"
        }

        fn profile_status(&self) -> PlatformResult<FirewallProfileStatus> {
            Ok(*self.profiles.lock().unwrap())
        }

        fn ensure_profiles_enabled(&self) -> PlatformResult<bool> {
            let mut p = self.profiles.lock().unwrap();
            p.domain_enabled = true;
            p.private_enabled = true;
            p.public_enabled = true;
            Ok(p.all_enabled())
        }

        fn enumerate_rules(&self, prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>> {
            if *self.fail_read.lock().unwrap() {
                return Err(PlatformError::Com {
                    code: -1,
                    context: "mock readback failure".into(),
                });
            }
            let prefix_l = prefix.trim().to_ascii_lowercase();
            Ok(self
                .rules
                .lock()
                .unwrap()
                .iter()
                .filter(|r| {
                    prefix_l.is_empty() || r.name.to_ascii_lowercase().starts_with(&prefix_l)
                })
                .cloned()
                .collect())
        }

        fn dedupe_rules(&self, prefix: &str) -> PlatformResult<usize> {
            let mut rules = self.rules.lock().unwrap();
            let prefix_l = prefix.trim().to_ascii_lowercase();
            let matching: Vec<_> = rules
                .iter()
                .filter(|r| r.name.to_ascii_lowercase().starts_with(&prefix_l))
                .cloned()
                .collect();
            let dups = duplicate_rule_indices(&matching);
            let mut removed = 0usize;
            let mut seen = HashSet::new();
            rules.retain(|r| {
                if !r.name.to_ascii_lowercase().starts_with(&prefix_l) {
                    return true;
                }
                let k = (
                    r.name.to_ascii_lowercase(),
                    normalize_program_path(&r.program),
                    r.direction,
                    r.action,
                );
                if seen.insert(k) {
                    true
                } else {
                    removed += 1;
                    false
                }
            });
            assert_eq!(removed, dups.len());
            Ok(removed)
        }

        fn ensure_rules(&self, desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage> {
            let mut added = 0usize;
            {
                let mut rules = self.rules.lock().unwrap();
                let managed_names: HashSet<String> = desired
                    .iter()
                    .map(|s| s.name.trim().to_ascii_lowercase())
                    .filter(|n| is_prunable_managed_rule_name(n))
                    .collect();
                for spec in desired {
                    if !rules.iter().any(|r| rule_matches_spec(r, spec)) {
                        rules.push(FirewallRuleRecord {
                            name: spec.name.clone(),
                            program: spec
                                .program
                                .as_ref()
                                .map(|p| {
                                    resolve_program_path_for_firewall(p)
                                        .to_string_lossy()
                                        .to_string()
                                })
                                .unwrap_or_default(),
                            direction: spec.direction,
                            action: spec.action,
                            enabled: spec.enabled,
                            profiles: spec.profiles,
                        });
                        added += 1;
                    }
                }
                if !managed_names.is_empty() {
                    rules.retain(|r| {
                        let name_l = r.name.trim().to_ascii_lowercase();
                        !managed_names.contains(&name_l)
                            || desired.iter().any(|s| rule_matches_spec(r, s))
                    });
                }
            }
            let after = self.enumerate_rules(CG_RULE_PREFIX).ok();
            Ok(build_coverage(after.as_deref(), desired, added))
        }

        fn remove_rules_by_name(&self, names: &[String]) -> PlatformResult<RemoveReport> {
            let wants: Vec<_> = names
                .iter()
                .map(|n| n.trim().to_ascii_lowercase())
                .collect();
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|r| !wants.contains(&r.name.trim().to_ascii_lowercase()));
            let removed = before - rules.len();
            Ok(RemoveReport {
                removed,
                remaining: 0,
                query_ok: true,
            })
        }

        fn remove_rules_with_prefix(&self, prefix: &str) -> PlatformResult<RemoveReport> {
            let prefix_l = prefix.trim().to_ascii_lowercase();
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|r| !r.name.trim().to_ascii_lowercase().starts_with(&prefix_l));
            let removed = before - rules.len();
            Ok(RemoveReport {
                removed,
                remaining: 0,
                query_ok: true,
            })
        }
    }

    #[test]
    fn quarantine_and_lockdown_rule_naming() {
        assert_eq!(
            quarantine_rule_names("claude"),
            (
                "ClaudeGuard Block Out (claude)".to_string(),
                "ClaudeGuard Block In (claude)".to_string()
            )
        );
        assert_eq!(
            quarantine_rule_names("chatgpt"),
            (
                "ClaudeGuard Block Out (chatgpt)".to_string(),
                "ClaudeGuard Block In (chatgpt)".to_string()
            )
        );
        let rel = quarantine_release_names("claude");
        assert!(rel.contains(&"ClaudeGuard Block Out (claude)".to_string()));
        assert!(rel.contains(&"ClaudeGuard Block Out".to_string()));
        assert_eq!(
            lockdown_rule_name("antigravity"),
            "ClaudeGuard Lockdown (antigravity)"
        );
        assert_eq!(global_cut_spec().name, "ClaudeGuard Cut All");
        assert!(global_cut_spec().program.is_none());
    }

    #[test]
    fn rule_matching_checks_program_direction_action_and_enabled() {
        let exe = PathBuf::from(r"C:\Apps\Claude\claude.exe");
        let spec = FirewallRuleSpec::block_out("ClaudeGuard Block Out (claude)", exe.clone());

        assert!(rule_matches_spec(
            &rec(
                "ClaudeGuard Block Out (claude)",
                r"c:\apps\claude\claude.exe",
                RuleDirection::Outbound,
                RuleAction::Block,
                true,
            ),
            &spec
        ));
        // Disabled rule does not pass verification.
        assert!(!rule_matches_spec(
            &rec(
                "ClaudeGuard Block Out (claude)",
                r"C:\Apps\Claude\claude.exe",
                RuleDirection::Outbound,
                RuleAction::Block,
                false,
            ),
            &spec
        ));
        // Wrong direction does not pass.
        assert!(!rule_matches_spec(
            &rec(
                "ClaudeGuard Block Out (claude)",
                r"C:\Apps\Claude\claude.exe",
                RuleDirection::Inbound,
                RuleAction::Block,
                true,
            ),
            &spec
        ));
        // Allow rule does not pass Block check.
        assert!(!rule_matches_spec(
            &rec(
                "ClaudeGuard Block Out (claude)",
                r"C:\Apps\Claude\claude.exe",
                RuleDirection::Outbound,
                RuleAction::Allow,
                true,
            ),
            &spec
        ));
        // Different exe path (version upgrade) does not pass.
        assert!(!rule_matches_spec(
            &rec(
                "ClaudeGuard Block Out (claude)",
                r"C:\Apps\Claude2\claude.exe",
                RuleDirection::Outbound,
                RuleAction::Block,
                true,
            ),
            &spec
        ));
    }

    #[test]
    fn coverage_never_claims_success_when_query_fails_or_partial() {
        let specs =
            agent_quarantine_specs("claude", &[PathBuf::from(r"C:\Apps\Claude\claude.exe")]);
        let failed_read = build_coverage(None, &specs, 2);
        assert!(!failed_read.query_ok);
        assert!(!failed_read.complete());
        assert!(failed_read.summary().contains("无法核验"));

        let partial = build_coverage(
            Some(&[rec(
                "ClaudeGuard Block Out (claude)",
                r"C:\Apps\Claude\claude.exe",
                RuleDirection::Outbound,
                RuleAction::Block,
                true,
            )]),
            &specs,
            1,
        );
        assert!(partial.query_ok);
        assert_eq!(partial.desired, 2);
        assert_eq!(partial.verified, 1);
        assert!(!partial.complete());
        assert!(partial.summary().contains("1/2"));

        let zero = build_coverage(Some(&[]), &[], 0);
        assert!(!zero.complete());
    }

    #[test]
    fn dedupe_detects_only_identical_rule_instances() {
        let rules = vec![
            rec(
                "ClaudeGuard Block Out (claude)",
                r"C:\Apps\A.exe",
                RuleDirection::Outbound,
                RuleAction::Block,
                true,
            ),
            rec(
                "ClaudeGuard Block Out (claude)",
                r"c:\apps\a.EXE",
                RuleDirection::Outbound,
                RuleAction::Block,
                true,
            ),
            // Different exe sharing the same rule name must NOT be flagged as duplicate.
            rec(
                "ClaudeGuard Block Out (claude)",
                r"C:\Apps\B.exe",
                RuleDirection::Outbound,
                RuleAction::Block,
                true,
            ),
            // Same exe, opposite direction must NOT be flagged as duplicate.
            rec(
                "ClaudeGuard Block In (claude)",
                r"C:\Apps\A.exe",
                RuleDirection::Inbound,
                RuleAction::Block,
                true,
            ),
        ];
        assert_eq!(duplicate_rule_indices(&rules), vec![1]);
    }

    #[test]
    fn mock_engine_quarantine_dedupe_lockdown_cut_and_idempotent_release() {
        let engine = Arc::new(MockFirewall::with_profiles(true, false, true));
        assert!(!engine.profile_status().unwrap().all_enabled());

        let exes = vec![
            PathBuf::from(r"C:\Apps\Claude\claude.exe"),
            PathBuf::from(r"C:\Apps\Claude\helper.exe"),
        ];
        let cov = quarantine_agent(engine.as_ref(), "claude", &exes).unwrap();
        assert!(cov.complete());
        assert_eq!(cov.desired, 4);
        assert_eq!(cov.verified, 4);
        assert_eq!(cov.added, 4);
        assert!(engine.profile_status().unwrap().all_enabled());

        // Inject a duplicate and dedupe.
        engine.rules.lock().unwrap().push(rec(
            "ClaudeGuard Block Out (claude)",
            r"C:\Apps\Claude\claude.exe",
            RuleDirection::Outbound,
            RuleAction::Block,
            true,
        ));
        assert_eq!(engine.dedupe_rules(CG_RULE_PREFIX).unwrap(), 1);
        assert_eq!(engine.enumerate_rules(CG_RULE_PREFIX).unwrap().len(), 4);

        // Lockdown & global cut.
        let lock_cov =
            apply_lockdown(engine.as_ref(), &[("claude".to_string(), exes.clone())]).unwrap();
        assert!(lock_cov.complete());
        assert!(lockdown_status(engine.as_ref()).on);
        assert_eq!(lockdown_status(engine.as_ref()).rules, 2);

        let cut_cov = apply_global_cut(engine.as_ref()).unwrap();
        assert!(cut_cov.complete());

        // Readback failure must return query_ok == false.
        *engine.fail_read.lock().unwrap() = true;
        assert!(!lockdown_status(engine.as_ref()).query_ok);
        let unverified = apply_global_cut(engine.as_ref()).unwrap();
        assert!(!unverified.query_ok);
        assert!(!unverified.complete());
        *engine.fail_read.lock().unwrap() = false;

        // Idempotent cleanup: release twice succeeds cleanly both times.
        assert!(release_agent(engine.as_ref(), "claude").unwrap().clean());
        let second_release = release_agent(engine.as_ref(), "claude").unwrap();
        assert!(second_release.clean());
        assert_eq!(second_release.removed, 0);

        assert!(clear_lockdown(engine.as_ref()).unwrap().clean());
        assert!(clear_global_cut(engine.as_ref()).unwrap().clean());
        assert!(engine.enumerate_rules(CG_RULE_PREFIX).unwrap().is_empty());
    }

    #[test]
    fn verbatim_prefix_stripping_stale_agent_lockdown_and_program_upgrade_pruning() {
        assert_eq!(
            normalize_program_path(r"\\?\C:\Program Files\WindowsApps\Claude\claude.exe"),
            r"c:\program files\windowsapps\claude\claude.exe"
        );
        assert_eq!(
            normalize_program_path(r"\\?\UNC\Server\Share\Claude.exe"),
            r"\\server\share\claude.exe"
        );

        let engine = Arc::new(MockFirewall::with_profiles(true, true, true));
        // 1. Lockdown on both claude & chatgpt, then re-apply with ONLY claude (upgraded exe path!)
        let _ = apply_lockdown(
            engine.as_ref(),
            &[
                (
                    "claude".into(),
                    vec![PathBuf::from(r"\\?\C:\Apps\Claude_v1\claude.exe")],
                ),
                (
                    "chatgpt".into(),
                    vec![PathBuf::from(r"C:\Apps\ChatGPT\chatgpt.exe")],
                ),
            ],
        )
        .unwrap();
        assert_eq!(lockdown_status(engine.as_ref()).rules, 2);

        let cov2 = apply_lockdown(
            engine.as_ref(),
            &[(
                "claude".into(),
                vec![PathBuf::from(r"C:\Apps\Claude_v2\claude.exe")],
            )],
        )
        .unwrap();
        assert!(cov2.complete());
        let remaining = engine.enumerate_rules(LOCKDOWN_RULE_PREFIX).unwrap();
        // `chatgpt` lockdown rule removed AND `Claude_v1\claude.exe` pruned in favor of `Claude_v2\claude.exe`!
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "ClaudeGuard Lockdown (claude)");
        assert_eq!(
            normalize_program_path(&remaining[0].program),
            r"c:\apps\claude_v2\claude.exe"
        );

        // 2. Quarantine upgrade also prunes stale v1 program under same Block Out/In rule names
        let _ = quarantine_agent(
            engine.as_ref(),
            "claude",
            &[PathBuf::from(r"C:\Apps\Claude_v1\claude.exe")],
        )
        .unwrap();
        let q2 = quarantine_agent(
            engine.as_ref(),
            "claude",
            &[PathBuf::from(r"C:\Apps\Claude_v2\claude.exe")],
        )
        .unwrap();
        assert!(q2.complete());
        let q_rules = engine.enumerate_rules("ClaudeGuard Block").unwrap();
        assert_eq!(q_rules.len(), 2);
        assert!(q_rules
            .iter()
            .all(|r| normalize_program_path(&r.program) == r"c:\apps\claude_v2\claude.exe"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_com_read_only_enumeration_and_profile_query_work() {
        let engine = ComFirewallEngine::new();
        // Read-only queries on Windows Firewall COM should succeed without elevation.
        let status = engine
            .profile_status()
            .expect("COM profile query should succeed");
        let _ = status.all_enabled();
        let rules = engine
            .enumerate_rules(CG_RULE_PREFIX)
            .expect("COM rule enumeration should succeed");
        let _ = rules.len();
    }
}
