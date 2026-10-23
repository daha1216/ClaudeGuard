//! 监控调度：一轮探测 → 每目标判定 → 防抖 → 熔断/恢复/启动门禁。
//!
//! 只有这个模块会"下决定"；`anchors`/`policy` 是纯逻辑，`guard`/`netcut` 只执行动作。

use crate::config::Config;
use crate::model::{
    now, CutMode, Evaluation, ProbeResult, Target, TargetState, TargetStatus, TripInfo, Verdict,
};
use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri::Manager;

/// 暂停守护的时长（分钟）。
pub const PAUSE_MINUTES: u64 = 30;

/// Claude 的 AUMID 兜底值（包家族未找到时仍可尝试）。
const CLAUDE_APP_ID_FALLBACK: &str = "Claude_pzs8sxrjxfjjc!Claude";

/// v3.10 R08：`Unconfigured`（首启、配置从未有效完成）只允许只读检测与向导，
/// 不允许 launch / kill / 隔离 / 断网 / lockdown。判据只有一个来源：`cfg.first_run`。
pub fn is_unconfigured(cfg: &Config) -> bool {
    cfg.first_run
}

/// 熔断决策的输入（纯数据，便于单测覆盖首启/暂停/未接入等组合）。
#[derive(Debug, Clone, Copy)]
pub struct TripGate {
    pub unconfigured: bool,
    pub paused: bool,
    pub tripped: bool,
    pub access_uncovered: bool,
    pub access_streak: u32,
    pub failing: usize,
    pub max_streak: u32,
    pub threshold: u32,
    pub launch: bool,
    /// v3.10 R06：用户已要求停止保护时不得熔断（否则会立刻撤销急救结果）。
    pub disarmed: bool,
}

/// 是否应当熔断。R08 的约束在这里集中体现：未配置时永不熔断。
pub fn trip_allowed(g: &TripGate) -> bool {
    if g.unconfigured || g.paused || g.tripped || g.disarmed {
        return false;
    }
    let target_trip = g.failing > 0 && (g.launch || g.max_streak >= g.threshold);
    let access_trip = g.access_uncovered && (g.launch || g.access_streak >= g.threshold);
    target_trip || access_trip
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Monitor,
    Manual,
    Launch,
}

#[derive(Debug, Clone)]
pub struct RoundSummary {
    pub passed: bool,
    pub block_reason: String,
    #[allow(dead_code)]
    pub failing: Vec<String>,
}

impl RoundSummary {
    fn ok() -> Self {
        Self {
            passed: true,
            block_reason: String::new(),
            failing: Vec::new(),
        }
    }
}

/// --check 用的只读结果（不写状态、不熔断）。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DryResult {
    pub id: String,
    pub name: String,
    pub pass: bool,
    pub verdict: Verdict,
    pub reason: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub latency_ms: u64,
}

/// 并行探测全部启用目标，返回与输入同序的结果。`proxy=None` 直连（TUN/未接入）。
fn probe_all(cfg: &Config, proxy: Option<String>) -> Vec<(Target, ProbeResult)> {
    let targets: Vec<Target> = cfg.enabled_targets().cloned().collect();
    if targets.is_empty() {
        return Vec::new();
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .iter()
            .map(|target| {
                let proxy = proxy.clone();
                let target = target.clone();
                scope.spawn(move || {
                    let probe = crate::anchors::probe(proxy.as_deref(), &target);
                    (target, probe)
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .collect()
    })
}

/// 单目标"未接入，跳过探测"的结果（run_round / dry_round / recheck 共用文案）。
pub fn dry_skipped(target: &crate::model::Target) -> DryResult {
    dry_skipped_with(target, "未接入代理链路，已跳过探测")
}

/// 带原因的跳过结果（接入路径无法确认时用）。
pub fn dry_skipped_with(target: &crate::model::Target, reason: &str) -> DryResult {
    DryResult {
        id: target.id.clone(),
        name: target.name.clone(),
        pass: false,
        verdict: Verdict::Unverified,
        reason: reason.into(),
        ip: None,
        country: None,
        latency_ms: 0,
    }
}

/// 只读检查（--check 与设置页"测试目标"共用）。探测同样跟随系统代理；
/// 未接入（且启用检查）时不直连，直接标"无法确认"。
pub fn dry_round(cfg: &Config) -> Vec<DryResult> {
    let (route, access) = crate::access::resolve(cfg);
    let enforced = cfg!(target_os = "windows") && cfg.enforce_access_path;
    let skipped = enforced && access.is_uncovered();
    let results = if skipped {
        Vec::new()
    } else {
        match &route {
            crate::access::ProbeRoute::Proxy(url) => probe_all(cfg, Some(url.clone())),
            _ => probe_all(cfg, None),
        }
    };
    results
        .into_iter()
        .map(|(target, probe)| {
            let eval = crate::policy::evaluate(&target, &probe);
            DryResult {
                id: target.id.clone(),
                name: target.name.clone(),
                pass: eval.verdict == Verdict::Pass,
                verdict: eval.verdict,
                reason: eval.reason,
                ip: probe.ip,
                country: probe.country,
                latency_ms: probe.latency_ms,
            }
        })
        .chain(if skipped {
            cfg.targets
                .iter()
                .filter(|t| t.enabled)
                .map(dry_skipped)
                .collect()
        } else {
            Vec::new()
        })
        .collect()
}

/// 跑一轮完整检查（会更新状态、按需熔断/恢复）。
/// 纯函数：本轮依据的配置代次是否已经过期（R10）。
///
/// 过期 = 用户在本轮探测期间改了配置（白名单/目标/档位/阈值），此时本轮的
/// 判定与熔断决定都建立在旧配置上，必须丢弃而不是提交。
pub fn round_is_stale(start_rev: u64, current_rev: u64) -> bool {
    start_rev != current_rev
}

pub fn run_round(state: &Arc<AppState>, purpose: Purpose) -> RoundSummary {
    if state.is_checking() && purpose != Purpose::Launch {
        return RoundSummary::ok();
    }
    // R06/D3：外部 `--restore`/`--rearm` 只改意图文件，常驻实例必须每轮对齐，
    // 否则用户以为停手了，这里下一轮照样杀进程、加规则。
    state.sync_disarm();
    state.set_checking(true);
    state.emit_state();

    // R10：配置与代次取自同一时刻；提交结果前比对，过期轮次不提交。
    let (cfg, rev) = state.config_rev();
    // v3.7 接入路径：探测跟随系统代理；v3.8 起未接入（且启用检查）时不直连探测——
    // 守护器自身流量绝不带着家宽 IP 出机器，判定与熔断靠注册表/TUN 的确定性检查。
    let (route, access) = crate::access::resolve(&cfg);
    state.set_access(access.clone());
    let access_enforced = cfg!(target_os = "windows") && cfg.enforce_access_path;
    let access_uncovered = access_enforced && access.is_uncovered();
    // v3.10 R03：接入路径无法确认（PAC / socks / 缺地址 / 绕过列表）同样不探测、不熔断。
    let access_unknown = access_enforced && access.is_unknown();
    // v3.10 R08：未完成配置时只做只读检测，不探测、不封锁、不熔断。
    let unconfigured = is_unconfigured(&cfg);
    let skip_probes = unconfigured || access_uncovered || access_unknown;

    // v3.10 R06：用户已要求停止保护（如 `--restore` 急救）时，本轮只做检测，
    // 不再封锁/隔离/断网；否则急救刚清掉的规则会被守护器立刻加回去。
    let disarmed = state.is_disarmed();

    // v3.9 防火墙兜底：未接入时维持守护对象出站封锁（回环代理不受影响），接入后自动解除。
    if cfg!(target_os = "windows") && !disarmed {
        let want_lockdown = !unconfigured && access_uncovered && cfg.lockdown_on_uncovered;
        state.sync_lockdown(want_lockdown, &cfg);
    }

    let probes = if skip_probes {
        Vec::new()
    } else {
        match &route {
            crate::access::ProbeRoute::Proxy(url) => probe_all(&cfg, Some(url.clone())),
            // Direct（TUN 接管）；未启用检查时的未接入也按用户选择直连。
            _ => probe_all(&cfg, None),
        }
    };
    let mut statuses: Vec<TargetStatus> = cfg
        .targets
        .iter()
        .map(|t| {
            let state_kind = if t.enabled {
                TargetState::Pending
            } else {
                TargetState::Disabled
            };
            TargetStatus::from_target(t, state_kind)
        })
        .collect();

    let previous = state.statuses();
    let prev_state = |id: &str| {
        previous
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.state)
            .unwrap_or(TargetState::Pending)
    };

    for (target, probe) in probes {
        let Some(slot) = statuses.iter_mut().find(|s| s.id == target.id) else {
            continue;
        };
        let eval: Evaluation = crate::policy::evaluate(&target, &probe);
        let mut streak = previous
            .iter()
            .find(|s| s.id == target.id)
            .map(|s| s.fail_streak)
            .unwrap_or(0);
        match eval.verdict {
            Verdict::Fail => streak = streak.saturating_add(1),
            _ => streak = 0,
        }
        slot.apply(&probe, &eval, streak);
    }

    // v3.8：未接入被跳过探测的目标标"无法确认"，界面与 --check 可见原因。
    if skip_probes {
        let skip_reason = if unconfigured {
            "尚未完成配置，已跳过探测".to_string()
        } else if access_unknown {
            format!("接入路径无法确认，已跳过探测：{}", access.note)
        } else {
            "未接入代理链路，已跳过探测".to_string()
        };
        for slot in statuses.iter_mut() {
            if slot.state == TargetState::Pending {
                slot.state = TargetState::Unverified;
                slot.reason = skip_reason.clone();
                slot.checked_at = Some(crate::model::now());
            }
        }
    }

    // 状态变化日志 + 预警通知（只在跨越阈值-1 时提醒一次）。
    for status in &statuses {
        if status.state == TargetState::Disabled {
            continue;
        }
        let was = prev_state(&status.id);
        if was != status.state {
            state.log(format!(
                "{}：{}（{}）",
                status.name,
                status.reason,
                match status.state {
                    TargetState::Pass => "通过",
                    TargetState::Fail => "未通过",
                    TargetState::Unverified => "无法确认",
                    _ => "等待",
                }
            ));
        }
        if status.state == TargetState::Fail
            && cfg.trip_threshold > 1
            && status.fail_streak == cfg.trip_threshold - 1
            && !state.is_tripped()
        {
            state.log(format!(
                "{} 出口连续 {} 次未通过，再失败一次将熔断",
                status.name, status.fail_streak
            ));
            state.notify(
                "warning",
                "ClaudeGuard 检查未通过",
                &format!(
                    "{} 出口第 {} 次连续失败，再失败一次将熔断。",
                    status.name, status.fail_streak
                ),
            );
        }
    }

    let failing: Vec<String> = statuses
        .iter()
        .filter(|s| s.state == TargetState::Fail)
        .map(|s| s.name.clone())
        .collect();
    let failing_ids: Vec<String> = statuses
        .iter()
        .filter(|s| s.state == TargetState::Fail)
        .map(|s| s.id.clone())
        .collect();
    let passed_count = statuses
        .iter()
        .filter(|s| s.state == TargetState::Pass)
        .count();
    let enabled_count = statuses
        .iter()
        .filter(|s| s.state != TargetState::Disabled)
        .count();
    let max_streak = statuses.iter().map(|s| s.fail_streak).max().unwrap_or(0);

    // R10：这一轮依据的配置若已被改动（用户刚改了白名单/目标/档位），
    // 结果与熔断决定都已过期——丢弃本轮，不写状态、不熔断。
    if round_is_stale(rev, state.cfg_rev()) {
        state.log("配置已变更，本轮检查结果作废（下一轮按新配置重新判定）");
        state.set_checking(false);
        state.emit_state();
        return RoundSummary::ok();
    }

    state.set_statuses(statuses.clone());
    state.set_last_check(now());
    // R09/D6：能跑完一轮检查就说明新版本可用，这时才允许清理上一版备份。
    crate::update::confirm_healthy();

    let all_pass = enabled_count > 0 && passed_count == enabled_count;
    let primary_ip = statuses.iter().find_map(|s| s.ip.clone());
    let reason = if failing.is_empty() {
        String::new()
    } else {
        format!("{} 出口不在白名单", failing.join("、"))
    };
    let access_reason = "系统代理未开启且未检测到 TUN 网卡，应用会直连真实出口";
    let mut summary = RoundSummary {
        passed: all_pass,
        block_reason: if unconfigured {
            "尚未完成配置：请先在向导中设置监控目标与白名单".to_string()
        } else if !failing.is_empty() {
            reason.clone()
        } else if access_uncovered {
            access_reason.to_string()
        } else if access_unknown {
            format!("无法确认应用接入路径，暂不允许启动：{}", access.note)
        } else if all_pass {
            String::new()
        } else {
            "部分目标无法确认，暂不允许启动".to_string()
        },
        failing: failing.clone(),
    };

    let paused = state.is_paused();

    // v3.7 接入路径防抖：未接入与目标 Fail 走同一套阈值语义。
    let access_streak = if access_uncovered && !unconfigured {
        state.bump_access_streak()
    } else {
        state.reset_access_streak();
        0
    };
    if access_uncovered
        && !state.is_tripped()
        && cfg.trip_threshold > 1
        && access_streak == cfg.trip_threshold - 1
    {
        state.log("接入路径连续未接入，下一轮将熔断");
        state.notify(
            "warning",
            "ClaudeGuard 检查未通过",
            "系统代理未开启且无 TUN 网卡，应用正直连真实出口；下一轮将熔断。",
        );
    }
    let gate = TripGate {
        unconfigured,
        paused,
        tripped: state.is_tripped(),
        access_uncovered,
        access_streak,
        failing: failing.len(),
        max_streak,
        threshold: cfg.trip_threshold,
        launch: purpose == Purpose::Launch,
        disarmed,
    };
    let access_trip = access_uncovered
        && !unconfigured
        && !paused
        && !state.is_tripped()
        && (purpose == Purpose::Launch || access_streak >= cfg.trip_threshold);
    let should_trip = trip_allowed(&gate);

    if should_trip {
        if access_trip && failing.is_empty() {
            do_trip(state, &cfg, &[], access_reason);
        } else {
            do_trip(state, &cfg, &failing_ids, &reason);
        }
    } else if state.is_tripped() {
        if !failing.is_empty() || access_uncovered {
            if cfg.kill_on_fail && !unconfigured && !disarmed {
                let mut killed = crate::guard::kill_agents(&cfg);
                if cfg.guarded_agents.iter().any(|id| id == "claude") {
                    killed += crate::guard::kill_claude_cli();
                }
                if killed > 0 {
                    state.log(format!("持续异常：再次结束 {killed} 个进程"));
                }
            }
        } else if passed_count > 0
            && enabled_count > 0
            && passed_count == enabled_count
            && !access_uncovered
        {
            // v3.7：恢复额外要求接入路径已重新覆盖（系统代理或 TUN）。
            do_recover(state, &cfg, primary_ip.as_deref());
        }
    } else if all_pass && !failing.is_empty() {
        state.set_launch_error(reason.clone());
    }

    state.set_checking(false);
    state.emit_state();

    summary.passed = all_pass && !state.is_tripped();
    summary
}

fn do_trip(state: &Arc<AppState>, cfg: &Config, failing_ids: &[String], reason: &str) {
    // R10：熔断是唯一的"高权限副作用"，同一时刻只允许一轮执行；抢不到说明
    // 另一轮已经在做（手动检查与定时检查撞车），本轮直接放弃，不重复杀/重复加规则。
    let Ok(_guard) = state.trip_guard.try_lock() else {
        state.log("另一轮检查正在执行熔断，本轮跳过");
        return;
    };
    if state.is_tripped() {
        return;
    }
    let mode = if cfg!(target_os = "macos") {
        CutMode::Off
    } else {
        cfg.cut_mode()
    };
    state.log(format!("触发熔断：{reason}；断网档位 {}", mode.label()));
    let trip = crate::guard::trip(cfg, reason);
    let (cut_ok, cut_note) = crate::netcut::cut(mode);
    if !cut_ok && mode != CutMode::Off {
        state.log(format!("断网执行未完全成功：{cut_note}"));
    }
    let info = TripInfo {
        since: now(),
        reason: reason.to_string(),
        failing_ids: failing_ids.to_vec(),
        killed: trip.killed as u32,
        firewall_rules: trip.firewall_rules as u32,
        quarantined_agents: if trip.quarantined {
            trip.agents.clone()
        } else {
            Vec::new()
        },
        agents: trip.agents.clone(),
        network_cut: if cfg!(target_os = "macos") && !cut_ok {
            CutMode::Off
        } else {
            mode
        },
        network_note: if cfg!(target_os = "macos") {
            "进程守护模式：已执行配置的进程关闭操作；出口未通过时禁止从守护器启动，网络保持连接"
                .into()
        } else if cut_ok {
            String::new()
        } else {
            cut_note.clone()
        },
    };
    state.set_tripped(Some(info));
    state.log(format!(
        "熔断完成：结束 {} 个进程（其中 CLI {}），防火墙隔离 {} 条，断网 {}",
        trip.killed,
        trip.cli_killed,
        trip.firewall_rules,
        if cut_ok { mode.label() } else { "执行失败" }
    ));
    let body = if cfg!(target_os = "macos") {
        format!("{reason}，已执行配置的进程关闭操作；出口未通过时禁止从守护器启动。")
    } else {
        format!("{reason}，已结束相关应用并切断网络。修正后自动恢复。")
    };
    state.notify("trip", "ClaudeGuard 已熔断", &body);
    state.feishu.observe(
        false,
        &format!("{reason}（{cut_note}）"),
        None,
        true,
        if cfg!(target_os = "macos") {
            "已熔断，禁止守护器启动"
        } else {
            "已熔断隔离"
        },
    );
}

fn do_recover(state: &Arc<AppState>, _cfg: &Config, ip: Option<&str>) {
    let (ok, note) = crate::netcut::restore();
    let released = crate::guard::firewall_release();
    state.set_tripped(None);
    state.clear_streaks();
    state.log(format!(
        "恢复：出口检查通过，解除隔离{}，网络{}",
        if released {
            "成功"
        } else {
            "无可解除规则"
        },
        if ok { "已恢复" } else { &note }
    ));
    state.notify(
        "recover",
        "ClaudeGuard 已恢复",
        if cfg!(target_os = "macos") {
            "出口检查通过，已恢复启动许可；应用需手动启动。"
        } else {
            "出口检查通过，已解除隔离并恢复网络。"
        },
    );
    state
        .feishu
        .observe(true, "出口检查通过", ip, false, "已解除隔离");
}

/// 手动"重新检查"（异步）。
pub fn recheck(state: &Arc<AppState>) {
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        run_round(&state, Purpose::Manual);
    });
}

fn launch_permission(summary: &RoundSummary, tripped: bool) -> Result<(), String> {
    if !summary.passed {
        return Err(if summary.block_reason.is_empty() {
            "出口检查未通过".into()
        } else {
            summary.block_reason.clone()
        });
    }
    if tripped {
        return Err("熔断状态尚未解除".into());
    }
    Ok(())
}

/// 启动门禁：必须所有启用目标通过才放行 Claude。
/// 契约 D3：已停止保护时守护器不再校验出口，因此也不能代用户启动。
pub fn disarmed_launch_reason(disarmed: bool) -> Option<String> {
    if disarmed {
        Some("已停止保护，无法通过守护器启动；请先重新布防".to_string())
    } else {
        None
    }
}

pub fn launch(state: &Arc<AppState>) -> Result<(), String> {
    // 契约 D3：已停止保护时守护器不再承担"通过检查才放行"的责任，
    // 因此也不能代替用户启动——否则等于用一条不再校验的通道冒充门禁。
    if let Some(reason) = disarmed_launch_reason(state.is_disarmed()) {
        state.set_launch_error(reason.clone());
        state.log(format!("阻止启动：{reason}"));
        state.emit_state();
        return Err(reason);
    }
    let cfg = state.config();
    let summary = run_round(state, Purpose::Launch);
    if let Err(reason) = launch_permission(&summary, state.is_tripped()) {
        state.set_launch_error(reason.clone());
        state.log(format!("阻止启动：{reason}"));
        state.notify("launch_blocked", "ClaudeGuard 已阻止启动", &reason);
        state.emit_state();
        return Err(reason);
    }
    let app_id = crate::guard::resolve_app_id(CLAUDE_APP_ID_FALLBACK);
    match crate::guard::launch_claude(&app_id) {
        Ok(()) => {
            state.set_launch_error("");
            state.log("校验通过，已启动 Claude");
            if cfg.close_to_tray {
                if let Some(window) = state.app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            state.emit_state();
            Ok(())
        }
        Err(err) => {
            state.set_launch_error(err.clone());
            state.log(format!("启动失败：{err}"));
            state.emit_state();
            Err(err)
        }
    }
}

/// 暂停守护；到点自动恢复。
pub fn pause(state: &Arc<AppState>, minutes: u64) {
    let until = now().saturating_add(minutes.saturating_mul(60));
    state.set_paused_until(Some(until));
    // CONTRACT D3：暂停只停"新的"副作用，既有隔离原样保留。
    state.log(format!(
        "暂停守护 {minutes} 分钟：期间不再熔断/结束进程/断网，既有隔离保持不变"
    ));
    state.emit_state();
}

pub fn resume(state: &Arc<AppState>) {
    state.set_paused_until(None);
    // 恢复只恢复检查；若仍处于熔断，需用户显式"解除隔离"（D3：不自动解除）。
    if state.is_tripped() {
        state.log("恢复守护：检查已恢复；当前仍处于熔断状态，解除隔离需手动操作");
    } else {
        state.log("恢复守护：检查已恢复");
    }
    state.emit_state();
}

pub fn toggle_pause(state: &Arc<AppState>) {
    if state.is_paused() {
        resume(state);
    } else {
        pause(state, PAUSE_MINUTES);
    }
}

/// 手动解除隔离并恢复网络（不改变配置）。
pub fn release(state: &Arc<AppState>) {
    let (ok, note) = crate::netcut::restore();
    let released = crate::guard::firewall_release();
    state.set_tripped(None);
    state.clear_streaks();
    state.log(format!(
        "手动解除隔离：网络{}，防火墙规则{}",
        if ok { "已恢复" } else { &note },
        if released { "已解除" } else { "无" }
    ));
    state.notify(
        "recover",
        "ClaudeGuard 已恢复",
        if cfg!(target_os = "macos") {
            "已清除熔断状态；启动前仍需出口检测通过。"
        } else {
            "已手动解除隔离并恢复网络。"
        },
    );
    state.emit_state();
}

/// 后台监控线程：启动 1 秒后首轮，之后按配置间隔轮询。
pub fn spawn(state: Arc<AppState>) {
    spawn_sweeper(Arc::clone(&state));
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(1));
        let mut last_run = 0u64;
        loop {
            if state.stop.load(Ordering::SeqCst) {
                break;
            }
            let interval = state.config().interval_secs();
            let ts = now();
            if ts.saturating_sub(last_run) >= interval && !state.is_checking() {
                last_run = ts;
                run_round(&state, Purpose::Monitor);
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    });
}

/// 残留清理线程（v3.2）：盯 Claude 桌面端是否退出；退出并度过宽限期后清掉残留进程
/// （桌面家族 + 孤儿 CLI）。暂停守护 / 未守护 claude / 配置关闭时不动作。
fn spawn_sweeper(state: Arc<AppState>) {
    std::thread::spawn(move || {
        const TICK_MS: u64 = 2000;
        const GRACE_SECS: u64 = 4;
        let mut desktop_seen = false;
        let mut gone_at: Option<u64> = None;
        loop {
            if state.stop.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(TICK_MS));
            let cfg = state.config();
            let active = cfg.sweep_on_exit
                && cfg.guarded_agents.iter().any(|a| a == "claude")
                && !state.is_paused()
                && !state.is_disarmed();
            if !active {
                desktop_seen = false;
                gone_at = None;
                continue;
            }
            let claude_dir_l =
                crate::guard::find_claude_dir().map(|d| d.to_string_lossy().to_lowercase());
            let procs = crate::guard::snapshot_processes();
            let desktop_now = procs.iter().any(|p| {
                crate::guard::classify_claude(p, claude_dir_l.as_deref())
                    == Some(crate::guard::ClaudeKind::Desktop)
            });
            if desktop_now {
                desktop_seen = true;
                gone_at = None;
                continue;
            }
            if !desktop_seen {
                gone_at = None;
                continue;
            }
            // 下降沿：桌面端刚消失。宽限几秒复查（自动更新/快速重启会自己回来），过后清残留。
            let ts = now();
            let gone = *gone_at.get_or_insert(ts);
            if ts.saturating_sub(gone) < GRACE_SECS {
                continue;
            }
            let report = crate::guard::sweep_claude(crate::guard::SweepMode::Residual);
            if report.killed > 0 {
                state.log(format!(
                    "清理残留：Claude 退出后结束 {} 个进程（桌面 {} / CLI {}）",
                    report.killed, report.desktop_killed, report.cli_killed
                ));
            }
            desktop_seen = false;
            gone_at = None;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_rounds_are_discarded() {
        // R10：代次没变 → 结果可提交；代次变了 → 本轮作废（不写状态、不熔断）。
        assert!(!round_is_stale(3, 3));
        assert!(round_is_stale(3, 4));
        assert!(round_is_stale(4, 3), "任何不一致都按过期处理，宁可不提交");
    }

    /// 行为锁：停止保护期间不得代用户启动（否则等于用不校验的通道冒充门禁）。
    #[test]
    fn launch_is_refused_while_disarmed() {
        assert!(disarmed_launch_reason(true).is_some());
        assert!(disarmed_launch_reason(false).is_none());
    }

    #[test]
    fn launch_denies_failed_unverified_empty_and_unreleased_trip() {
        for reason in ["出口不在白名单", "部分目标无法确认，暂不允许启动", ""]
        {
            let summary = RoundSummary {
                passed: false,
                block_reason: reason.into(),
                failing: vec![],
            };
            assert!(launch_permission(&summary, false).is_err());
            assert!(launch_permission(&summary, true).is_err());
        }
        assert!(launch_permission(&RoundSummary::ok(), true).is_err());
        assert!(launch_permission(&RoundSummary::ok(), false).is_ok());
    }

    fn gate() -> TripGate {
        TripGate {
            unconfigured: false,
            paused: false,
            tripped: false,
            access_uncovered: false,
            access_streak: 0,
            failing: 0,
            max_streak: 0,
            threshold: 3,
            launch: false,
            disarmed: false,
        }
    }

    /// 行为锁：用户已要求停止保护（如刚跑过 `--restore` 急救）时，
    /// 即便各项都失败也不能熔断，否则守护器会把急救结果立刻撤销。
    #[test]
    fn disarmed_never_trips_even_when_everything_fails() {
        let mut g = gate();
        g.disarmed = true;
        g.failing = 3;
        g.max_streak = 99;
        g.access_uncovered = true;
        g.access_streak = 99;
        g.launch = true;
        assert!(!trip_allowed(&g), "停止保护期间不允许熔断");

        // 反向对照：同样的失败，没有停止保护时应当熔断——否则上一条断言没有意义。
        g.disarmed = false;
        assert!(trip_allowed(&g));
    }

    #[test]
    fn unconfigured_never_trips_even_on_launch_with_failures() {
        let mut g = gate();
        g.unconfigured = true;
        g.launch = true;
        g.failing = 2;
        g.max_streak = 9;
        g.access_uncovered = true;
        g.access_streak = 9;
        assert!(!trip_allowed(&g), "首启未配置时不允许任何熔断");
    }

    #[test]
    fn configured_trip_follows_launch_or_threshold() {
        let mut g = gate();
        g.failing = 1;
        g.max_streak = 1;
        assert!(!trip_allowed(&g), "后台轮次未达阈值不熔断");
        g.max_streak = 3;
        assert!(trip_allowed(&g), "后台轮次达阈值应熔断");
        g.max_streak = 1;
        g.launch = true;
        assert!(trip_allowed(&g), "启动前检查失败应立即熔断");
    }

    #[test]
    fn paused_or_tripped_or_uncovered_gate() {
        let mut g = gate();
        g.failing = 1;
        g.launch = true;
        g.paused = true;
        assert!(!trip_allowed(&g));
        g.paused = false;
        g.tripped = true;
        assert!(!trip_allowed(&g));
        g.tripped = false;
        g.failing = 0;
        g.launch = false;
        g.access_uncovered = true;
        g.access_streak = 3;
        assert!(trip_allowed(&g), "未接入达阈值同样熔断");
        g.access_streak = 1;
        assert!(!trip_allowed(&g));
    }

    #[test]
    fn summary_blocks_when_failing() {
        let summary = RoundSummary {
            passed: false,
            block_reason: "Claude 出口不在白名单".into(),
            failing: vec!["Claude 出口".into()],
        };
        assert!(!summary.passed);
        assert!(summary.block_reason.contains("Claude"));
    }

    #[test]
    fn ok_summary_is_pass() {
        let summary = RoundSummary::ok();
        assert!(summary.passed);
        assert!(summary.block_reason.is_empty());
    }
}
