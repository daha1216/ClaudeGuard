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

fn proxy_url(cfg: &Config) -> String {
    cfg.proxy_url()
}

/// 并行探测全部启用目标，返回与输入同序的结果。
fn probe_all(cfg: &Config) -> Vec<(Target, ProbeResult)> {
    let targets: Vec<Target> = cfg.enabled_targets().cloned().collect();
    if targets.is_empty() {
        return Vec::new();
    }
    let proxy = proxy_url(cfg);
    std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .iter()
            .map(|target| {
                let proxy = proxy.clone();
                let target = target.clone();
                scope.spawn(move || {
                    let probe = crate::anchors::probe(&proxy, &target);
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

/// 只读检查（--check 与设置页"测试目标"共用）。
pub fn dry_round(cfg: &Config) -> Vec<DryResult> {
    probe_all(cfg)
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
        .collect()
}

/// 跑一轮完整检查（会更新状态、按需熔断/恢复）。
pub fn run_round(state: &Arc<AppState>, purpose: Purpose) -> RoundSummary {
    if state.is_checking() && purpose != Purpose::Launch {
        return RoundSummary::ok();
    }
    state.set_checking(true);
    state.emit_state();

    let cfg = state.config();
    let probes = probe_all(&cfg);
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

    state.set_statuses(statuses.clone());
    state.set_last_check(now());

    let all_pass = enabled_count > 0 && passed_count == enabled_count;
    let primary_ip = statuses.iter().find_map(|s| s.ip.clone());
    let reason = if failing.is_empty() {
        String::new()
    } else {
        format!("{} 出口不在白名单", failing.join("、"))
    };
    let mut summary = RoundSummary {
        passed: all_pass,
        block_reason: if failing.is_empty() {
            if all_pass {
                String::new()
            } else {
                "部分目标无法确认，暂不允许启动".to_string()
            }
        } else {
            reason.clone()
        },
        failing: failing.clone(),
    };

    let paused = state.is_paused();
    let should_trip = !failing.is_empty()
        && !state.is_tripped()
        && !paused
        && (purpose == Purpose::Launch || max_streak >= cfg.trip_threshold);

    if should_trip {
        do_trip(state, &cfg, &failing_ids, &reason);
    } else if state.is_tripped() {
        if !failing.is_empty() {
            if cfg.kill_on_fail {
                let killed = crate::guard::kill_agents(&cfg);
                if killed > 0 {
                    state.log(format!("持续异常：再次结束 {killed} 个进程"));
                }
            }
        } else if passed_count > 0 && enabled_count > 0 && passed_count == enabled_count {
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
    let mode = cfg.cut_mode();
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
        network_cut: mode,
        network_note: if cut_ok {
            String::new()
        } else {
            cut_note.clone()
        },
    };
    state.set_tripped(Some(info));
    state.log(format!(
        "熔断完成：结束 {} 个进程，防火墙隔离 {} 条，断网 {}",
        trip.killed,
        trip.firewall_rules,
        if cut_ok { mode.label() } else { "执行失败" }
    ));
    let body = format!("{reason}，已结束相关应用并切断网络。修正后自动恢复。");
    state.notify("trip", "ClaudeGuard 已熔断", &body);
    state.feishu.observe(
        false,
        &format!("{reason}（{cut_note}）"),
        None,
        true,
        "已熔断隔离",
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
        "出口检查通过，已解除隔离并恢复网络。",
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

/// 启动门禁：必须所有启用目标通过才放行 Claude。
pub fn launch(state: &Arc<AppState>) -> Result<(), String> {
    let cfg = state.config();
    let summary = run_round(state, Purpose::Launch);
    if !summary.passed {
        let reason = if summary.block_reason.is_empty() {
            "出口检查未通过".to_string()
        } else {
            summary.block_reason.clone()
        };
        state.set_launch_error(reason.clone());
        state.log(format!("阻止启动：{reason}"));
        state.notify("launch_blocked", "ClaudeGuard 已阻止启动", &reason);
        state.emit_state();
        return Err(reason);
    }
    if !cfg.kill_on_fail && state.is_tripped() {
        return Err("熔断状态尚未解除".into());
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
    state.log(format!("暂停守护 {minutes} 分钟"));
    state.emit_state();
}

pub fn resume(state: &Arc<AppState>) {
    state.set_paused_until(None);
    state.log("恢复守护");
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
        "已手动解除隔离并恢复网络。",
    );
    state.emit_state();
}

/// 后台监控线程：启动 1 秒后首轮，之后按配置间隔轮询。
pub fn spawn(state: Arc<AppState>) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
