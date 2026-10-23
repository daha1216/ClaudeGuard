//! 恢复协调（R06）：所有"停止保护并恢复系统"的入口走同一份实现。
//!
//! 入口：正常恢复并退出、`--restore` 离线急救、`--uninstall`、安装器卸载。
//! 每个入口都拿到同一份**分项结构化结果**，不允许某处"看起来成功"而实际残留。
//!
//! 恢复分项（顺序即执行顺序）：
//! 1. 网络：按账本恢复本产品断网（删全局阻断规则、启用本产品禁用的网卡）
//! 2. 熔断隔离：删除按 exe 的出/入站 Block 规则
//! 3. 兜底封锁：删除 Lockdown 规则
//! 4. 核验：查询规则是否真的清空（查询失败不算成功）

use crate::guard;

/// 单个恢复项的结果。
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Item {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// 恢复报告：`ok` 只在所有项都成功且核验通过时为 true。
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Report {
    pub items: Vec<Item>,
    pub ok: bool,
    /// 核验是否真的执行过（查询失败时为 false，不能宣称"已恢复干净"）
    pub verified: bool,
}

impl Report {
    fn new() -> Report {
        Report {
            items: Vec::new(),
            ok: true,
            verified: false,
        }
    }

    fn push(&mut self, name: &str, ok: bool, detail: &str) {
        if !ok {
            self.ok = false;
        }
        self.items.push(Item {
            name: name.to_string(),
            ok,
            detail: detail.to_string(),
        });
    }

    /// 给日志/界面的一句话结论。
    pub fn summary(&self) -> String {
        let failed: Vec<String> = self
            .items
            .iter()
            .filter(|i| !i.ok)
            .map(|i| {
                if i.detail.is_empty() {
                    i.name.clone()
                } else {
                    format!("{}（{}）", i.name, i.detail)
                }
            })
            .collect();
        if failed.is_empty() {
            if self.verified {
                "已恢复：本产品的网络改动与隔离规则均已清除并核验".to_string()
            } else {
                "已执行恢复，但未能核验结果".to_string()
            }
        } else {
            format!("恢复未完成：{}", failed.join("；"))
        }
    }
}

/// 停止保护并恢复系统（流程 B）。不依赖探测成功，也不依赖 GUI。
pub fn restore_all() -> Report {
    let mut report = Report::new();

    // 1. 网络（账本驱动）
    let (net_ok, net_note) = crate::netcut::restore();
    report.push("恢复网络", net_ok, &net_note);

    // 2. 熔断隔离规则
    let released = guard::firewall_release();
    report.push(
        "解除熔断隔离",
        true,
        if released {
            "已删除隔离规则"
        } else {
            "未发现隔离规则"
        },
    );

    // 3. 兜底封锁规则
    let cleared = guard::lockdown_clear();
    report.push(
        "解除兜底封锁",
        true,
        if cleared {
            "已删除封锁规则"
        } else {
            "未发现封锁规则"
        },
    );

    // 4. 核验：必须查得到"本产品规则已为 0 条"才算完成
    let (verified, detail) = verify_cleanup(guard::firewall_rule_count());
    report.verified = verified;
    report.push("核验规则清空", verified, &detail);

    if !report.ok {
        log_line(&format!("recover: {}", report.summary()));
    }
    report
}

/// 纯函数：把"规则条数查询结果"翻译成核验结论。
///
/// 查询失败（None）绝不算成功——那正是最危险的情形：规则可能还在，
/// 只是我们看不见。宁可报告"未能核验"，也不能宣称"已恢复干净"。
pub fn verify_cleanup(count: Option<usize>) -> (bool, String) {
    match count {
        Some(0) => (true, "本产品防火墙规则已为 0 条".to_string()),
        Some(n) => (false, format!("仍有 {n} 条规则残留")),
        None => (false, "无法查询防火墙规则，未能核验".to_string()),
    }
}

fn log_line(line: &str) {
    crate::guard::log_line(line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_fails_when_any_item_fails() {
        let mut r = Report::new();
        r.push("恢复网络", true, "");
        r.push("解除隔离", false, "权限不足");
        assert!(!r.ok);
        assert!(r.summary().contains("解除隔离"));
        assert!(r.summary().contains("权限不足"));
    }

    /// 行为锁：查询失败不能变成"已恢复干净"，残留条数要如实报告。
    #[test]
    fn cleanup_verification_never_trusts_a_failed_query() {
        let (ok, detail) = verify_cleanup(None);
        assert!(!ok, "查不到规则时不能宣称已清空");
        assert!(detail.contains("未能核验"));

        let (ok, detail) = verify_cleanup(Some(3));
        assert!(!ok);
        assert!(detail.contains("仍有 3 条"));

        let (ok, detail) = verify_cleanup(Some(0));
        assert!(ok);
        assert!(detail.contains("0 条"));
    }

    #[test]
    fn report_never_claims_clean_without_verification() {
        let mut r = Report::new();
        r.push("恢复网络", true, "");
        assert!(r.ok);
        assert!(!r.verified);
        assert!(r.summary().contains("未能核验"), "没核验就不能说恢复干净");

        r.verified = true;
        assert!(r.summary().contains("均已清除并核验"));
    }
}
