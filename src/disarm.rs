//! 停止保护（Disarmed）意图：`--restore` 等外部入口用它通知存活实例"别再重新
//! 施加规则"，并让这个意图跨重启保留——否则用户急救后一重启，守护器又把规则
//! 加回去，急救等于白做。
//!
//! 存的是**意图**而不是结果：文件存在 = 用户要求停止保护。文件内容只作展示
//! （何时、为何），解析失败也不影响"已停止保护"这个判断。

use std::path::Path;

const FILE: &str = "disarmed";

/// 读某个目录下的停止保护意图；返回原因文本（可能为空）。
pub fn reason_in(dir: &Path) -> Option<String> {
    let path = dir.join(FILE);
    if !path.exists() {
        return None;
    }
    Some(std::fs::read_to_string(&path).unwrap_or_default())
}

/// 当前是否处于"已停止保护"状态；返回原因文本（可能为空）。
pub fn reason() -> Option<String> {
    reason_in(&crate::config::config_dir())
}

/// 标记"用户要求停止保护"。写失败要如实返回——调用方不能假装已停用。
pub fn mark_in(dir: &Path, reason_text: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建目录失败：{e}"))?;
    std::fs::write(dir.join(FILE), reason_text).map_err(|e| format!("写入停止保护标记失败：{e}"))
}

pub fn mark(reason_text: &str) -> Result<(), String> {
    mark_in(&crate::config::config_dir(), reason_text)
}

pub fn clear_in(dir: &Path) -> Result<(), String> {
    let path = dir.join(FILE);
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(&path).map_err(|e| format!("删除停止保护标记失败：{e}"))
}

pub fn clear() -> Result<(), String> {
    clear_in(&crate::config::config_dir())
}

/// 内存里的意图与磁盘上的不一致时，返回"应该更新成什么"。
///
/// 存活实例只在启动时读一次磁盘，外部 `--restore` 改的是文件；没有这层比对，
/// 用户以为已经停手，常驻进程下一轮照样杀进程、加规则。
pub fn reconcile(memory: Option<&str>, disk: Option<&str>) -> Option<Option<String>> {
    let same = match (memory, disk) {
        (None, None) => true,
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    if same {
        None
    } else {
        Some(disk.map(str::to_string))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// 行为锁：没有标记文件就是"仍在布防"，不能被解读成"已停止保护"。
    #[test]
    fn missing_file_means_still_armed() {
        let dir = temp("cg-disarm-test-none");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(reason_in(&dir), None);
    }

    /// 行为锁：写入后能读到原因，删除后回到"布防"。
    #[test]
    fn mark_and_clear_roundtrip() {
        let dir = temp("cg-disarm-test-rt");
        mark_in(&dir, "急救恢复").unwrap();
        assert_eq!(reason_in(&dir).as_deref(), Some("急救恢复"));
        clear_in(&dir).unwrap();
        assert_eq!(reason_in(&dir), None);
        // 目录不存在时删除也要成功（幂等）。
        clear_in(&dir).unwrap();
    }

    /// 写不进去必须报错：调用方靠返回值判断"是否真的停用了保护"。
    #[test]
    fn mark_reports_failure_instead_of_pretending() {
        let dir = temp("cg-disarm-test-bad");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("blocker");
        std::fs::write(&file, "x").unwrap();
        // 拿文件当目录用，create_dir_all 必然失败。
        let err = mark_in(&file, "急救恢复").unwrap_err();
        assert!(err.contains("创建目录失败"), "实际：{err}");
    }

    /// 存活实例与磁盘意图不一致时给出新值，一致时不动（避免每轮重复打日志）。
    #[test]
    fn reconcile_only_reports_real_changes() {
        assert_eq!(reconcile(None, None), None);
        assert_eq!(reconcile(Some("a"), Some("a")), None);
        assert_eq!(
            reconcile(None, Some("急救")),
            Some(Some("急救".to_string()))
        );
        assert_eq!(reconcile(Some("急救"), None), Some(None));
        assert_eq!(
            reconcile(Some("旧"), Some("新")),
            Some(Some("新".to_string()))
        );
    }
}
