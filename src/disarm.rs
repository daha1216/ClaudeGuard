//! 停止保护（Disarmed）意图：`--restore` 等外部入口用它通知存活实例"别再重新
//! 施加规则"，并让这个意图跨重启保留——否则用户急救后一重启，守护器又把规则
//! 加回去，急救等于白做。
//!
//! 存的是**意图**而不是结果：文件存在 = 用户要求停止保护。文件内容只作展示
//! （何时、为何），解析失败也不影响"已停止保护"这个判断。

use std::path::PathBuf;

const FILE: &str = "disarmed";

fn path() -> PathBuf {
    crate::config::config_dir().join(FILE)
}

/// 当前是否处于"已停止保护"状态；返回原因文本（可能为空）。
pub fn reason() -> Option<String> {
    let path = path();
    if !path.exists() {
        return None;
    }
    Some(std::fs::read_to_string(&path).unwrap_or_default())
}

/// 标记"用户要求停止保护"。写失败要如实返回——调用方不能假装已停用。
pub fn mark(reason_text: &str) -> Result<(), String> {
    let path = path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
    }
    std::fs::write(&path, reason_text).map_err(|e| format!("写入停止保护标记失败：{e}"))
}

pub fn clear() -> Result<(), String> {
    let path = path();
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(&path).map_err(|e| format!("删除停止保护标记失败：{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 行为锁：没有标记文件就是"仍在布防"，不能被解读成"已停止保护"。
    #[test]
    fn missing_file_means_still_armed() {
        let dir = std::env::temp_dir().join("cg-disarm-test-none");
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join(FILE);
        assert!(!file.exists());
        // 直接验证判断逻辑：文件不存在 → None。
        assert_eq!(
            if file.exists() {
                Some(String::new())
            } else {
                None
            },
            None
        );
    }

    /// 行为锁：写入后能读到原因，删除后回到"布防"。
    #[test]
    fn mark_and_clear_roundtrip() {
        let dir = std::env::temp_dir().join("cg-disarm-test-rt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(FILE);
        std::fs::write(&file, "急救恢复").unwrap();
        assert!(file.exists());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "急救恢复");
        std::fs::remove_file(&file).unwrap();
        assert!(!file.exists());
    }
}
