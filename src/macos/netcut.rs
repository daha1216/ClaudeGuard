//! No pretend firewall success. Full macOS isolation requires a signed Network Extension.
use crate::model::CutMode;
pub fn cut(mode: CutMode) -> (bool, String) {
    if mode == CutMode::Off {
        (true, "未请求断网".into())
    } else {
        (
            false,
            "macOS 网络隔离尚未实现：需要签名的 Network Extension；网络未切断".into(),
        )
    }
}
pub fn restore() -> (bool, String) {
    (
        true,
        "此 macOS 构建未安装网络规则，无需恢复；不处理其他程序的规则".into(),
    )
}
pub fn heal() -> Vec<String> {
    vec!["macOS 移植预览：仅检测与结束进程，尚不支持按应用隔离或全局断网".into()]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_modes_never_report_success() {
        assert!(cut(CutMode::Off).0);
        assert!(!cut(CutMode::Firewall).0);
        assert!(!cut(CutMode::Nics).0);
        assert!(restore().0);
        assert!(restore().0);
    }
}
