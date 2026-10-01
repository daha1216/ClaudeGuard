//! v2 IPC 绑定层：#[tauri::command] 薄封装，全部转发到既有核心模块。
//! 红线：不改守卫判定/核心模块内部实现，本文件只做参数搬运与序列化。

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tauri::State;

use crate::config::Config;
use crate::install;
use crate::monitor::{self, Shared, UpdState};

type Sh<'a> = State<'a, Arc<Shared>>;

/// 守卫快照（前端进入时拉一次，之后靠 guard://status 事件）。
#[tauri::command]
pub fn get_state(sh: Sh) -> monitor::StatusSnapshot {
    monitor::sh_full_snapshot(&sh)
}

#[tauri::command]
pub fn get_config(sh: Sh) -> Config {
    sh.cfg.lock().unwrap().clone()
}

/// 前端校验通过后整体写回（v1 语义：字段合法才保存）。
/// 更新 Shared 里的活配置，监测线程下一轮即用新值。
#[tauri::command]
pub fn set_config(sh: Sh, cfg: Config) -> Result<(), String> {
    if let Err(e) = cfg.save() {
        return Err(format!("保存失败：{e}"));
    }
    *sh.cfg.lock().unwrap() = cfg;
    Ok(())
}

/// 手动"重新检查"（托盘同款）。
#[tauri::command]
pub fn recheck(sh: Sh) {
    monitor::spawn_check(&sh, monitor::Purpose::Manual);
}

/// "启动 Claude"：先完整复查，通过才启动（v1 Purpose::Launch）。
#[tauri::command]
pub fn launch(sh: Sh) {
    monitor::spawn_check(&sh, monitor::Purpose::Launch);
}

/// 托盘"解除隔离"。
#[tauri::command]
pub fn release(sh: Sh) {
    monitor::release_now(&sh);
}

#[tauri::command]
pub fn recent_logs(sh: Sh) -> Vec<String> {
    sh.loglines.lock().unwrap().clone()
}

/// 底栏"打开数据文件夹"：%APPDATA%\ClaudeGuard。
#[tauri::command]
pub fn open_data_folder() {
    let dir = crate::config::config_dir();
    let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
}

/// 向导页 2 选项 A / 底栏"安装到电脑"（install::install 原样调用）。
#[tauri::command]
pub fn install_app(sh: Sh) -> Result<String, String> {
    match install::install() {
        Ok(path) => {
            monitor::INSTALLED_FLAG.store(true, Ordering::SeqCst);
            sh.log(format!("安装完成： {}", path.display()));
            Ok(path.to_string_lossy().into_owned())
        }
        Err(e) => {
            sh.log(format!("安装失败： {e}"));
            Err(e)
        }
    }
}

/// 设置卡"开机自启"开关：install::set_autostart + 配置落盘（v1 同款三连）。
#[tauri::command]
pub fn set_autostart(sh: Sh, enabled: bool) -> bool {
    let ok = install::set_autostart(enabled);
    {
        let mut cfg = sh.cfg.lock().unwrap();
        cfg.auto_start_with_system = enabled;
        let _ = cfg.save();
    }
    ok
}

#[tauri::command]
pub fn upd_state(sh: Sh) -> UpdState {
    sh.upd.lock().unwrap().clone()
}

#[tauri::command]
pub fn upd_check(sh: Sh) {
    monitor::spawn_update_check(&sh);
}

#[tauri::command]
pub fn upd_download(sh: Sh, url: String, size: u64) {
    monitor::spawn_update_download(&sh, url, size);
}

/// 前端诊断桥（P0 调试期）：JS 错误/里程碑写 guard.log——无 devtools 的冒烟环境靠它定位。
#[tauri::command]
pub fn js_log(sh: Sh, msg: String) {
    sh.log(format!("[js] {msg}"));
}
