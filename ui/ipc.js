/* Tauri IPC 封装 — 命令名与 src/ipc.rs 一一对应。
 * IIFE 隔离词法作用域：classic script 共享全局词法域，顶层 const 会与 main.js 的解构撞名
 * (v2 P0 实测: SyntaxError: Identifier 'invoke' has already been declared，整个 main.js 编译失败)。 */
(() => {
  "use strict";

  if (!window.__TAURI__) {
    throw new Error("__TAURI__ missing (withGlobalTauri?)");
  }

  const core = window.__TAURI__.core;
  const event = window.__TAURI__.event;
  const winApi = window.__TAURI__.window;

  const invoke = (cmd, args) => core.invoke(cmd, args);

  const EV = {
    status: "guard://status",
    log: "guard://log",
    update: "guard://update",
  };

  const CMD = {
    getState: "get_state",
    getConfig: "get_config",
    setConfig: "set_config",
    recheck: "recheck",
    launch: "launch",
    release: "release",
    recentLogs: "recent_logs",
    openDataFolder: "open_data_folder",
    installApp: "install_app",
    setAutostart: "set_autostart",
    updState: "upd_state",
    updCheck: "upd_check",
    updDownload: "upd_download",
  };

  const win = winApi.getCurrentWindow();

  window.CG_IPC = { invoke, EV, CMD, listen: event.listen, win };
})();
