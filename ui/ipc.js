/* Tauri IPC 封装 — 命令名与 src/ipc.rs 一一对应。
 * IIFE 隔离词法作用域：classic script 共享全局词法域，顶层 const 会与 main.js 的解构撞名
 * (v2 P0 实测: SyntaxError: Identifier 'invoke' has already been declared，整个 main.js 编译失败)。 */
(() => {
  "use strict";

  if (!window.__TAURI__) {
    document.title = "ClaudeGuard · 请打开桌面程序";
    document.body.innerHTML = `<main style="max-width:520px;margin:12vh auto;padding:32px;font-family:'Microsoft YaHei UI',sans-serif;line-height:1.8">
      <h1 style="font-size:24px">请从桌面打开 ClaudeGuard</h1>
      <p>这里是桌面应用的界面文件预览，单独打开网页无法连接守护器。</p>
      <p>请关闭此页，双击 ClaudeGuard 快捷方式，或从系统托盘打开守护器。</p>
      <p style="color:#707070">飞书通知设置位于内置版的「设置 → 飞书通知」。</p>
    </main>`;
    return;
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
    openGuide: "open_guide",
    installApp: "install_app",
    setAutostart: "set_autostart",
    updState: "upd_state",
    updCheck: "upd_check",
    updDownload: "upd_download",
  };

  const win = winApi.getCurrentWindow();

  window.CG_IPC = { invoke, EV, CMD, listen: event.listen, win };
})();
