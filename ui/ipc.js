/* ClaudeGuard v3 — 极薄的 Tauri 桥。固定契约：window.CG_IPC = { invoke, EV, listen }。
   命令名严格对齐 docs/SPEC-v3.md §7 与 src/ipc.rs 的 generate_handler! 列表。 */
(() => {
  "use strict";

  const root = typeof window !== "undefined" ? window : globalThis;
  const T = root.__TAURI__ || {};
  const core = T.core || T.tauri || {};
  const EV = {
    state: "guard://state",
    log: "guard://log"
  };
  const CMD = {
    get_state: "get_state",
    get_config: "get_config",
    update_settings: "update_settings",
    save_targets: "save_targets",
    reset_targets: "reset_targets",
    recheck: "recheck",
    launch: "launch",
    recheck_target: "recheck_target",
    release: "release",
    pause: "pause",
    resume: "resume",
    sweep_claude: "sweep_claude",
    lockdown: "lockdown",
    recent_logs: "recent_logs",
    open_data_folder: "open_data_folder",
    open_guide: "open_guide",
    install_app: "install_app",
    set_autostart: "set_autostart",
    upd_state: "upd_state",
    upd_check: "upd_check",
    upd_download: "upd_download",
    feishu_status: "feishu_status",
    feishu_save: "feishu_save",
    feishu_test: "feishu_test",
    feishu_retry_failed: "feishu_retry_failed",
    claude_update_status: "claude_update_status",
    claude_update_configure: "claude_update_configure",
    claude_update_check: "claude_update_check",
    codex_update_status: "codex_update_status",
    codex_update_configure: "codex_update_configure",
    codex_update_check: "codex_update_check",
    js_log: "js_log",
    notify_test: "notify_test"
  };

  function noBridge() {
    return new Error("Tauri bridge unavailable");
  }

  async function invoke(cmd, args) {
    if (!core.invoke) throw noBridge();
    try {
      return await core.invoke(cmd, args || {});
    } catch (e) {
      if (e instanceof Error) throw e;
      const msg = e && typeof e === "object" ? (e.message || JSON.stringify(e)) : String(e);
      throw new Error(msg || "Command failed");
    }
  }

  let listenWarned = false;
  async function listen(event, handler) {
    try {
      if (T.event && T.event.listen) return await T.event.listen(event, handler);
      if (core.event && core.event.listen) return await core.event.listen(event, handler);
    } catch (e) {
      if (!listenWarned) {
        listenWarned = true;
        console.warn("CG_IPC: event.listen unavailable", e);
      }
    }
    return () => {};
  }

  function currentWindow() {
    try {
      if (T.window && T.window.getCurrentWindow) return T.window.getCurrentWindow();
      if (core.window && core.window.getCurrentWindow) return core.window.getCurrentWindow();
    } catch (e) { /* 无 Tauri 环境（file:// 浏览器预览）时静默降级 */ }
    return null;
  }
  function quiet(p) {
    try { if (p && typeof p.catch === "function") p.catch(() => {}); } catch (e) { /* ignore */ }
  }
  function minimize() {
    const w = currentWindow();
    if (w) { try { quiet(w.minimize()); } catch (e) { /* ignore */ } }
  }
  function close() {
    const w = currentWindow();
    if (w) { try { quiet(w.close()); } catch (e) { /* ignore */ } }
  }

  root.CG_IPC = {
    invoke,
    EV,
    CMD,
    listen,
    minimize,
    close,
    win: { minimize, close }
  };
})();
