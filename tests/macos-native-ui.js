/* Explicit native WKWebView acceptance script; injected only by --macos-ui-selftest. */
(() => {
  "use strict";
  if (window.__CG_NATIVE_ACCEPTANCE_STARTED) return;
  window.__CG_NATIVE_ACCEPTANCE_STARTED = true;
  const cases = [];
  const check = (condition, name) => {
    if (!condition) throw new Error(name);
    cases.push(name);
  };
  const waitFor = async (predicate, label) => {
    const until = Date.now() + 5000;
    while (Date.now() < until) {
      if (await predicate()) return;
      await new Promise(resolve => setTimeout(resolve, 30));
    }
    throw new Error("Timed out: " + label);
  };
  const emit = result => window.__TAURI__.event.emit("guard://acceptance", result);
  (async () => {
    await waitFor(() => document.readyState === "complete" && window.CG_IPC && window.CG_UI && document.body.dataset.ready === "1", "production UI ready");
    const invoke = window.CG_IPC.invoke;
    const initial = await invoke("get_state");
    check(initial.platform === "macos" && initial.networkIsolationSupported === false, "native_state_and_platform");
    const original = await invoke("get_config");
    check(original.kill_on_fail === false && original.guarded_agents.length === 0 && original.notify.enabled === false && original.auto_upd_check === false, "isolated_safe_configuration");
    check(document.body.dataset.platform === "macos" && document.body.textContent.includes("进程守护模式"), "macos_copy_and_platform_rendered");
    window.CG_UI.openSettings();
    await waitFor(() => document.getElementById("st-interval") && document.getElementById("st-quarantine"), "settings mounted");
    const switches = Array.from(document.querySelectorAll("#st-cut button"));
    check(switches.length === 3 && switches.every(button => button.disabled), "unavailable_network_modes_disabled");
    const quarantine = document.getElementById("st-quarantine");
    check(quarantine.disabled && !quarantine.checked, "unavailable_application_firewall_disabled");
    const updated = await invoke("update_settings", { patch: { check_interval_secs: 17 } });
    check(updated.intervalSecs === 17 && (await invoke("get_config")).check_interval_secs === 17, "real_settings_ipc_roundtrip");
    await window.CG_UI.refresh();
    const interval = document.getElementById("st-interval");
    interval.value = "19";
    interval.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(async () => (await invoke("get_config")).check_interval_secs === 19, "settings change handler");
    check((await invoke("get_state")).intervalSecs === 19, "real_dom_change_persisted_via_ipc");
    await invoke("pause");
    const paused = await invoke("get_state");
    check(paused.pausedUntil > Math.floor(Date.now() / 1000) && paused.overall === "paused", "real_pause_ipc");
    await waitFor(() => document.body.dataset.overall === "paused", "paused event rendered");
    cases.push("native_state_event_reaches_webview");
    await invoke("resume");
    check((await invoke("get_state")).pausedUntil === null, "real_resume_ipc");
    await invoke("release");
    check((await invoke("get_state")).tripped === null, "real_release_ipc");
    const statuses = await Promise.all([invoke("upd_state"), invoke("feishu_status"), invoke("claude_update_status"), invoke("codex_update_status")]);
    check(statuses.every(status => status && typeof status === "object"), "read_only_status_ipc");
    const recent = await invoke("recent_logs", { limit: 50 });
    check(Array.isArray(recent) && !recent.some(line => /ui\[error\]/.test(line)), "no_production_javascript_errors");
    await invoke("open_guide");
    cases.push("local_guide_ipc_invoked");
    await emit({ passed: true, cases, scope: "native WKWebView and production IPC; isolated settings; no workers, probes, process termination, updates, notifications or external messages" });
  })().catch(async error => {
    try { await emit({ passed: false, cases, error: String(error && error.message || error) }); }
    catch (deliveryError) { console.error("acceptance result delivery failed", deliveryError); }
  });
})();
