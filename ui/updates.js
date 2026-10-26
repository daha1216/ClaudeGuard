/* ClaudeGuard v3 — 软件更新 / Claude 客户端更新 / Codex 客户端更新 三组设置项。
   约定：window.CG_UI.updates = { mount(hosts, opts), setState(state) }。
   hosts = { upd, claude, codex } 三个容器元素。 */
(() => {
  "use strict";

  const root = window;
  const IPC = root.CG_IPC;
  if (!IPC) return;
  const { invoke, CMD } = IPC;
  const CG = (root.CG_UI = root.CG_UI || {});
  const $ = (id) => document.getElementById(id);
  const esc = (v) =>
    String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));

  let OPTS = {};
  let HOSTS = null;
  let mounted = false;
  let timer = 0;
  let busy = false;

  const BUSY_PHASES = new Set(["checking", "downloading", "verifying", "installing"]);

  const PHASE_TEXT = {
    unsupported: "macOS 自动更新尚未实现",
    idle: "尚未检查",
    checking: "正在检查和验证…",
    available: "发现新版本，自动更新尚未执行",
    current: "已是最新版本",
    downloading: "正在下载官方更新包…",
    verifying: "正在验证官方签名和应用身份…",
    waiting: "更新已准备，等待应用退出后安装",
    installing: "正在原位升级，请稍候…",
    deferred: "新版尚未生效，正在核对 Windows 注册结果…",
    pending_stalled: "Windows 长时间未完成升级，可稍后重试",
    restart_required: "更新尚未完成，需要重启应用",
    resume_restart: "已安排重启后完成更新",
    resume_waiting: "已安排完成更新，等待应用退出",
    updated: "更新完成",
    failed: "更新已停止，请检查错误后重试",
  };

  function fmtBytes(n) {
    const v = Number(n) || 0;
    if (v <= 0) return "";
    if (v < 1024 * 1024) return (v / 1024).toFixed(0) + " KB";
    if (v < 1024 * 1024 * 1024) return (v / 1024 / 1024).toFixed(1) + " MB";
    return (v / 1024 / 1024 / 1024).toFixed(2) + " GB";
  }
  function fmtTime(sec) {
    if (!sec) return "";
    try {
      return new Date(sec * 1000).toLocaleString("zh-CN", {
        timeZone: "Asia/Shanghai",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch (e) {
      return "";
    }
  }
  function toast(msg, ok) {
    if (typeof OPTS.onToast === "function") OPTS.onToast(msg, ok);
  }
  function setProgress(el, bar, done, total) {
    if (!el || !bar) return;
    const pct = total > 0 ? Math.max(0, Math.min(1, done / total)) : 0;
    el.hidden = pct <= 0;
    bar.style.transform = "scaleX(" + pct.toFixed(3) + ")";
  }
  function setStatus(el, text, tone) {
    if (!el) return;
    el.textContent = text;
    el.className = "upd-status" + (tone ? " is-" + tone : "");
  }

  /* ---------- 自身更新 ---------- */

  function buildUpd(host) {
    host.innerHTML =
      '<div class="srow"><div class="slabel">自动检查更新<span class="shint">每 6 小时后台静默检查，发现新版本弹通知</span></div>' +
      '<div class="sval"><label class="switch"><input type="checkbox" id="st-auto-upd" aria-label="自动检查更新">' +
      '<span class="switch-track"><span class="switch-knob"></span></span></label></div></div>' +
      '<div class="srow"><div class="slabel">当前版本<span class="shint" id="upd-cur"></span></div>' +
      '<div class="sval"><button class="btn" type="button" id="upd-btn">检查更新</button></div></div>' +
      '<div class="srow"><div class="slabel">GitHub 仓库' +
      '<span class="shint">github.com/daha1216/ClaudeGuard · 更新说明与历史版本</span></div>' +
      '<div class="sval"><button class="btn" type="button" id="upd-repo">打开</button></div></div>' +
      '<div class="srow col"><div class="slabel">更新状态</div>' +
      '<div class="upd-status" id="upd-text">尚未检查更新</div>' +
      '<div class="progress" id="upd-progress" hidden><i id="upd-bar"></i></div></div>';
    const btn = $("upd-btn");
    if (btn) btn.addEventListener("click", onUpdAction);
    const repo = $("upd-repo");
    if (repo) {
      repo.addEventListener("click", () => {
        invoke(CMD.open_repo).catch((e) => toast((e && e.message) || "打开失败"));
      });
    }
    const sw = $("st-auto-upd");
    if (sw) {
      invoke(CMD.get_config)
        .then((cfg) => { if (sw) sw.checked = !(cfg && cfg.auto_upd_check === false); })
        .catch(() => {});
      sw.addEventListener("change", async () => {
        try {
          await invoke(CMD.update_settings, { patch: { auto_upd_check: !!sw.checked } });
          toast("已保存", true);
        } catch (e) {
          toast((e && e.message) || "保存失败");
        }
      });
    }
  }

  function updKind(u) {
    return u && typeof u === "object" && typeof u.state === "string" ? u.state : "idle";
  }

  function paintUpd(u, version) {
    const cur = $("upd-cur");
    if (cur && version) cur.textContent = "ClaudeGuard v" + version;
    const text = $("upd-text");
    const btn = $("upd-btn");
    const prog = $("upd-progress");
    const bar = $("upd-bar");
    const kind = updKind(u);
    let tone = "";
    let action = "check";
    let label = "检查更新";
    let disabled = false;
    switch (kind) {
      case "checking":
        setStatus(text, "正在检查更新…");
        label = "检查中…";
        disabled = true;
        action = "";
        break;
      case "up_to_date":
        setStatus(text, "已是最新版本", "ok");
        label = "重新检查";
        break;
      case "available":
        setStatus(text, "发现新版本 v" + esc(u.ver || "") + (u.size ? " · " + fmtBytes(u.size) : ""), "warn");
        label = "下载更新";
        action = "download";
        break;
      case "downloading":
        setStatus(text, "正在下载更新 " + (u.total ? Math.round((u.done / u.total) * 100) + "%" : "…"));
        label = "下载中…";
        disabled = true;
        action = "";
        break;
      case "restarting":
        setStatus(text, "正在重启以完成更新…");
        label = "重启中…";
        disabled = true;
        action = "";
        break;
      case "failed":
        setStatus(text, (u.msg && String(u.msg)) || "更新失败", "bad");
        tone = "bad";
        label = "重新检查";
        break;
      default:
        setStatus(text, "尚未检查更新");
        break;
    }
    if (prog && bar) {
      if (kind === "downloading") setProgress(prog, bar, u.done || 0, u.total || 0);
      else setProgress(prog, bar, 0, 0);
    }
    if (btn) {
      btn.disabled = disabled;
      btn.textContent = label;
      btn.dataset.action = action;
    }
  }

  async function onUpdAction() {
    const btn = $("upd-btn");
    const action = (btn && btn.dataset.action) || "check";
    if (!btn || btn.disabled || busy) return;
    busy = true;
    btn.disabled = true;
    try {
      if (action === "download") {
        await invoke(CMD.upd_download);
        toast("已开始下载更新", true);
      } else {
        await invoke(CMD.upd_check);
        toast("已开始检查更新", true);
      }
    } catch (e) {
      toast((e && e.message) || "操作失败");
    } finally {
      busy = false;
      // 立即回读一次状态
      invoke(CMD.upd_state).then((u) => paintUpd(u, currentVersion())).catch(() => {});
    }
  }
  function currentVersion() {
    const st = stateOf();
    return st && st.version ? st.version : "";
  }

  /* ---------- 客户端更新（Claude / Codex） ---------- */

  function buildClient(host, prefix, name) {
    host.innerHTML =
      '<div class="srow"><div class="slabel">自动安装官方更新<span class="shint">仅在出口全部合规、' + esc(name) + ' 已退出时执行</span></div>' +
      '<div class="sval"><label class="switch"><input type="checkbox" id="' + prefix + '-enabled" aria-label="自动安装' + esc(name) + '更新">' +
      '<span class="switch-track"><span class="switch-knob"></span></span></label></div></div>' +
      '<div class="srow col"><div class="slabel">状态</div>' +
      '<div class="upd-status" id="' + prefix + '-text">尚未检查</div>' +
      '<div class="progress" id="' + prefix + '-progress" hidden><i id="' + prefix + '-bar"></i></div>' +
      '<div class="formhint" id="' + prefix + '-meta"></div></div>' +
      '<div class="srow"><div class="slabel">立即检查<span class="shint">核对官方版本与签名</span></div>' +
      '<div class="sval"><button class="btn" type="button" id="' + prefix + '-check">检查更新</button></div></div>' +
      '<div class="srow" id="' + prefix + '-finish-row"><div class="slabel">完成更新<span class="shint">已下载的更新将在' + esc(name) + '退出后安装</span></div>' +
      '<div class="sval"><button class="btn is-primary" type="button" id="' + prefix + '-finish">完成已下载的更新</button></div></div>';
    const sw = $(prefix + "-enabled");
    if (sw) sw.addEventListener("change", () => onClientToggle(prefix, sw.checked));
    const check = $(prefix + "-check");
    if (check) check.addEventListener("click", () => onClientCheck(prefix, false));
    const finish = $(prefix + "-finish");
    if (finish) finish.addEventListener("click", () => onClientCheck(prefix, true));
  }

  function phaseOf(s) {
    return s && typeof s.phase === "string" && s.phase ? s.phase : "idle";
  }
  function paintClient(prefix, s) {
    if (!s || typeof s !== "object") return;
    const enabled = !!s.enabled;
    const phase = phaseOf(s);
    const text = $(prefix + "-text");
    const meta = $(prefix + "-meta");
    const prog = $(prefix + "-progress");
    const bar = $(prefix + "-bar");
    const finishRow = $(prefix + "-finish-row");
    const sw = $(prefix + "-enabled");
    const check = $(prefix + "-check");
    const busyNow = BUSY_PHASES.has(phase) || phase === "unsupported";

    if (sw && sw.checked !== enabled) sw.checked = enabled;
    if (sw) sw.disabled = busyNow;
    if (check) check.disabled = busyNow;
    if (finishRow) finishRow.hidden = !s.pendingVersion;

    let label = PHASE_TEXT[phase] || phase;
    if (phase === "available" && s.latestVersion) label = "发现新版本 " + s.latestVersion + "，自动更新尚未执行";
    if (phase === "current" && s.latestVersion) label = "已是最新版本 " + (s.installedVersion || s.latestVersion);
    setStatus(text, label, phase === "failed" ? "bad" : phase === "updated" ? "ok" : phase === "available" ? "warn" : "");

    if (phase === "downloading" || phase === "verifying" || phase === "installing") {
      setProgress(prog, bar, s.downloaded || 0, s.total || 0);
    } else {
      setProgress(prog, bar, 0, 0);
    }

    const bits = [];
    if (s.installedVersion) bits.push("已安装 " + s.installedVersion);
    if (s.latestVersion && s.latestVersion !== s.installedVersion) bits.push("最新 " + s.latestVersion);
    if (s.pendingVersion) bits.push("待安装 " + s.pendingVersion);
    if (s.total && phase === "downloading") bits.push(fmtBytes(s.downloaded) + " / " + fmtBytes(s.total));
    if (phase === "failed" && s.error) bits.push(String(s.error));
    else if (s.error && phase !== "failed") bits.push(String(s.error));
    if (s.waitReason) bits.push(String(s.waitReason));
    if (s.lastCheck && !bits.length) bits.push("上次检查 " + fmtTime(s.lastCheck));
    if (meta) {
      meta.textContent = bits.join(" · ");
      meta.hidden = !bits.length;
    }
  }

  async function onClientToggle(prefix, enabled) {
    const cmd = prefix === "cu" ? CMD.claude_update_configure : CMD.codex_update_configure;
    try {
      await invoke(cmd, { enabled: !!enabled });
    } catch (e) {
      toast((e && e.message) || "保存失败");
    }
    refreshOne(prefix);
  }
  async function onClientCheck(prefix, finish) {
    const cmd = prefix === "cu" ? CMD.claude_update_check : CMD.codex_update_check;
    try {
      await invoke(cmd, finish ? { finish: true } : {});
      toast(finish ? "已安排完成更新" : "已开始检查更新", true);
    } catch (e) {
      toast((e && e.message) || "操作失败");
    }
    refreshOne(prefix);
  }
  async function refreshOne(prefix) {
    const cmd = prefix === "cu" ? CMD.claude_update_status : CMD.codex_update_status;
    try {
      const s = await invoke(cmd);
      paintClient(prefix, s);
    } catch (e) {
      /* 状态命令暂不可用时保持旧值 */
    }
  }

  /* ---------- 轮询 ---------- */

  function stateOf() {
    return typeof OPTS.getState === "function" ? OPTS.getState() : null;
  }

  async function refreshAll() {
    const jobs = [];
    if ($("upd-text")) {
      jobs.push(
        invoke(CMD.upd_state)
          .then((u) => paintUpd(u, currentVersion()))
          .catch(() => {})
      );
    }
    if ($("cu-text")) jobs.push(refreshOne("cu"));
    if ($("cx-text")) jobs.push(refreshOne("cx"));
    await Promise.all(jobs);
  }

  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(tick, ms);
  }
  async function tick() {
    if (!mounted) return;
    if (!document.hidden) {
      try {
        await refreshAll();
      } catch (e) {
        /* 忽略，下一轮再试 */
      }
    }
    if (mounted) schedule(2500);
  }

  /* ---------- 公开接口 ---------- */

  CG.updates = {
    mount(hosts, opts) {
      if (mounted) return;
      HOSTS = hosts || {};
      OPTS = opts || {};
      if (HOSTS.upd) buildUpd(HOSTS.upd);
      if (HOSTS.claude) buildClient(HOSTS.claude, "cu", "Claude");
      if (HOSTS.codex) buildClient(HOSTS.codex, "cx", "Codex");
      mounted = true;
      const st = stateOf();
      if (st) this.setState(st);
      schedule(400);
    },
    setState(state) {
      if (!state) return;
      if (state.upd) paintUpd(state.upd, state.version || "");
      else if (state.version) paintUpd({ state: "idle" }, state.version);
      if (state.claudeUpdate) paintClient("cu", state.claudeUpdate);
      if (state.codexUpdate) paintClient("cx", state.codexUpdate);
    },
    refresh() {
      return refreshAll();
    },
  };
})();
