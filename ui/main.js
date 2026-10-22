/* ClaudeGuard v3 — 页面编排：状态渲染、折叠卡、首启向导、事件订阅。
   对外公开：window.CG_UI = { openSettings, openDetails, openLog, expand, toast, ... }（幂等）。
   数据契约：guard://state → StateView（camelCase）；get_state / get_config 走 window.CG_IPC。 */
(() => {
  "use strict";

  const root = window;
  const IPC = root.CG_IPC;
  if (!IPC) return;

  const { invoke, EV, CMD } = IPC;

  // 未捕获异常写进 guard.log（后端环形日志），便于 CDP / 日志排查；限次防止刷屏。
  let jsErrCount = 0;
  function reportJsError(msg) {
    if (jsErrCount >= 20) return;
    jsErrCount++;
    try {
      invoke(CMD.js_log, { level: "error", msg: String(msg || "unknown error").slice(0, 500) }).catch(() => {});
    } catch (e) { /* 桥不可用时忽略 */ }
  }
  window.addEventListener("error", (e) => {
    reportJsError((e.message || "script error") + " @" + (e.filename || "") + ":" + (e.lineno || 0));
  });
  window.addEventListener("unhandledrejection", (e) => {
    const r = e && e.reason;
    reportJsError((r && r.message) || String(r || "unhandled rejection"));
  });

  const $ = (id) => document.getElementById(id);
  const esc = (v) =>
    String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
  const icon = (name, size) => {
    const set = root.ICONS || {};
    const svg = set[name] || "";
    return size ? svg.replace('width="20" height="20"', 'width="' + size + '" height="' + size + '"') : svg;
  };

  const REGION_NAMES = {
    US: "美国", JP: "日本", SG: "新加坡", HK: "香港", TW: "台湾", KR: "韩国",
    GB: "英国", UK: "英国", DE: "德国", FR: "法国", CA: "加拿大", AU: "澳大利亚",
    NL: "荷兰", CH: "瑞士", SE: "瑞典", RU: "俄罗斯", IN: "印度", BR: "巴西",
    AE: "阿联酋", TR: "土耳其", TH: "泰国", MY: "马来西亚", VN: "越南", PH: "菲律宾",
    ID: "印尼", IT: "意大利", ES: "西班牙", PL: "波兰", FI: "芬兰", NO: "挪威",
    DK: "丹麦", IE: "爱尔兰", AT: "奥地利", BE: "比利时", PT: "葡萄牙", CN: "中国",
  };
  const CITY_NAMES = {
    tokyo: "东京", osaka: "大阪", "los angeles": "洛杉矶", "san francisco": "旧金山",
    "san jose": "圣何塞", seattle: "西雅图", "new york": "纽约", chicago: "芝加哥",
    dallas: "达拉斯", miami: "迈阿密", singapore: "新加坡", "hong kong": "香港",
    taipei: "台北", seoul: "首尔", london: "伦敦", frankfurt: "法兰克福",
    amsterdam: "阿姆斯特丹", paris: "巴黎", sydney: "悉尼", toronto: "多伦多",
    vancouver: "温哥华", tokyo2: "东京", osaka2: "大阪",
  };
  const STATE_LABEL = { pass: "通过", fail: "不合规", unverified: "未确认", pending: "待检测", checking: "检测中", disabled: "未启用" };
  const CUT_LABEL = { off: "不断网", firewall: "防火墙全局阻断", nics: "禁用物理网卡" };
  const PHASE_LABEL = {
    idle: "待检查", checking: "检查中", downloading: "正在下载", downloading_setup: "正在下载安装包",
    waiting_exit: "等待退出", installing: "正在安装", pending_reboot: "等待重启", done: "已完成",
    up_to_date: "已是最新", error: "出错", disabled: "已关闭", pending: "等待中",
  };

  const S = {
    state: null,
    stable: null,
    cfg: null,
    logs: [],
    manualBusy: false,
    launchBusy: false,
    releaseBusy: false,
    folds: { details: false, settings: false, logs: false },
    settingsMounted: false,
    smokeOpened: false,
    launchErrShown: "",
    wizard: { open: false, step: 0, busy: false },
    detailsKey: "",
  };

  /* ---------- 小工具 ---------- */

  function pad2(n) { return String(n).padStart(2, "0"); }
  function fmtClock(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
  }
  function minutesLeft(ts) {
    if (!ts) return 0;
    return Math.max(0, Math.ceil((ts * 1000 - Date.now()) / 60000));
  }
  function regionText(code) {
    if (!code) return "";
    const c = String(code).toUpperCase();
    return REGION_NAMES[c] || String(code);
  }
  function cityText(city) {
    if (!city) return "";
    return CITY_NAMES[String(city).toLowerCase()] || String(city);
  }
  function listText(arr) {
    return Array.isArray(arr) && arr.length ? arr.join(", ") : "";
  }
  function shortHost(url) {
    if (!url) return "";
    return String(url).replace(/^[a-z]+:\/\//i, "").split("/")[0];
  }
  function targetGeo(t) {
    if (!t) return "";
    if (t.state === "disabled") return "未启用";
    if (t.anchorKind === "reachability") {
      if (t.state === "pass") return "可达 · " + (t.latencyMs || 0) + "ms";
      if (t.state === "fail") return "不可达";
      return "待检测";
    }
    if (t.state === "fail") return "不符合白名单";
    if (t.country) {
      const parts = [regionText(t.country)];
      const city = cityText(t.city);
      if (city) parts.push(city);
      if (t.colo) parts.push(t.colo);
      return parts.join(" · ");
    }
    if (t.state === "checking") return "检测中…";
    if (t.state === "pass") return "已通过";
    if (t.state === "unverified") return "地区未确认";
    if (t.reason) return t.reason;
    return "待检测";
  }
  function targetLat(t) {
    if (!t) return "";
    if (t.state === "disabled") return "未启用";
    if (t.state === "checking") return "…";
    if (t.state === "pending") return "—";
    if (t.latencyMs) return t.latencyMs + " ms";
    if (t.state === "fail") return "校验失败";
    return "—";
  }
  function dotClass(state) {
    if (state === "pass") return "dot";
    if (state === "fail") return "dot fail";
    if (state === "unverified") return "dot unverified";
    if (state === "checking") return "dot checking";
    return "dot idle";
  }
  function phaseText(ph) {
    return PHASE_LABEL[String(ph || "").toLowerCase()] || String(ph || "");
  }

  let toastTimer = 0;
  function toast(msg, ok) {
    const el = $("toast");
    if (!el) return;
    el.textContent = String(msg || "");
    el.className = "toast" + (ok ? " is-ok" : "");
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
  }

  async function call(cmd, args, quiet) {
    try {
      return await invoke(cmd, args || {});
    } catch (e) {
      if (!quiet) toast((e && e.message) || "操作失败");
      return undefined;
    }
  }

  /* ---------- 折叠卡 ---------- */

  const FOLDS = {
    details: { card: "card-details", head: "head-details", body: "body-details", sub: "details-sub" },
    settings: { card: "card-settings", head: "head-settings", body: "body-settings", sub: "settings-sub" },
    logs: { card: "card-logs", head: "head-logs", body: "body-logs", sub: "logs-sub" },
  };

  function setFold(id, open, scroll) {
    const f = FOLDS[id];
    if (!f) return;
    const card = $(f.card);
    const body = $(f.body);
    const head = $(f.head);
    if (!card || !body) return;
    const want = !!open;
    const was = S.folds[id];
    S.folds[id] = want;
    card.classList.toggle("is-open", want);
    body.hidden = !want;
    if (head) head.setAttribute("aria-expanded", want ? "true" : "false");
    if (want && !was) {
      if (id === "settings") mountSettings();
      if (id === "details") renderDetails();
      if (id === "logs") loadLogs();
    }
    if (want && scroll) {
      try { card.scrollIntoView({ block: "nearest", behavior: prefersReduced() ? "auto" : "smooth" }); } catch (e) { /* ignore */ }
    }
  }
  function toggleFold(id) { setFold(id, !S.folds[id], true); }
  function expand(id) {
    if (id === "settings") setFold("settings", true, true);
    else if (id === "log" || id === "logs") setFold("logs", true, true);
    else setFold("details", true, true);
  }
  function prefersReduced() {
    try { return window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { return false; }
  }

  /* ---------- 英雄区 ---------- */

  const RING_STROKE = {
    pass: "#03AA49",
    fail: "#ED6300",
    tripped: "#E4002B",
    checking: "#0071E3",
    idle: "#C7C7CC",
    paused: "#B0B0B6",
  };

  function renderRing(overall) {
    const fg = $("ring-fg");
    const spinner = $("ring-spinner");
    const core = $("hero-core");
    if (!fg || !spinner || !core) return;
    const checking = overall === "checking" || S.manualBusy;
    fg.style.opacity = checking ? "0" : "1";
    fg.setAttribute("stroke", RING_STROKE[overall] || RING_STROKE.idle);
    if (checking) spinner.removeAttribute("hidden");
    else spinner.setAttribute("hidden", "");
    let name = "";
    let size = 44;
    if (checking) name = "";
    else if (overall === "pass") name = "check";
    else if (overall === "tripped") { name = "x"; size = 40; }
    else if (overall === "fail") name = "alert";
    else if (overall === "paused") name = "pause";
    else name = "dash";
    core.innerHTML = name ? icon(name, size) : "";
  }

  function renderHero() {
    const st = S.state;
    const title = $("hero-title");
    const sub = $("hero-sub");
    if (!st || !title || !sub) return;
    const overall = st.overall || "idle";
    renderRing(overall);
    const targets = st.targets || [];
    let t = "守护待命";
    let s = "等待首次检测";
    if (overall === "pass") {
      t = "守护正常";
      s = heroPassText(st, targets);
      if (S.manualBusy) s = "正在重新校验出口 IP…";
    } else if (overall === "checking") {
      t = "正在检查";
      s = "正在校验出口 IP…";
    } else if (overall === "fail") {
      const bad = targets.filter((x) => x.state === "fail" || x.state === "unverified").length;
      t = "校验未通过";
      s = bad + " 个出口不符合白名单";
    } else if (overall === "tripped") {
      t = "已熔断";
      s = (st.tripped && st.tripped.reason) || "出口 IP 不符合白名单";
    } else if (overall === "paused") {
      const left = minutesLeft(st.pausedUntil);
      t = "已暂停";
      s = left > 0 ? "守护暂停中，" + left + " 分钟后自动恢复" : "守护已暂停";
    } else {
      const passed = targets.some((x) => x.state === "pass");
      s = passed ? "等待下一次自动检测" : "等待首次检测";
    }
    title.textContent = t;
    sub.textContent = s;
  }

  function heroPassText(st, targets) {
    const ok = targets.filter((x) => x.state === "pass");
    const primary = ok.find((x) => /claude/i.test(x.name)) || ok[0];
    const head = primary ? primary.name.replace(/\s*出口$/, "") + " 出口校验通过" : "出口校验通过";
    const n = (st.guardedAgents || []).length;
    return n > 0 ? head + " · " + n + " 个应用受守护" : head;
  }

  /* ---------- 目标列表 ---------- */

  function renderTargets() {
    const host = $("targets");
    if (!host) return;
    const st = S.state;
    const targets = (st && st.targets) || [];
    if (!targets.length) {
      host.innerHTML = '<div class="egress-empty">还没有监控目标，可在设置里添加</div>';
      return;
    }
    host.innerHTML = targets
      .map((t) => {
        const ipText = t.ip || "—";
        const ipCls = "ip" + (t.state === "fail" ? " fail" : !t.ip ? " idle" : "");
        const latCls = "lat" + (t.state === "fail" ? " fail" : !t.ip ? " idle" : "");
        return (
          '<div class="row" data-target="' +
          esc(t.id) +
          '">' +
          '<span class="' + dotClass(t.state) + '" aria-hidden="true"></span>' +
          '<div class="body"><div class="name">' + esc(t.name) + '</div><div class="geo">' + esc(targetGeo(t)) + "</div></div>" +
          '<div class="right"><div class="' + ipCls + '">' + esc(ipText) + '</div><div class="' + latCls + '">' + esc(targetLat(t)) + "</div></div>" +
          "</div>"
        );
      })
      .join("");
  }

  /* ---------- 横幅 ---------- */

  function banner(kind, lines, action) {
    const txt = (Array.isArray(lines) ? lines : [lines]).filter(Boolean).map(esc).join("<br>");
    const act = action
      ? '<button class="bact" data-bact="' + esc(action.id) + '" type="button">' + esc(action.label) + "</button>"
      : "";
    return '<div class="banner ' + kind + '" role="status"><div class="btxt">' + txt + "</div>" + act + "</div>";
  }

  function renderBanners() {
    const host = $("banners");
    if (!host) return;
    const st = S.state;
    if (!st) { host.innerHTML = ""; return; }
    const parts = [];
    const overall = st.overall || "idle";
    const trip = st.tripped;
    if (overall === "tripped" && trip) {
      const fails = (st.targets || []).filter((t) => t.state === "fail");
      const failIp = fails.map((t) => t.ip).find(Boolean);
      const line1 = failIp ? "出口 " + failIp + " 不在允许列表" : trip.reason || "出口不符合允许列表";
      const line2 = trip.networkNote || "网络已阻断，修正配置后可解除";
      parts.push(banner("trip", [line1, line2], { id: "release", label: "解除隔离" }));
    } else if (overall === "paused") {
      const left = minutesLeft(st.pausedUntil);
      const text = left > 0 ? "已暂停 " + left + " 分钟，期间不会熔断" : "守护已暂停，可随时恢复";
      parts.push(banner("info", [text], { id: "resume", label: "恢复守护" }));
    } else if (overall === "fail") {
      const bad = (st.targets || []).filter((x) => x.state === "fail").map((x) => x.name);
      parts.push(banner("warn", ["出口校验未通过", (bad.length ? bad.join("、") + " " : "") + "不符合白名单，熔断前可修正"], { id: "details", label: "查看详情" }));
    }
    if (st.launchError && st.launchError !== S.launchErrShown) {
      S.launchErrShown = st.launchError;
      parts.push(banner("warn", ["启动 Claude 失败", st.launchError], { id: "launch-dismiss", label: "知道了" }));
    }
    // CLI 提醒不占首屏横幅位（设计 A：信息量最少），仅写入详情卡与日志。
    host.innerHTML = parts.join("");
    host.querySelectorAll("[data-bact]").forEach((el) => {
      el.addEventListener("click", () => {
        const id = el.getAttribute("data-bact");
        if (id === "release") doRelease();
        else if (id === "resume") doResume();
        else if (id === "details") expand("details");
        else if (id === "launch-dismiss") {
          S.launchErrShown = st.launchError;
          el.closest(".banner").remove();
        }
      });
    });
  }

  /* ---------- CTA ---------- */

  function renderCta() {
    const st = S.state;
    const btn = $("btn-primary");
    const act = $("btn-recheck");
    if (!btn || !act) return;
    const overall = (st && st.overall) || "idle";
    const checking = S.manualBusy || (st && st.checking);
    let label;
    let icons = "";
    let blocked = false;
    let busy = false;
    let actLabel = "";
    let actIcon = "refresh";
    let actRole = "recheck";
    let actDanger = false;
    let actDisabled = false;
    if (overall === "tripped") {
      label = "启动已禁止";
      icons = icon("ban", 16);
      blocked = true;
      actLabel = "解除隔离并恢复网络";
      actRole = "release";
      actDanger = true;
      actDisabled = S.releaseBusy;
    } else if (checking) {
      label = "正在检查…";
      busy = true;
      actLabel = "立即检测";
      actDisabled = true;
    } else if (overall === "pass") {
      label = S.launchBusy ? "正在启动…" : "启动 Claude";
      icons = icon("play", 16);
      busy = S.launchBusy;
      actLabel = "立即检测";
    } else {
      label = "重新检查";
      icons = icon("refresh", 16);
    }
    btn.innerHTML = icons + "<span>" + esc(label) + "</span>";
    btn.disabled = blocked || busy;
    btn.className = "btn-primary" + (blocked ? " is-blocked" : "") + (busy ? " is-busy" : "");
    act.hidden = !actLabel;
    act.innerHTML = actLabel
      ? (S.releaseBusy && actDanger ? icon("rotate", 13) : icon(actIcon, 13)) + "<span>" + esc(actLabel) + "</span>"
      : "";
    act.className = "link-action" + (actDanger ? " is-danger" : "");
    act.disabled = !!actDisabled;
    act.dataset.role = actRole;
  }

  /* ---------- 详情 ---------- */

  function renderDetails() {
    const body = $("body-details");
    const sub = $("details-sub");
    if (!body) return;
    const st = S.state;
    if (!st) {
      body.innerHTML = '<div class="dempty">还没有结果，稍等片刻…</div>';
      if (sub) sub.textContent = "等待首次检测";
      return;
    }
    const targets = st.targets || [];
    const parts = [];
    const trip = st.tripped;
    if (trip) {
      parts.push(
        '<div class="dgroup"><div class="dhead">' + icon("alert", 12) + " 熔断记录</div>" +
          '<div class="dkv"><span class="k">时间</span><span>' + esc(fmtClock(trip.since)) + "</span>" +
          '<span class="k">原因</span><span>' + esc(trip.reason) + "</span></div>" +
          '<div class="dkv"><span class="k">结束进程</span><span>' + esc(String(trip.killed || 0)) + " 个</span>" +
          '<span class="k">防火墙规则</span><span>' + esc(String(trip.firewallRules || 0)) + " 条</span></div>" +
          '<div class="dkv"><span class="k">隔离应用</span><span>' + esc(listText(trip.quarantinedAgents) || "无") + "</span></div>" +
          '<div class="dkv"><span class="k">断网</span><span>' + esc(CUT_LABEL[trip.networkCut] || trip.networkCut || "未断网") +
          (trip.networkNote ? "（" + esc(trip.networkNote) + "）" : "") + "</span></div>" +
          (trip.agents && trip.agents.length ? '<div class="dkv"><span class="k">涉及应用</span><span>' + esc(trip.agents.join("、")) + "</span></div>" : "") +
          "</div>"
      );
    }
    if (targets.length) {
      const rows = targets
        .map((t) => {
          const exp = [];
          if ((t.expectIps || []).length) exp.push("IP " + t.expectIps.join(", "));
          if ((t.expectRegions || []).length) exp.push("地区 " + (t.expectRegions || []).map(regionText).join(", "));
          return (
            '<div class="drow">' +
            '<span class="' + dotClass(t.state) + '" aria-hidden="true"></span>' +
            '<span class="dname">' + esc(t.name) + "</span>" +
            '<span class="dmid">' + esc(STATE_LABEL[t.state] || t.state) +
            (t.reason ? " · " + esc(t.reason) : "") + "</span>" +
            '<span class="dright">' + (t.latencyMs ? "<b>" + esc(String(t.latencyMs)) + "</b> ms" : esc(targetLat(t))) + "</span>" +
            "</div>" +
            '<div class="dkv"><span class="k">锚点</span><span>' + esc(shortHost(t.anchorUrl) || "内置") + "</span>" +
            (exp.length ? '<span class="k">期望</span><span>' + esc(exp.join("；")) + "</span>" : "") +
            (t.failStreak ? '<span class="k">连续失败</span><span>' + esc(String(t.failStreak)) + " 次</span>" : "") +
            "</div>"
          );
        })
        .join("");
      parts.push('<div class="dgroup"><div class="dhead">目标判定</div>' + rows + "</div>");
    }
    const cfg = S.cfg || {};
    const cfgBits = [];
    if (cfg.proxy_port) cfgBits.push("端口 " + cfg.proxy_port);
    if (st.intervalSecs) cfgBits.push("间隔 " + st.intervalSecs + " 秒");
    if (st.tripThreshold) cfgBits.push("连续失败 " + st.tripThreshold + " 次");
    cfgBits.push("断网档位 " + (CUT_LABEL[st.cutMode] || "不断网"));
    parts.push(
      '<div class="dgroup"><div class="dhead">运行参数</div><div class="dkv"><span class="k">配置</span><span>' +
        esc(cfgBits.join(" · ")) +
        "</span></div>" +
        '<div class="dkv"><span class="k">上次检测</span><span>' + esc(st.checkedAt ? fmtClock(st.checkedAt) : "尚未检测") + "</span>" +
        '<span class="k">通知</span><span>' + (st.notifyEnabled ? "已开启" : "已关闭") + "</span>" +
        '<span class="k">管理员</span><span>' + (st.admin ? "是" : "否") + "</span></div></div>"
    );
    const procs = [];
    if ((st.agentsRunning || []).length) procs.push("桌面端：" + st.agentsRunning.map((a) => a.name + "×" + a.count).join("、"));
    if ((st.cliRunning || []).length) procs.push("命令行：" + st.cliRunning.join("、"));
    if (procs.length) {
      parts.push('<div class="dgroup"><div class="dhead">进程</div><div class="dkv"><span>' + esc(procs.join("；")) + "</span></div></div>");
    }
    body.innerHTML = parts.join("");
    if (sub) {
      if (trip) sub.textContent = "熔断记录";
      else if (st.overall === "pass") sub.textContent = "全部通过" + (st.checkedAt ? " · " + fmtClock(st.checkedAt) : "");
      else if (st.overall === "fail") sub.textContent = "有异常";
      else if (st.overall === "checking") sub.textContent = "检查中";
      else sub.textContent = st.checkedAt ? "上次 " + fmtClock(st.checkedAt) : "等待首次检测";
    }
  }

  /* ---------- 日志 ---------- */

  async function loadLogs() {
    const lines = await call(CMD.recent_logs, { limit: 200 }, true);
    if (Array.isArray(lines)) S.logs = lines.slice();
    renderLogs();
  }
  function renderLogs() {
    const host = $("log-lines");
    const sub = $("logs-sub");
    if (!host) return;
    if (!S.logs.length) {
      host.innerHTML = '<div class="log-empty">还没有日志。检查发生时这里会逐行追加。</div>';
    } else {
      host.innerHTML = S.logs.map((l) => '<div class="log-line">' + esc(l) + "</div>").join("");
      host.scrollTop = host.scrollHeight;
    }
    if (sub) sub.textContent = S.logs.length ? "最近 " + S.logs.length + " 条" : "暂无";
  }
  function appendLog(line) {
    if (line == null) return;
    S.logs.push(String(line));
    if (S.logs.length > 400) S.logs.splice(0, S.logs.length - 400);
    if (S.folds.logs) {
      const host = $("log-lines");
      if (host) {
        if (host.querySelector(".log-empty")) host.innerHTML = "";
        const div = document.createElement("div");
        div.className = "log-line";
        div.textContent = String(line);
        host.appendChild(div);
        while (host.childElementCount > 400) host.removeChild(host.firstElementChild);
        host.scrollTop = host.scrollHeight;
      }
      const sub = $("logs-sub");
      if (sub) sub.textContent = "最近 " + S.logs.length + " 条";
    }
  }

  /* ---------- 设置卡 ---------- */

  function mountSettings() {
    if (S.settingsMounted) return;
    const host = $("body-settings");
    const comp = root.CG_UI && root.CG_UI.settings;
    if (!host || !comp) return;
    S.settingsMounted = true;
    comp.mount(host, {
      getState: () => S.state,
      getConfig: () => S.cfg,
      reloadConfig: async () => {
        S.cfg = (await call(CMD.get_config, {}, true)) || S.cfg;
        if (S.state) { renderDetails(); }
        return S.cfg;
      },
      onToast: toast,
      onExpanded: () => setFold("settings", true, false),
      expandCard: expand,
    });
  }

  /* ---------- 状态应用 ---------- */

  function stableView(st) {
    if (!st || typeof st !== "object") return st;
    if (!st.checking) {
      S.stable = st;
      return st;
    }
    // 自动巡检每轮都会短暂 checking；没有手动重检时沿用上一轮的稳定结果，避免整页闪烁。
    if (S.manualBusy || !S.stable) return st;
    return Object.assign({}, st, {
      checking: false,
      overall: S.stable.overall,
      targets: S.stable.targets,
    });
  }

  function applyState(st) {
    if (!st || typeof st !== "object") return;
    const view = stableView(st);
    S.state = view;
    const overall = view.overall || "idle";
    document.body.setAttribute("data-overall", overall);
    renderHero();
    renderTargets();
    renderBanners();
    renderCta();
    renderDetails();
    const ver = $("foot-version");
    if (ver && view.version) ver.textContent = "v" + view.version;
    const comp = root.CG_UI && root.CG_UI.settings;
    if (S.settingsMounted && comp && comp.setState) comp.setState(view);
    if (view.smokeSettings && !S.smokeOpened) {
      S.smokeOpened = true;
      // 自动展开设置卡（联调/截图钩子）
      setTimeout(() => { mountSettings(); setFold("settings", true, false); }, 60);
    }
    maybeWizard();
  }

  async function refreshState() {
    const st = await call(CMD.get_state, {}, true);
    if (st) applyState(st);
    return st;
  }
  async function refreshConfig() {
    S.cfg = (await call(CMD.get_config, {}, true)) || S.cfg;
    return S.cfg;
  }

  /* ---------- 动作 ---------- */

  async function doRecheck() {
    if (S.manualBusy) return;
    S.manualBusy = true;
    renderHero();
    renderCta();
    try {
      await call(CMD.recheck);
      await refreshState();
    } finally {
      S.manualBusy = false;
      S.state = stableView(S.state);
      renderHero();
      renderCta();
    }
  }

  async function doLaunch() {
    if (S.launchBusy) return;
    S.launchBusy = true;
    renderCta();
    const r = await call(CMD.launch);
    if (r === undefined) {
      S.launchErrShown = "";
      await refreshState();
    } else {
      toast("Claude 已启动", true);
    }
    S.launchBusy = false;
    renderCta();
  }

  async function doRelease() {
    if (S.releaseBusy) return;
    S.releaseBusy = true;
    renderCta();
    await call(CMD.release);
    await refreshState();
    S.releaseBusy = false;
    renderCta();
  }

  async function doResume() {
    await call(CMD.resume);
    await refreshState();
  }

  /* ---------- 首启向导 ---------- */

  function wizStep(n) {
    S.wizard.step = Math.max(0, Math.min(2, n));
    document.querySelectorAll("#wizard .wiz-page").forEach((p) => {
      p.classList.toggle("is-on", Number(p.dataset.step) === S.wizard.step);
    });
    document.querySelectorAll("#wiz-dots span").forEach((d, i) => d.classList.toggle("is-on", i === S.wizard.step));
    const prev = $("wiz-prev");
    const next = $("wiz-next");
    const skip = $("wiz-skip");
    if (prev) prev.hidden = S.wizard.step === 0;
    if (next) {
      next.hidden = S.wizard.step === 2;
      next.textContent = S.wizard.step === 0 ? "开始" : "下一步";
    }
    if (skip) skip.hidden = S.wizard.step === 2;
    wizErr("");
  }
  function wizErr(msg) {
    const el = $("wiz-err");
    if (!el) return;
    el.textContent = msg || "";
    el.hidden = !msg;
  }
  function openWizard() {
    const wiz = $("wizard");
    if (!wiz) return;
    S.wizard.open = true;
    wiz.hidden = false;
    document.body.classList.add("wiz-open");
    wizStep(0);
    const cfg = S.cfg || {};
    const port = $("wiz-port");
    if (port && !port.value) port.value = cfg.proxy_port ? String(cfg.proxy_port) : "";
    const ips = $("wiz-ips");
    if (ips && !ips.value) {
      const local = (cfg.targets || []).find((t) => t.id === "local");
      const expect = (local && local.expect_ips) || [];
      if (expect.length) ips.value = expect.join(", ");
    }
  }
  function closeWizard() {
    const wiz = $("wizard");
    if (!wiz) return;
    S.wizard.open = false;
    wiz.hidden = true;
    document.body.classList.remove("wiz-open");
  }
  function maybeWizard() {
    if (!S.cfg) return;
    if (!S.cfg.first_run) return;
    if (S.state && S.state.smokeSettings) return;
    if (S.wizard.open) return;
    openWizard();
  }
  function parseIpList(raw) {
    return String(raw || "")
      .split(/[\s,，;；]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }
  function validPort(v) {
    if (!String(v || "").trim()) return null;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return NaN;
    return n;
  }
  async function finishWizard(install) {
    if (S.wizard.busy) return;
    const portRaw = ($("wiz-port") || {}).value || "";
    const port = validPort(portRaw);
    if (Number.isNaN(port)) { wizErr("代理端口要填 1-65535 之间的数字"); return; }
    const ips = parseIpList(($("wiz-ips") || {}).value || "");
    const region = (($("wiz-region") || {}).value || "").trim().toUpperCase();
    S.wizard.busy = true;
    const buttons = ["wiz-install", "wiz-portable"].map((id) => $(id)).filter(Boolean);
    buttons.forEach((b) => (b.disabled = true));
    try {
      if (install) {
        wizErr("");
        const note = $("wiz-install-note");
        if (note) { note.hidden = false; note.textContent = "正在注册安装…"; }
        const r = await call(CMD.install_app, {}, true);
        if (r === undefined) {
          if (note) { note.hidden = false; note.textContent = "安装没有成功，可以改用便携版。"; }
          wizErr("注册安装失败（可能是调试版或权限不足），可改用便携版。");
          return;
        }
      }
      if (!S.cfg) await refreshConfig();
      const cfg = S.cfg || {};
      const targets = JSON.parse(JSON.stringify(cfg.targets || []));
      const builtins = ["local", "claude", "codex"];
      let touched = false;
      targets.forEach((t) => {
        if (!builtins.includes(t.id)) return;
        touched = true;
        if (ips.length) t.expect_ips = ips.slice();
        if (region) t.expect_regions = [region];
        else if (ips.length) t.expect_regions = [];
      });
      // 两个输入都留空时保持现有白名单不动；否则只在确实填了内容时才整表保存，
      // 避免全新安装（默认目标尚无白名单）直接触发后端的“至少填一项”校验。
      if (touched && (ips.length || region)) {
        const r = await call(CMD.save_targets, { targets }, true);
        if (r === undefined) { wizErr("保存监控目标失败，请检查白名单 IP 格式。"); return; }
      }
      const patch = { first_run: false };
      if (port != null) patch.proxy_port = port;
      const r2 = await call(CMD.update_settings, { patch }, true);
      if (r2 === undefined) { wizErr("保存设置失败，请稍后重试。"); return; }
      closeWizard();
      toast("设置已保存", true);
      await refreshConfig();
      await refreshState();
    } finally {
      S.wizard.busy = false;
      buttons.forEach((b) => (b.disabled = false));
    }
  }

  /* ---------- 事件绑定 ---------- */

  function bind() {
    const min = $("btn-min");
    const close = $("btn-close");
    if (min) min.addEventListener("click", () => IPC.minimize && IPC.minimize());
    if (close) close.addEventListener("click", () => IPC.close && IPC.close());

    Object.keys(FOLDS).forEach((id) => {
      const head = $(FOLDS[id].head);
      if (head) head.addEventListener("click", () => toggleFold(id));
    });
    const linkDetails = $("link-details");
    const linkSettings = $("link-settings");
    const linkLogs = $("link-logs");
    if (linkDetails) linkDetails.addEventListener("click", () => expand("details"));
    if (linkSettings) linkSettings.addEventListener("click", () => expand("settings"));
    if (linkLogs) linkLogs.addEventListener("click", () => expand("logs"));
    const primary = $("btn-primary");
    if (primary) {
      primary.addEventListener("click", () => {
        const st = S.state;
        if (!st || st.overall === "tripped") return;
        if (st.overall === "pass") doLaunch();
        else doRecheck();
      });
    }
    const act = $("btn-recheck");
    if (act) {
      act.addEventListener("click", () => {
        if (act.dataset.role === "release") doRelease();
        else doRecheck();
      });
    }
    // 一键清理 Claude 进程（CTA 下方，与「立即检测」并排）：两段确认，防误触
    const sweep = $("btn-sweep");
    if (sweep) {
      let armed = false;
      let armTimer = 0;
      const sweepLabel = (txt, danger) => {
        sweep.innerHTML = icon(danger ? "stop" : "trash", 13) + "<span>" + esc(txt) + "</span>";
        sweep.classList.toggle("is-danger", !!danger);
      };
      sweepLabel("清理 Claude 进程", false);
      sweep.addEventListener("click", async () => {
        if (sweep.disabled) return;
        if (!armed) {
          armed = true;
          sweepLabel("确认结束全部 Claude 进程？", true);
          clearTimeout(armTimer);
          armTimer = setTimeout(() => { armed = false; sweepLabel("清理 Claude 进程", false); }, 3200);
          return;
        }
        clearTimeout(armTimer);
        armed = false;
        sweep.disabled = true;
        sweepLabel("正在清理…", true);
        try {
          const rep = await invoke(CMD.sweep_claude);
          const n = rep && rep.killed != null ? rep.killed : 0;
          toast(n > 0
            ? "已结束 " + n + " 个 Claude 进程（桌面 " + (rep.desktopKilled || 0) + " / CLI " + (rep.cliKilled || 0) + "）"
            : "未发现 Claude 进程", true);
        } catch (e) {
          toast((e && e.message) || "清理失败");
        } finally {
          sweep.disabled = false;
          sweepLabel("清理 Claude 进程", false);
        }
      });
    }

    const wizNext = $("wiz-next");
    const wizPrev = $("wiz-prev");
    const wizSkip = $("wiz-skip");
    const wizInstall = $("wiz-install");
    const wizPortable = $("wiz-portable");
    if (wizNext) wizNext.addEventListener("click", () => wizStep(S.wizard.step + 1));
    if (wizPrev) wizPrev.addEventListener("click", () => wizStep(S.wizard.step - 1));
    if (wizSkip) wizSkip.addEventListener("click", async () => {
      closeWizard();
      if (S.cfg && S.cfg.first_run) await call(CMD.update_settings, { patch: { first_run: false } }, true);
      await refreshConfig();
    });
    if (wizInstall) wizInstall.addEventListener("click", () => finishWizard(true));
    if (wizPortable) wizPortable.addEventListener("click", () => finishWizard(false));

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && S.wizard.open) {
        closeWizard();
        if (S.cfg && S.cfg.first_run) call(CMD.update_settings, { patch: { first_run: false } }, true);
      }
    });

    document.querySelectorAll(".chev").forEach((el) => { el.innerHTML = icon("chevronDown", 12); });

    if (IPC.listen) {
      IPC.listen(EV.state, (e) => {
        const payload = e && e.payload !== undefined ? e.payload : e;
        if (payload) applyState(payload);
      });
      IPC.listen(EV.log, (e) => {
        const payload = e && e.payload !== undefined ? e.payload : e;
        appendLog(payload);
      });
    }
  }

  /* ---------- 时钟（暂停倒计时） ---------- */

  function tick() {
    const st = S.state;
    if (!st) return;
    if (st.overall === "paused") {
      renderHero();
      renderBanners();
    }
    if (S.folds.logs && !S.folds.details) { /* 日志卡打开时无需额外刷新 */ }
  }

  /* ---------- 启动 ---------- */

  async function init() {
    bind();
    await refreshConfig();
    await refreshState();
    if (!S.state) {
      // 事件未到也没有快照：给一个安全的空态
      const idle = { overall: "idle", targets: [], checking: false, intervalSecs: 0, notifyEnabled: true, cutMode: "off", admin: false, version: "3.1.0", smokeSettings: false, upd: { state: "idle" } };
      S.state = idle;
      applyState(idle);
    }
    if (S.state && S.state.smokeSettings) {
      setTimeout(() => { mountSettings(); setFold("settings", true, false); }, 80);
    }
    maybeWizard();
    setTimeout(() => document.body.setAttribute("data-ready", "1"), 30);
    setInterval(tick, 1000);
    void renderLogs;
  }

  root.CG_UI = {
    expand,
    openSettings: () => expand("settings"),
    openDetails: () => expand("details"),
    openLog: () => expand("logs"),
    toast,
    getState: () => S.state,
    getConfig: () => S.cfg,
    refresh: async () => { await refreshConfig(); await refreshState(); },
    applyState,
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
