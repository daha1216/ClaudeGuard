/* ClaudeGuard v2 前端主逻辑 — 对等依据 docs/PARITY-v2.md（文案/状态机以它为准）
 * IIFE 隔离词法作用域（见 ipc.js 头注：顶层 const 撞名会让整个脚本编译失败）。 */
(() => {
"use strict";

const { invoke, EV, CMD, listen, win } = window.CG_IPC;

/* ===== JS 诊断桥（P0 调试期）：错误与里程碑写入 guard.log ===== */
const jsLog = (m) => {
  try { invoke("js_log", { msg: m }); } catch (_) { /* 诊断自身不许抛 */ }
};
window.addEventListener("error", (e) => {
  jsLog(`error: ${e.message} @${(e.filename || "").split("/").pop()}:${e.lineno}:${e.colno}`);
});
window.addEventListener("unhandledrejection", (e) => {
  jsLog(`rejection: ${e.reason}`);
});

/* ===== 全局状态 ===== */
const S = {
  checking: false,
  last: null,          // CheckOutcome | null
  tripped: null,       // {killed,firewall_rules,quarantined} | null
  admin: true,
  installed: false,
  version: "",
  smokeSettings: false,
  cfg: null,           // Config
  upd: { state: "idle" },
  logs: [],
  notice: null,        // {title, desc} 4 秒自动清
  wizPage: 0,
  wizPort: "",
  wizIp: "",
  openCards: { details: false, settings: false, log: false },
};

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/* ===== 校验（与 v1 Rust 端规则一致） ===== */
const portOk = (s) => /^\d{1,5}$/.test(s.trim()) && +s.trim() >= 1 && +s.trim() <= 65535;
function ipOk(s) {
  const t = s.trim();
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
  if (!m) return false;
  return m.slice(1).every((p) => (/^0\d/.test(p) ? false : +p <= 255));
}
const intOk = (s) => /^\d+$/.test(s.trim());

/* ===== plain_reason（PARITY §7） ===== */
function plainReason(reason) {
  const r = reason || "";
  if (r.includes("系统代理")) return "电脑还没开系统代理：打开代理软件里的「系统代理」开关";
  if (r.includes("端口") || r.includes("握手") || r.includes("CONNECT")) return "连不上代理端口：看看代理软件是不是开着";
  if (r.includes("出口") || r.includes("IP")) return "出口 IP 和约定不一致";
  if (!r) return "没有通过检查";
  return r;
}

/* ===== 启动 ===== */
async function init() {
  const [st, cfg, upd, logs] = await Promise.all([
    invoke(CMD.getState),
    invoke(CMD.getConfig),
    invoke(CMD.updState),
    invoke(CMD.recentLogs),
  ]);
  Object.assign(S, st);
  S.cfg = cfg;
  S.upd = upd;
  S.logs = logs;
  S.wizPort = String(cfg.proxy_port ?? "");
  S.wizIp = cfg.required_ip ?? "";
  if (S.smokeSettings) S.openCards.settings = true;

  listen(EV.status, (e) => {
    Object.assign(S, e.payload);
    render();
  });  listen(EV.log, (e) => {
    S.logs.push(e.payload);
    if (S.logs.length > 200) S.logs.splice(0, S.logs.length - 200);
    renderLog();
  });
  listen(EV.update, (e) => {
    S.upd = e.payload;
    renderSettings();
  });

  wireStatic();
  render();
  playBoot();
  if (S.smokeSettings) {
    // 手风琴展开(280ms)完成后再滚到底，否则内容长高后停在中途
    setTimeout(() => {
      const c = $("content");
      c.scrollTop = c.scrollHeight;
    }, 450);
  }
}

/* ===== 静态事件接线 ===== */
function wireStatic() {
  $("btn-min").onclick = () => win.minimize();
  $("btn-max").onclick = () => win.toggleMaximize();
  $("btn-close").onclick = () => win.close();
  win.onResized(() => {
    win.isMaximized().then((m) => {
      $("btn-max").innerHTML = m ? ICONS.restore : ICONS.maximize;
    });
    updateCompact();
  });

  // 边缘缩放热区（ResizeDirection 枚举是 PascalCase 变体名）
  const EDGE_DIR = { n: "North", s: "South", e: "East", w: "West", ne: "NorthEast", nw: "NorthWest", se: "SouthEast", sw: "SouthWest" };
  document.querySelectorAll(".edge").forEach((el) => {
    el.addEventListener("pointerdown", (ev) => {
      win.startResizeDragging(EDGE_DIR[el.dataset.edge] || "East");
      ev.preventDefault();
    });
  });

  // 折叠卡头（div+role=button：键盘 Enter/Space 等价点击）
  document.querySelectorAll(".card-head[data-toggle]").forEach((head) => {
    head.onclick = () => {
      const key = head.dataset.toggle;
      S.openCards[key] = !S.openCards[key];
      render();
      if (S.openCards[key]) staggerIn(key);
    };
    head.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        head.click();
      }
    };
  });

  // 底栏
  $("link-data-folder").onclick = (e) => {
    e.preventDefault();
    invoke(CMD.openDataFolder);
  };
  $("link-install").onclick = (e) => {
    e.preventDefault();
    doInstall();
  };

  // 向导
  $("wiz0-next").onclick = () => gotoWizard(1);
  $("wiz1-prev").onclick = (e) => {
    e.preventDefault();
    gotoWizard(0);
  };
  $("wiz1-next").onclick = wiz1Continue;
  $("wiz2-prev").onclick = (e) => {
    e.preventDefault();
    gotoWizard(1);
  };
  $("wiz2-install").onclick = async () => {
    await doInstall();
    finishWizard();
  };
  $("wiz2-portable").onclick = () => finishWizard();

  $("cta").onclick = ctaClick;

  updateCompact();
  new ResizeObserver(updateCompact).observe($("content"));

  // 标题栏发丝线：内容滚到标题栏底下才浮现（macOS 风）
  const contentEl = $("content");
  contentEl.addEventListener("scroll", () => {
    $("titlebar").classList.toggle("scrolled", contentEl.scrollTop > 0);
  }, { passive: true });
}

function updateCompact() {
  const h = $("content").clientHeight;
  document.body.classList.toggle("compact", h > 0 && h < 400);
}

/* ===== 渲染总控 ===== */
function render() {
  const wizardMode = !!S.cfg && S.cfg.first_run;
  $("home").classList.toggle("hidden", wizardMode);
  $("wizard").classList.toggle("hidden", !wizardMode);
  // 折叠状态应用（默认全收起；点击头部或冒烟钩子展开）
  const CARD_IDS = { details: "card-details", settings: "card-settings", log: "card-log" };
  for (const k in CARD_IDS) {
    const open = !!S.openCards[k];
    const card = $(CARD_IDS[k]);
    card.classList.toggle("open", open);
    card.querySelector(".card-head").setAttribute("aria-expanded", String(open));
  }
  if (wizardMode) {
    renderWizard();
    return;
  }
  renderHero();
  renderBanners();
  renderCta();
  renderDetails();
  renderSettings();
  renderLog();
  renderFooter();
}

/* ===== hero ===== */
function heroState() {
  if (S.checking) return { ring: "spin", title: "正在检查…", sub: "正在核对代理和出口 IP" };
  if (S.tripped) {
    const reason = S.last && S.last.reason ? S.last.reason : "出口 IP 与约定不一致";
    return { ring: "fail", title: "已暂停 Claude", sub: `${reason} · 切回节点后自动恢复` };
  }
  if (S.last && S.last.passed) {
    const ip = S.last.egress_ip || "-";
    const desc = (S.last.egress_desc || "").slice(0, 18);
    return { ring: "pass", title: "一切正常", sub: `出口 ${ip} ${desc}`.trim() };
  }
  if (S.last) return { ring: "fail", title: "没有通过检查", sub: plainReason(S.last.reason) };
  return { ring: "idle", title: "准备中", sub: "马上开始第一次检查" };
}

let prevRing = ""; // 状态没变就不重画环（自旋动画不重置、对勾不重播）
let firstHero = true; // 首帧交给进场编排，副标题不做淡换

// 签名转场：自旋减速收拢成满环——弧长 30%→100% + 旋转对齐到整圈，对勾延迟 240ms 描画
function settleRing(g, wasSpin) {
  if (!wasSpin || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const t = getComputedStyle(g).transform;
  let th = 0;
  if (t && t !== "none") th = (Math.atan2(new DOMMatrixReadOnly(t).b, new DOMMatrixReadOnly(t).a) * 180) / Math.PI;
  const target = Math.ceil((th + 140) / 360) * 360; // 收在整圈上，动画结束后回落 0° 无跳变
  const ease = "cubic-bezier(0.23,1,0.32,1)";
  g.animate([{ transform: `rotate(${th}deg)` }, { transform: `rotate(${target}deg)` }], { duration: 400, easing: ease });
  g.querySelector(".ring-full").animate([{ strokeDasharray: "30 100" }, { strokeDasharray: "100 0" }], { duration: 400, easing: ease });
  const mark = g.querySelector(".ring-mark");
  if (mark) mark.style.animationDelay = "240ms";
}

function renderHero() {
  const h = heroState();
  const sub = $("hero-sub");
  if (!firstHero && sub.textContent !== h.sub) {
    sub.classList.remove("swap");
    void sub.offsetWidth;
    sub.classList.add("swap");
  }
  firstHero = false;
  $("hero-title").textContent = h.title;
  sub.textContent = h.sub;
  const g = $("ring-dynamic");
  const changed = prevRing !== h.ring;
  if (h.ring === "spin") {
    if (changed) {
      let arcs = "";
      for (let i = 0; i < 3; i++) {
        const a0 = (i * 2 * Math.PI) / 3;
        const a1 = a0 + 1.4;
        const x0 = 60 + 52 * Math.cos(a0), y0 = 60 + 52 * Math.sin(a0);
        const x1 = 60 + 52 * Math.cos(a1), y1 = 60 + 52 * Math.sin(a1);
        arcs += `<path class="spin-arc" d="M${x0.toFixed(1)} ${y0.toFixed(1)} A52 52 0 0 1 ${x1.toFixed(1)} ${y1.toFixed(1)}"/>`;
      }
      g.innerHTML = arcs;
    }
    prevRing = h.ring;
    g.classList.add("spin");
    return;
  }
  g.classList.remove("spin");
  if (!changed) return;
  const wasSpin = prevRing === "spin";
  prevRing = h.ring;
  const draw = ' pathLength="1" class="ring-mark draw-in"'; // 仅状态切换时描画
  if (h.ring === "pass") {
    g.innerHTML = `<circle class="ring-full" pathLength="100" cx="60" cy="60" r="52" stroke="var(--green)"/>
      <circle class="disc" cx="60" cy="60" r="40" fill="var(--green)" fill-opacity="0.09" stroke="none"/>
      <path${draw} d="M44 61 L54 72 L77 48" stroke="var(--green)"/>`;
    settleRing(g, wasSpin);
  } else if (h.ring === "fail") {
    g.innerHTML = `<circle class="ring-full" pathLength="100" cx="60" cy="60" r="52" stroke="var(--red)"/>
      <circle class="disc" cx="60" cy="60" r="40" fill="var(--red)" fill-opacity="0.09" stroke="none"/>
      <path${draw} d="M60 45 L60 67 M49 56 L71 56" stroke="var(--red)"/>`;
    settleRing(g, wasSpin);
  } else {
    g.innerHTML = `<circle class="ring-dot" cx="46" cy="60" r="4.5"/>
      <circle class="ring-dot" cx="60" cy="60" r="4.5"/>
      <circle class="ring-dot" cx="74" cy="60" r="4.5"/>`;
  }
}

// 首屏进场编排：环先落位 → 标题 → 副标题（40ms 步进）；向导完成后回主屏重播
function playBoot() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const home = $("home");
  home.classList.remove("boot");
  void home.offsetWidth;
  home.classList.add("boot");
}

// 展开内容错峰：仅展开瞬间挂 .dealing（前 8 行 30ms 步进），状态重渲染不重播
function staggerIn(key) {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const inner = document.querySelector(`#card-${key} .card-inner`);
  if (!inner) return;
  inner.classList.remove("dealing");
  [...inner.children].slice(0, 8).forEach((el, i) => el.style.setProperty("--row", i));
  void inner.offsetWidth;
  inner.classList.add("dealing");
}

/* ===== 横幅（优先级：notice > 非管理员 > tripped > 网络不明） ===== */
function renderBanners() {
  const z = $("banner-zone");
  let html = "";
  if (S.notice) {
    html += `<div class="banner green"><span class="banner-dot"></span><div>
      <div class="banner-title">${esc(S.notice.title)}</div>
      ${S.notice.desc ? `<div class="banner-desc">${esc(S.notice.desc)}</div>` : ""}</div></div>`;
  } else if (!S.admin) {
    const desc = document.body.classList.contains("compact")
      ? "请关掉本窗口，用桌面的 ClaudeGuard 快捷方式重新打开。"
      : "自动断网要用管理员权限。请关掉这个窗口，用桌面的 ClaudeGuard 快捷方式重新打开。";
    html += `<div class="banner orange"><span class="banner-dot"></span><div>
      <div class="banner-title">需要管理员权限</div><div class="banner-desc">${esc(desc)}</div></div></div>`;
  } else if (S.tripped) {
    html += `<div class="banner red"><span class="banner-dot"></span><div>
      <div class="banner-title">Claude 已被暂停</div>
      <div class="banner-desc">出口 IP 和约定不一致：已结束 Claude 的进程，并断开了它的网络。切回正确节点后会自动恢复。</div></div></div>`;
  } else if (S.last && !S.last.passed && !S.checking && S.last.egress_ip == null) {
    html += `<div class="banner orange"><span class="banner-dot"></span><div>
      <div class="banner-title">暂时没法确认网络</div>
      <div class="banner-desc">刚才的检查没有成功，可能是网络没通。确认代理软件开着，再点重新检查。</div></div></div>`;
  }
  // 内容签名去重：状态事件每几秒重渲一次，内容没变就别重建 DOM（否则横幅入场动画会被重播）
  if (z.dataset.sig !== html) {
    z.dataset.sig = html;
    z.innerHTML = html;
  }
}
function showNotice(title, desc) {
  if (S.noticeTimer) clearTimeout(S.noticeTimer);
  S.notice = { title, desc };
  renderBanners();
  S.noticeTimer = setTimeout(dismissNotice, 4000);
}
function dismissNotice() {
  S.noticeTimer = null;
  const b = document.querySelector("#banner-zone .banner");
  if (b) {
    // 退场淡出后再清（进出同曲线，退场更快）
    b.classList.add("leaving");
    setTimeout(() => {
      S.notice = null;
      renderBanners();
    }, 170);
  } else {
    S.notice = null;
    renderBanners();
  }
}

/* ===== CTA ===== */
function ctaClick() {
  if (S.tripped || !S.last || !S.last.passed || S.checking) {
    invoke(CMD.recheck);
  } else {
    invoke(CMD.launch);
  }
}

function renderCta() {
  const btn = $("cta");
  const sec = $("cta-secondary");
  if (S.tripped) {
    btn.disabled = S.checking;
    btn.textContent = "我已切回节点，重新检查";
  } else if (S.checking || !S.last) {
    btn.disabled = true;
    btn.textContent = "正在检查，稍候…";
  } else if (S.last.passed) {
    btn.disabled = false;
    btn.textContent = "启动 Claude";
  } else {
    btn.disabled = false;
    btn.textContent = "重新检查";
  }
  const lastOk = S.last && S.last.passed && !S.tripped;
  sec.innerHTML = lastOk ? `<button id="cta-recheck" class="btn-outline">重新检查</button>` : "";
  if (lastOk) {
    $("cta-recheck").onclick = () => {
      invoke(CMD.recheck);
    };
  }
}

/* ===== 检查详情卡 ===== */
function renderDetails() {
  const side = $("details-state");
  const body = $("details-body");
  if (!S.last) {
    side.textContent = S.checking ? "检查中" : "还没检查";
    side.className = "card-head-side";
    body.innerHTML = `<div class="details-empty">还没有结果，稍等片刻…</div>`;
    return;
  }
  if (S.last.passed) {
    side.textContent = "全部通过";
    side.className = "card-head-side ok";
  } else {
    side.textContent = "有问题";
    side.className = "card-head-side bad";
  }
  // Rust StepState 枚举序列化为 "Pass"/"Fail"/"Skip"（v1 --check JSON 格式，保持不动），
  // 前端归一成小写再当 CSS class / 比较用。
  const rows = [
    ["代理已开启", S.last.proxy],
    ["代理能连通", S.last.port],
    ["出口 IP 正确", S.last.egress],
  ]
    .map(([name, step]) => {
      const st = String(step.state ?? "").toLowerCase();
      return `<div class="step-row">
        <span class="step-dot ${st}"></span>
        <span class="step-name">${esc(name)}</span>
        <span class="step-text">${esc(st === "skip" ? "未检测" : step.text)}</span>
      </div>`;
    })
    .join("");
  body.innerHTML = `<div class="steps">${rows}</div>`;
}

/* ===== 设置卡 ===== */
function renderSettings() {
  const cfg = S.cfg;
  if (!cfg) return;
  const body = $("settings-body");
  const err = (id, msg) => `<div class="field-error" id="${id}">${esc(msg || "")}</div>`;

  body.innerHTML = `
    <div class="group-title">检测</div>
    ${settingInput("set-port", "代理端口", "代理软件的端口，常见是 7890", String(cfg.proxy_port), "text")}
    <div class="hairline"></div>
    ${settingInput("set-ip", "约定的出口 IP", "只认这个出口，别的都会拦", cfg.required_ip, "text")}
    <div class="hairline"></div>
    ${settingInput("set-interval", "检查间隔", "每隔几秒复查一次（秒）", String(cfg.check_interval_secs), "text")}
    <div class="group-title">发现出口不对时</div>
    ${settingToggle("set-kill", "停掉 Claude", "立刻结束 Claude 的所有进程", cfg.kill_on_fail)}
    ${settingToggle("set-quarantine", "断开它的网络", "用防火墙拦住 Claude 联网，恢复后自动解除", cfg.quarantine_on_fail)}
    <div class="group-title">通用</div>
    ${settingToggle("set-tray", "关窗后驻留托盘", "守护继续在后台运行", cfg.close_to_tray)}
    ${settingToggle("set-autostart", "开机自启", S.installed ? "开机后自动在托盘里默默守护" : "安装之后才能开启", cfg.auto_start_with_system, !S.installed)}
    <div class="group-title">软件更新</div>
    <div id="upd-group"></div>
  `;

  wireSettingInput("set-port", (v) => {
    if (!portOk(v)) return { ok: false, msg: "端口要填 1-65535" };
    return { ok: true, apply: (c) => (c.proxy_port = +v.trim()) };
  });
  wireSettingInput("set-ip", (v) => {
    if (!ipOk(v)) return { ok: false, msg: "要写成 4 段数字，如 203.0.113.10" };
    return { ok: true, apply: (c) => (c.required_ip = v.trim()) };
  });
  wireSettingInput("set-interval", (v) => {
    if (!intOk(v)) return { ok: false, msg: "填数字" };
    const n = +v.trim();
    if (n < 5 || n > 3600) return { ok: false, msg: "范围 5-3600 秒" };
    return { ok: true, apply: (c) => (c.check_interval_secs = n) };
  });
  wireSettingToggle("set-kill", "kill_on_fail");
  wireSettingToggle("set-quarantine", "quarantine_on_fail");
  wireSettingToggle("set-tray", "close_to_tray");
  wireAutostart();
  renderUpdateGroup();
}

function settingInput(id, title, desc, value) {
  return `<div class="setting-row">
    <div class="setting-label"><div class="st-title">${esc(title)}</div><div class="st-desc">${esc(desc)}</div></div>
    <div class="setting-control">
      <input id="${id}" class="text-input" type="text" value="${esc(value)}">
      <div class="field-error" id="${id}-err"></div>
    </div>
  </div>`;
}

function settingToggle(id, title, desc, on, disabled = false) {
  return `<div class="setting-row">
    <div class="setting-label"><div class="st-title">${esc(title)}</div><div class="st-desc">${esc(desc)}</div></div>
    <div class="setting-control">
      <button id="${id}" class="toggle ${on ? "on" : ""}" ${disabled ? "disabled" : ""}><span class="knob"></span></button>
    </div>
  </div>`;
}

/* 失焦/回车校验写回（v1 同款） */
function wireSettingInput(id, validate) {
  const input = $(id);
  const errEl = $(id + "-err");
  const commit = async () => {
    const v = input.value;
    const r = validate(v);
    if (!r.ok) {
      input.classList.add("invalid");
      errEl.textContent = r.msg;
      return;
    }
    input.classList.remove("invalid");
    errEl.textContent = "";
    const old = JSON.stringify(S.cfg);
    r.apply(S.cfg);
    if (JSON.stringify(S.cfg) !== old) {
      await invoke(CMD.setConfig, { cfg: S.cfg });
      showNotice("完成", "已保存");
    }
  };
  input.addEventListener("blur", commit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      input.blur();
    }
  });
}

function wireSettingToggle(id, field) {
  $(id).onclick = async () => {
    S.cfg[field] = !S.cfg[field];
    $(id).classList.toggle("on", S.cfg[field]);
    await invoke(CMD.setConfig, { cfg: S.cfg });
    showNotice("完成", "已保存");
  };
}

function wireAutostart() {
  const btn = $("set-autostart");
  btn.onclick = async () => {
    const enabled = !S.cfg.auto_start_with_system;
    const ok = await invoke(CMD.setAutostart, { enabled });
    S.cfg.auto_start_with_system = enabled;
    btn.classList.toggle("on", enabled);
    showNotice("完成", "已保存");
  };
}

/* 软件更新组（UpdState 状态机文案 = PARITY §2） */
function renderUpdateGroup() {
  const el = $("upd-group");
  if (!el) return;
  const u = S.upd;
  let row = "";
  if (u.state === "idle") {
    row = settingRow("从 GitHub 看看有没有新版本", `<a href="#" id="upd-check" class="inline-link">检查更新</a>`);
  } else if (u.state === "up_to_date") {
    row = settingRow("已经是最新版本了", `<a href="#" id="upd-check" class="inline-link">检查更新</a>`);
  } else if (u.state === "checking") {
    row = settingRow("正在向 GitHub 查询", `<span style="font-size:13px;color:var(--txt2)">正在检查…</span>`);
  } else if (u.state === "available") {
    row = settingRow("有新版本，下载完会自动重启", `<a href="#" id="upd-download" class="inline-link">下载 v${esc(u.ver)} 并更新</a>`);
  } else if (u.state === "downloading") {
    const pct = u.total > 0 ? Math.floor((u.done / u.total) * 100) : 0;
    row = settingRow("正在下载新版本", `<div class="upd-row"><span class="upd-pct">${pct}%</span>
      <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div></div>`);
  } else if (u.state === "restarting") {
    row = settingRow("下载完成，马上重启", `<span style="font-size:13px;color:var(--txt2)">即将重启…</span>`);
  } else if (u.state === "failed") {
    row = settingRow("上次没成功，可以再试", `<a href="#" id="upd-check" class="inline-link">重试</a>`);
    row += `<div class="field-error" style="text-align:left">${esc(u.msg)}</div>`;
  }
  el.innerHTML = row;
  const c = $("upd-check");
  if (c) c.onclick = (e) => { e.preventDefault(); invoke(CMD.updCheck); };
  const d = $("upd-download");
  if (d) d.onclick = (e) => {
    e.preventDefault();
    invoke(CMD.updDownload, { url: u.url, size: u.size });
  };
}

function settingRow(title, control) {
  return `<div class="setting-row">
    <div class="setting-label"><div class="st-title" style="font-size:13px;color:var(--txt2)">${esc(title)}</div></div>
    <div class="setting-control">${control}</div>
  </div>`;
}

/* ===== 运行日志卡 ===== */
function renderLog() {
  const el = $("log-body");
  if (!el) return;
  // 空状态：引导语而不是空白
  if (!S.logs.length) {
    if (el.dataset.sig !== "empty") {
      el.dataset.sig = "empty";
      el.innerHTML = `<div class="log-empty">还没有日志，检查开始后这里会显示记录</div>`;
    }
    return;
  }
  const html = `<div id="log-scroll">${S.logs.slice(-30).map(renderLogLine).join("")}</div>`;
  if (el.dataset.sig === html) return;
  el.dataset.sig = html;
  // 用户没往上翻时像 tail -f 一样钉在底部；翻了就别拽
  const prev = $("log-scroll");
  const stick = !prev || prev.scrollHeight - prev.scrollTop - prev.clientHeight < 30;
  el.innerHTML = html;
  if (stick) {
    const s = $("log-scroll");
    s.scrollTop = s.scrollHeight;
  }
}

/* 时间戳弱化 + 结果关键词着色（都在 esc 之后做，不引入注入面） */
function renderLogLine(l) {
  let s = esc(l);
  const m = /^(\d{1,2}:\d{2}:\d{2})\s/.exec(s);
  let ts = "";
  if (m) {
    ts = `<span class="log-ts">${m[1]}</span>`;
    s = s.slice(m[0].length);
  }
  s = s
    .replace(/(passed=true|全部通过|已恢复|恢复守护|解除)/g, '<span class="log-ok">$1</span>')
    .replace(/(passed=false|失败|错误|暂停|拦截|隔离|不一致)/g, '<span class="log-err">$1</span>');
  return `<div>${ts}${s}</div>`;
}

/* ===== 底栏 ===== */
function renderFooter() {
  $("footer-version").textContent = `ClaudeGuard v${S.version}`;
  $("link-install").classList.toggle("hidden", S.installed);
  $("foot-sep-install").classList.toggle("hidden", S.installed);
}

async function doInstall() {
  try {
    await invoke(CMD.installApp);
    S.installed = true;
    showNotice("完成", "安装完成，桌面已建快捷方式");
  } catch (e) {
    showNotice("完成", `安装失败：${e}`);
  }
  renderFooter();
}

/* ===== 向导 ===== */
function gotoWizard(page) {
  const dir = page > S.wizPage ? "next" : "prev";
  const from = S.wizPage;
  S.wizPage = page;
  renderWizard();
  if (from !== page) {
    const el = $(`wiz-${page}`);
    if (el) {
      el.classList.remove("enter-next", "enter-prev");
      void el.offsetWidth; // 强制 reflow 让入场动画可重播
      el.classList.add(`enter-${dir}`);
    }
  }
}

function renderWizard() {
  for (let i = 0; i < 3; i++) {
    const el = $(`wiz-${i}`);
    if (el) el.classList.toggle("hidden", S.wizPage !== i);
  }
  const dots = $("wiz-dots");
  dots.innerHTML = [0, 1, 2].map((i) => `<span class="${i === S.wizPage ? "cur" : ""}"></span>`).join("");
  if (S.wizPage === 1) {
    const port = $("wiz-port"), ip = $("wiz-ip");
    if (!port.value) port.value = S.wizPort;
    if (!ip.value) ip.value = S.wizIp;
    port.oninput = ip.oninput = wiz1Validate;
    port.onkeydown = ip.onkeydown = (e) => { if (e.key === "Enter") wiz1Continue(); };
  }
}

function wiz1Validate() {
  const port = $("wiz-port").value, ip = $("wiz-ip").value;
  const okP = portOk(port), okI = ipOk(ip);
  const errEl = $("wiz1-error");
  if (!okP) errEl.textContent = "端口需为 1-65535 的数字";
  else if (!okI) errEl.textContent = "要写成 4 段数字，如 203.0.113.10";
  else errEl.textContent = "";
  $("wiz-port").classList.toggle("invalid", !okP);
  $("wiz-ip").classList.toggle("invalid", !okI);
  $("wiz1-next").disabled = !(okP && okI);
  return okP && okI;
}

async function wiz1Continue() {
  if (!wiz1Validate()) return;
  S.wizPort = $("wiz-port").value.trim();
  S.wizIp = $("wiz-ip").value.trim();
  // v2 修复（PARITY §0-1）：向导页 1 的端口/IP 即时落盘，不再等到主屏设置卡。
  S.cfg.proxy_port = +S.wizPort;
  S.cfg.required_ip = S.wizIp;
  await invoke(CMD.setConfig, { cfg: S.cfg });
  gotoWizard(2);
}

async function finishWizard() {
  S.cfg.first_run = false;
  await invoke(CMD.setConfig, { cfg: S.cfg });
  render();
  playBoot();
}

/* ===== 入口 ===== */
window.addEventListener("DOMContentLoaded", () => {
  $("btn-min").innerHTML = ICONS.minimize;
  $("btn-max").innerHTML = ICONS.maximize;
  $("btn-close").innerHTML = ICONS.close;
  document.querySelectorAll(".chevron").forEach((c) => (c.innerHTML = ICONS.chevron));
  document.querySelectorAll(".wiz-icon").forEach((el) => (el.innerHTML = ICONS[el.dataset.icon] || ""));
  init().catch((e) => {
    document.body.innerHTML = `<div style="padding:24px;color:#E4002B;font-size:13px">加载失败：${esc(String(e))}</div>`;
  });
});
})();
