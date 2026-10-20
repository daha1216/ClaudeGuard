/* ClaudeGuard v3 — 设置卡。默认收起；展开时拉一次 get_config 并渲染全部设置项。
   约定：window.CG_UI.settings = { mount(host, opts), setState(state), refresh() }。
   配置为 snake_case（Config/Settings）；保存走 update_settings {patch}，监控目标走 save_targets/reset_targets。 */
(() => {
  "use strict";

  const root = window;
  const IPC = root.CG_IPC;
  if (!IPC) return;
  const { invoke, CMD } = IPC;
  const CG = (root.CG_UI = root.CG_UI || {});
  const $ = (id) => document.getElementById(id);
  const ic = (name, size) => {
    const svg = (root.ICONS || {})[name] || "";
    return size ? svg.replace('width="20" height="20"', 'width="' + size + '" height="' + size + '"') : svg;
  };
  const esc = (v) =>
    String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));

  let HOST = null;
  let OPTS = {};
  let CFG = null;
  let TARGETS = [];
  let mounted = false;
  let loading = false;
  let msgtimer = 0;

  const KIND_OPTIONS = [
    ["auto", "自动识别"],
    ["trace", "trace 文本"],
    ["json_ip", "JSON 出口"],
    ["gemini_region", "页面地区标记"],
    ["reachability", "仅可达性"],
  ];

  function splitList(raw) {
    return String(raw || "")
      .split(/[\s,，;；]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }
  function notifyToast(msg, ok) {
    if (typeof OPTS.onToast === "function") OPTS.onToast(msg, ok);
  }
  function switchHtml(id, checked, disabled) {
    return (
      '<label class="switch"><input type="checkbox" id="' + id + '"' + (checked ? " checked" : "") +
      (disabled ? " disabled" : "") + '><span class="switch-track"><span class="switch-knob"></span></span></label>'
    );
  }
  function rowSwitch(id, title, hint, checked, disabled) {
    return (
      '<div class="srow"><div class="slabel">' + esc(title) +
      (hint ? '<span class="shint">' + esc(hint) + "</span>" : "") +
      '</div><div class="sval">' + switchHtml(id, checked, disabled) + "</div></div>"
    );
  }
  function rowInput(id, title, hint, value, unit, attrs) {
    return (
      '<div class="srow"><div class="slabel">' + esc(title) +
      (hint ? '<span class="shint">' + esc(hint) + "</span>" : "") +
      '</div><div class="sval"><input class="in num" id="' + id + '" type="number" ' + (attrs || "") +
      ' value="' + esc(value) + '">' + (unit ? '<span class="unit">' + esc(unit) + "</span>" : "") + "</div></div>"
    );
  }

  /* ---------- 构建静态骨架 ---------- */

  function build() {
    if (!HOST) return;
    const notify = (CFG && CFG.notify) || {};
    HOST.innerHTML =
      '<div class="sgroup">' +
      '<div class="sgroup-title">检测</div>' +
      '<div class="srow"><div class="slabel">代理端口<span class="shint">本机代理软件的端口</span></div><div class="sval"><input class="in num" id="st-port" type="number" min="1" max="65535" step="1"></div></div>' +
      '<div class="srow"><div class="slabel">检查间隔<span class="shint">自动复查的周期</span></div><div class="sval"><input class="in num" id="st-interval" type="number" min="5" max="3600" step="1"><span class="unit">秒</span></div></div>' +
      '<div class="srow"><div class="slabel">立即重新检查<span class="shint">不改配置，马上校验一轮</span></div><div class="sval"><button class="btn" id="st-recheck" type="button">' + ic("refresh", 12) + "重新检查</button></div></div>" +
      "</div>" +

      '<div class="sgroup">' +
      '<div class="sgroup-title">熔断</div>' +
      '<div class="srow col"><div class="slabel">断网档位<span class="shint">判定失败时切断出口的方式</span></div>' +
      '<div class="seg" id="st-cut" role="group" aria-label="断网档位">' +
      '<button type="button" data-mode="off" aria-pressed="false">不断网</button>' +
      '<button type="button" data-mode="firewall" aria-pressed="false">防火墙全局阻断</button>' +
      '<button type="button" data-mode="nics" aria-pressed="false">禁用物理网卡</button>' +
      "</div></div>" +
      rowSwitch("st-kill", "结束守护对象进程", "熔断时结束勾选应用的所有进程", !!(CFG && CFG.kill_on_fail), false) +
      rowSwitch("st-quarantine", "防火墙隔离", "阻断这些应用联网，解除后自动恢复", !!(CFG && CFG.quarantine_on_fail), false) +
      "</div>" +

      '<div class="sgroup">' +
      '<div class="sgroup-title">守护对象</div>' +
      rowSwitch("st-ag-claude", "Claude 桌面版", "Anthropic Claude 桌面端", false, false) +
      rowSwitch("st-ag-chatgpt", "ChatGPT 桌面版", "OpenAI ChatGPT / Codex 桌面端", false, false) +
      rowSwitch("st-ag-antigravity", "反重力桌面版", "Antigravity 桌面端", false, false) +
      "</div>" +

      '<div class="sgroup">' +
      '<div class="sgroup-title">监控目标</div>' +
      '<div class="sgroup-note">每行是一个探测目标。白名单 IP 与地区至少填一项（仅可达性类型除外），地区填两字母代码。</div>' +
      '<div class="tlist" id="st-targets"></div>' +
      '<div class="tactions"><button class="btn" id="st-target-add" type="button">' + ic("plus", 12) + "添加目标</button><span class=\"spacer\"></span>" +
      '<button class="btn is-ghost" id="st-target-reset" type="button">恢复默认</button>' +
      '<button class="btn is-primary" id="st-target-save" type="button">保存监控目标</button></div>' +
      '<div class="formerr" id="st-target-msg" hidden></div>' +
      "</div>" +

      '<div class="sgroup">' +
      '<div class="sgroup-title">通知</div>' +
      rowSwitch("st-notify-on", "启用桌面通知", "关闭后不再弹出任何通知", notify.enabled !== false, false) +
      rowSwitch("st-notify-trip", "熔断通知", "检测到出口不合规并熔断时", notify.trip !== false, false) +
      rowSwitch("st-notify-recover", "恢复通知", "解除隔离、恢复正常时", notify.recover !== false, false) +
      rowSwitch("st-notify-blocked", "启动被拦截", "出口不合规时尝试启动 Claude", notify.launch_blocked !== false, false) +
      rowSwitch("st-notify-warning", "预警通知", "连续失败但尚未熔断时", notify.warning !== false, false) +
      rowSwitch("st-notify-client", "客户端更新", "Claude / Codex 客户端需要更新时", notify.client_update !== false, false) +
      '<div class="srow"><div class="slabel">发送测试通知<span class="shint">确认系统通知能正常弹出</span></div><div class="sval"><button class="btn" id="st-notify-test" type="button">' + ic("bell", 12) + "发送测试</button></div></div>" +
      "</div>" +

      '<div class="sgroup">' +
      '<div class="sgroup-title">通用</div>' +
      rowSwitch("st-autostart", "开机自启", "开机后自动在托盘里默默守护", !!(CFG && CFG.auto_start_with_system), false) +
      rowSwitch("st-close-tray", "关闭窗口时驻留托盘", "关闭按钮只隐藏窗口，守护继续运行", !CFG || CFG.close_to_tray !== false, false) +
      '<div class="srow"><div class="slabel">数据文件夹<span class="shint">配置、日志与更新缓存所在目录</span></div><div class="sval"><button class="btn" id="st-folder" type="button">打开</button></div></div>' +
      '<div class="srow"><div class="slabel">用户指南<span class="shint">在浏览器中查看使用说明</span></div><div class="sval"><button class="btn" id="st-guide" type="button">打开</button></div></div>' +
      "</div>" +

      '<div class="sgroup"><div class="sgroup-title">软件更新</div><div id="upd-group"></div></div>' +
      '<div class="sgroup" id="feishu-group"><div class="sgroup-title">飞书通知</div></div>' +
      '<div class="sgroup"><div class="sgroup-title">Claude 客户端更新</div><div id="claude-update-group"></div></div>' +
      '<div class="sgroup"><div class="sgroup-title">Codex 客户端更新</div><div id="codex-update-group"></div></div>';

    wire();
    fill();
    mountChildren();
  }

  /* ---------- 填值 ---------- */

  function cutMode(cfg) {
    if (!cfg || !cfg.cut_network) return "off";
    return cfg.disable_network_adapters ? "nics" : "firewall";
  }
  function cutPatch(mode) {
    // 后端 Config 只有两个布尔；CutMode 由它派生（cut_mode()）：off / firewall / nics。
    return { cut_network: mode !== "off", disable_network_adapters: mode === "nics" };
  }

  function fill() {
    const cfg = CFG || {};
    const set = (id, v) => { const el = $(id); if (el) el.value = v == null ? "" : String(v); };
    const chk = (id, v) => { const el = $(id); if (el) el.checked = !!v; };
    set("st-port", cfg.proxy_port || "");
    set("st-interval", cfg.check_interval_secs || "");
    chk("st-kill", cfg.kill_on_fail);
    chk("st-quarantine", cfg.quarantine_on_fail);
    const agents = Array.isArray(cfg.guarded_agents) ? cfg.guarded_agents : [];
    chk("st-ag-claude", agents.includes("claude"));
    chk("st-ag-chatgpt", agents.includes("chatgpt"));
    chk("st-ag-antigravity", agents.includes("antigravity"));
    const n = cfg.notify || {};
    chk("st-notify-on", n.enabled !== false);
    chk("st-notify-trip", n.trip !== false);
    chk("st-notify-recover", n.recover !== false);
    chk("st-notify-blocked", n.launch_blocked !== false);
    chk("st-notify-warning", n.warning !== false);
    chk("st-notify-client", n.client_update !== false);
    chk("st-autostart", cfg.auto_start_with_system);
    chk("st-close-tray", cfg.close_to_tray !== false);
    syncCutButtons(cutMode(cfg));
    syncNotifyEnabled(n.enabled !== false);
    TARGETS = JSON.parse(JSON.stringify(Array.isArray(cfg.targets) ? cfg.targets : []));
    renderTargetList();
  }

  function syncCutButtons(mode) {
    const seg = $("st-cut");
    if (!seg) return;
    seg.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.mode === mode ? "true" : "false"));
  }
  function syncNotifyEnabled(on) {
    ["st-notify-trip", "st-notify-recover", "st-notify-blocked", "st-notify-warning", "st-notify-client"].forEach((id) => {
      const el = $(id);
      if (el) el.disabled = !on;
    });
  }

  /* ---------- 监控目标编辑器 ---------- */

  function kindLabel(k) {
    const found = KIND_OPTIONS.find((x) => x[0] === k);
    return found ? found[1] : k;
  }
  function targetItem(t, i) {
    const kind = t.anchor_kind || "auto";
    const opts = KIND_OPTIONS.map(
      ([v, label]) => '<option value="' + v + '"' + (v === kind ? " selected" : "") + ">" + esc(label) + "</option>"
    ).join("");
    return (
      '<div class="titem" data-idx="' + i + '">' +
      '<div class="titem-top">' +
      '<input class="in tname" data-f="name" maxlength="16" value="' + esc(t.name || "") + '" aria-label="目标名称" placeholder="名称">' +
      '<select class="in" data-f="anchor_kind" aria-label="识别类型">' + opts + "</select>" +
      '<label class="switch" title="启用"><input type="checkbox" data-f="enabled"' + (t.enabled !== false ? " checked" : "") + '><span class="switch-track"><span class="switch-knob"></span></span></label>' +
      '<button class="tdel" type="button" data-del="' + i + '" title="删除" aria-label="删除目标"' + (t.builtin ? " disabled" : "") + ">" + ic("trash", 13) + "</button>" +
      "</div>" +
      '<div class="trow2"><input class="in" data-f="anchor_url" value="' + esc(t.anchor_url || "") + '" placeholder="https://…" spellcheck="false" aria-label="锚点 URL"></div>' +
      '<div class="trow3">' +
      '<label class="tfield"><span>白名单 IP（逗号分隔）</span><input class="in" data-f="expect_ips" value="' + esc((t.expect_ips || []).join(", ")) + '" placeholder="204.1.100.98"></label>' +
      '<label class="tfield"><span>出口地区（两字母代码）</span><input class="in" data-f="expect_regions" value="' + esc((t.expect_regions || []).join(", ")) + '" placeholder="US, JP"></label>' +
      "</div>" +
      '<div class="trow3">' +
      '<label class="tfield"><span>超时（秒）</span><input class="in" type="number" min="3" max="60" step="1" data-f="timeout_secs" value="' + esc(t.timeout_secs || 12) + '"></label>' +
      '<span class="tfield"><span>来源</span><span class="tbadge">' + (t.builtin ? "内置" : "自定义") + "</span></span>" +
      "</div>" +
      "</div>"
    );
  }
  function renderTargetList() {
    const host = $("st-targets");
    if (!host) return;
    if (!TARGETS.length) {
      host.innerHTML = '<div class="formhint">还没有监控目标。点“恢复默认”取回四个内置目标。</div>';
      return;
    }
    host.innerHTML = TARGETS.map(targetItem).join("");
  }

  function readTargets() {
    if (!HOST) return TARGETS;
    HOST.querySelectorAll(".titem").forEach((item) => {
      const idx = Number(item.dataset.idx);
      const t = TARGETS[idx];
      if (!t) return;
      item.querySelectorAll("[data-f]").forEach((input) => {
        const f = input.dataset.f;
        if (f === "enabled") t.enabled = !!input.checked;
        else if (f === "anchor_kind") t.anchor_kind = input.value;
        else if (f === "expect_ips" || f === "expect_regions") t[f] = splitList(input.value);
        else if (f === "timeout_secs") t.timeout_secs = Math.max(3, Math.min(60, Number(input.value) || 12));
        else t[f] = String(input.value || "").trim();
      });
    });
    return TARGETS;
  }

  function validateTargets(list) {
    if (!list.length) return "至少要有一个监控目标";
    for (const t of list) {
      if (!t.name) return "目标名称不能为空";
      if (t.name.length > 16) return "目标名称不能超过 16 个字： " + t.name;
      if (!/^https:\/\//i.test(t.anchor_url || "")) return "「" + t.name + "」的探测地址必须以 https:// 开头";
      if (t.anchor_kind !== "reachability" && !(t.expect_ips || []).length && !(t.expect_regions || []).length) {
        return "「" + t.name + "」至少要填一个白名单 IP 或出口地区";
      }
    }
    return "";
  }

  async function reloadConfig() {
    const cfg = await invoke(CMD.get_config);
    CFG = cfg && typeof cfg === "object" ? cfg : {};
    return CFG;
  }

  async function saveTargets() {
    const msg = $("st-target-msg");
    const list = readTargets().map((t) => {
      const out = {
        id: t.id,
        name: t.name || "",
        builtin: !!t.builtin,
        enabled: t.enabled !== false,
        anchor_url: t.anchor_url || "",
        anchor_kind: t.anchor_kind || "auto",
        expect_ips: t.expect_ips || [],
        expect_regions: t.expect_regions || [],
        timeout_secs: t.timeout_secs || 12,
      };
      if (t.bind_agent != null) out.bind_agent = t.bind_agent;
      return out;
    });
    const err = validateTargets(list);
    if (err) {
      if (msg) { msg.textContent = err; msg.hidden = false; msg.className = "formerr"; }
      return;
    }
    if (msg) { msg.hidden = true; msg.textContent = ""; }
    try {
      await invoke(CMD.save_targets, { targets: list });
      await reloadConfig();
      fill();
      notifyToast("监控目标已保存", true);
      if (msg) { msg.textContent = "已保存"; msg.hidden = false; msg.className = "formok"; }
      clearTimeout(msgtimer);
      msgtimer = setTimeout(() => { if (msg) msg.hidden = true; }, 2400);
      if (typeof OPTS.reloadConfig === "function") OPTS.reloadConfig();
    } catch (e) {
      if (msg) { msg.textContent = (e && e.message) || "保存失败"; msg.hidden = false; msg.className = "formerr"; }
    }
  }

  async function resetTargets() {
    const msg = $("st-target-msg");
    if (msg) { msg.hidden = true; msg.textContent = ""; }
    try {
      await invoke(CMD.reset_targets);
      await reloadConfig();
      fill();
      notifyToast("已恢复默认监控目标", true);
      if (typeof OPTS.reloadConfig === "function") OPTS.reloadConfig();
    } catch (e) {
      if (msg) { msg.textContent = (e && e.message) || "恢复默认失败"; msg.hidden = false; msg.className = "formerr"; }
    }
  }

  /* ---------- 保存小工具 ---------- */

  async function patch(p, okMsg) {
    try {
      await invoke(CMD.update_settings, { patch: p });
      await reloadConfig().catch(() => {});
      if (okMsg) notifyToast(okMsg, true);
      if (typeof OPTS.reloadConfig === "function") OPTS.reloadConfig();
    } catch (e) {
      notifyToast((e && e.message) || "保存失败");
      fill();
      return false;
    }
    return true;
  }
  function numValue(el, min, max, fallback) {
    const n = Number(el.value);
    if (!Number.isInteger(n) || n < min || n > max) return null;
    return n;
  }

  /* ---------- 绑定 ---------- */

  function wire() {
    const port = $("st-port");
    const interval = $("st-interval");
    if (port) {
      port.addEventListener("change", async () => {
        const n = numValue(port, 1, 65535);
        if (n == null) { port.value = CFG && CFG.proxy_port ? CFG.proxy_port : ""; notifyToast("端口要填 1-65535"); return; }
        await patch({ proxy_port: n }, "端口已保存");
      });
    }
    if (interval) {
      interval.addEventListener("change", async () => {
        const n = numValue(interval, 5, 3600);
        if (n == null) { interval.value = CFG && CFG.check_interval_secs ? CFG.check_interval_secs : ""; notifyToast("间隔要填 5-3600 秒"); return; }
        await patch({ check_interval_secs: n }, "检查间隔已保存");
      });
    }
    const recheck = $("st-recheck");
    if (recheck) {
      recheck.addEventListener("click", async () => {
        recheck.disabled = true;
        try {
          await invoke(CMD.recheck);
          notifyToast("已开始重新检查", true);
          if (typeof OPTS.onRecheck === "function") OPTS.onRecheck();
        } catch (e) {
          notifyToast((e && e.message) || "重新检查失败");
        } finally {
          setTimeout(() => { recheck.disabled = false; }, 1200);
        }
      });
    }

    const cut = $("st-cut");
    if (cut) {
      cut.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-mode]");
        if (!b) return;
        const mode = b.dataset.mode;
        syncCutButtons(mode);
        patch(cutPatch(mode), "断网档位已保存");
      });
    }

    const kill = $("st-kill");
    if (kill) kill.addEventListener("change", () => patch({ kill_on_fail: !!kill.checked }, "已保存"));
    const quarantine = $("st-quarantine");
    if (quarantine) quarantine.addEventListener("change", () => patch({ quarantine_on_fail: !!quarantine.checked }, "已保存"));

    ["st-ag-claude:claude", "st-ag-chatgpt:chatgpt", "st-ag-antigravity:antigravity"].forEach((pair) => {
      const [id, agent] = pair.split(":");
      const el = $(id);
      if (!el) return;
      el.addEventListener("change", async () => {
        const current = new Set((CFG && CFG.guarded_agents) || []);
        if (el.checked) current.add(agent);
        else current.delete(agent);
        const next = [...current];
        await patch({ guarded_agents: next }, "守护对象已保存");
        if (!next.length) notifyToast("已没有守护对象：检查照常，但不会结束任何进程");
      });
    });

    const add = $("st-target-add");
    if (add) {
      add.addEventListener("click", () => {
        readTargets();
        const n = TARGETS.filter((t) => !t.builtin).length + 1;
        TARGETS.push({
          id: "custom_" + Date.now().toString(36).slice(-6),
          name: "自定义" + n,
          builtin: false,
          enabled: true,
          anchor_url: "https://www.cloudflare.com/cdn-cgi/trace",
          anchor_kind: "auto",
          expect_ips: [],
          expect_regions: [],
          timeout_secs: 12,
        });
        renderTargetList();
        const host = $("st-targets");
        if (host && host.lastElementChild) {
          try { host.lastElementChild.scrollIntoView({ block: "nearest" }); } catch (e) { /* ignore */ }
          const nameInput = host.lastElementChild.querySelector('[data-f="name"]');
          if (nameInput) nameInput.focus();
        }
        const msg = $("st-target-msg");
        if (msg) { msg.hidden = false; msg.className = "formhint"; msg.textContent = "填好名称、地址与白名单后点“保存监控目标”。"; }
      });
    }
    const save = $("st-target-save");
    if (save) save.addEventListener("click", saveTargets);
    const reset = $("st-target-reset");
    if (reset) reset.addEventListener("click", resetTargets);

    const list = $("st-targets");
    if (list) {
      const onEdit = (e) => {
        const input = e.target.closest("[data-f]");
        if (!input) return;
        const item = input.closest(".titem");
        const t = TARGETS[Number(item.dataset.idx)];
        if (!t) return;
        const f = input.dataset.f;
        if (f === "expect_ips" || f === "expect_regions") t[f] = splitList(input.value);
        else if (f === "timeout_secs") t.timeout_secs = Math.max(3, Math.min(60, Number(input.value) || 12));
        else if (f === "enabled") t.enabled = !!input.checked;
        else t[f] = String(input.value || "");
      };
      list.addEventListener("input", onEdit);
      list.addEventListener("change", onEdit);
      list.addEventListener("click", (e) => {
        const del = e.target.closest("[data-del]");
        if (!del || del.disabled) return;
        readTargets();
        const idx = Number(del.dataset.del);
        if (!TARGETS[idx] || TARGETS[idx].builtin) return;
        TARGETS.splice(idx, 1);
        renderTargetList();
      });
    }

    // 通知
    const notifyMap = {
      "st-notify-trip": "trip",
      "st-notify-recover": "recover",
      "st-notify-blocked": "launch_blocked",
      "st-notify-warning": "warning",
      "st-notify-client": "client_update",
    };
    const notifyOn = $("st-notify-on");
    if (notifyOn) {
      notifyOn.addEventListener("change", () => {
        syncNotifyEnabled(notifyOn.checked);
        const base = (CFG && CFG.notify) || {};
        patch({ notify: Object.assign({}, base, { enabled: !!notifyOn.checked }) }, "通知设置已保存");
      });
    }
    Object.keys(notifyMap).forEach((id) => {
      const el = $(id);
      if (!el) return;
      el.addEventListener("change", () => {
        const base = (CFG && CFG.notify) || {};
        patch({ notify: Object.assign({}, base, { [notifyMap[id]]: !!el.checked }) }, "通知设置已保存");
      });
    });
    const testNotify = $("st-notify-test");
    if (testNotify) {
      testNotify.addEventListener("click", async () => {
        testNotify.disabled = true;
        try {
          await invoke(CMD.notify_test, { kind: "trip" });
          notifyToast("测试通知已发送", true);
        } catch (e) {
          notifyToast((e && e.message) || "发送失败");
        } finally {
          setTimeout(() => { testNotify.disabled = false; }, 1200);
        }
      });
    }

    // 开机自启
    const auto = $("st-autostart");
    if (auto) {
      auto.addEventListener("change", async () => {
        const want = !!auto.checked;
        try {
          await invoke(CMD.set_autostart, { on: want });
          await reloadConfig();
          notifyToast(want ? "已开启开机自启" : "已关闭开机自启", true);
        } catch (e) {
          auto.checked = !want;
          notifyToast((e && e.message) || "设置失败");
        }
      });
    }
    // 关闭窗口时驻留托盘
    const closeTray = $("st-close-tray");
    if (closeTray) {
      closeTray.addEventListener("change", async () => {
        const want = !!closeTray.checked;
        await patch({ close_to_tray: want }, want ? "已开启关窗驻留" : "关闭窗口将直接退出守护");
      });
    }
    // 数据文件夹 / 用户指南
    const folderBtn = $("st-folder");
    if (folderBtn) folderBtn.addEventListener("click", () => invoke(CMD.open_data_folder));
    const guideBtn = $("st-guide");
    if (guideBtn) guideBtn.addEventListener("click", () => invoke(CMD.open_guide));
  }

  /* ---------- 子组件（更新 / 飞书） ---------- */

  function childOpts() {
    return {
      getState: () => (typeof OPTS.getState === "function" ? OPTS.getState() : null),
      getConfig: () => CFG,
      onToast: notifyToast,
      reloadConfig: async () => {
        await reloadConfig().catch(() => {});
        if (typeof OPTS.reloadConfig === "function") OPTS.reloadConfig();
        return CFG;
      },
    };
  }
  function mountChildren() {
    const U = CG.updates;
    if (U && U.mount) {
      U.mount(
        { upd: $("upd-group"), claude: $("claude-update-group"), codex: $("codex-update-group") },
        childOpts()
      );
    }
    const F = CG.feishu;
    if (F && F.mount) {
      F.mount($("feishu-group"), childOpts());
    }
  }

  /* ---------- 公开接口 ---------- */

  CG.settings = {
    mount(host, opts) {
      if (mounted) return;
      HOST = host;
      OPTS = opts || {};
      mounted = true;
      HOST.innerHTML = '<div class="formhint">正在读取配置…</div>';
      load();
    },
    setState(state) {
      // 设置表单不随状态刷新重建；只把状态转给更新/飞书小组件。
      const U = CG.updates;
      if (U && U.setState) U.setState(state);
      const F = CG.feishu;
      if (F && F.setState) F.setState(state);
    },
    refresh() {
      if (!mounted) return;
      load();
    },
    isOpen() { return mounted; },
  };

  async function load() {
    if (loading) return;
    loading = true;
    try {
      await reloadConfig();
      build();
    } catch (e) {
      if (HOST) HOST.innerHTML = '<div class="formerr">读取配置失败：' + esc((e && e.message) || "未知错误") + "</div>";
    } finally {
      loading = false;
    }
  }
})();
