/* ClaudeGuard v3 — 飞书通知设置组（内嵌在设置卡里）。
   约定：window.CG_UI.feishu = { mount(host, opts), setState(state), refresh() }。
   命令：feishu_status / feishu_save {cfgJson} / feishu_test / feishu_retry_failed。 */
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
  let HOST = null;
  let mounted = false;
  let timer = 0;
  let busy = false;

  function toast(msg, ok) {
    if (typeof OPTS.onToast === "function") OPTS.onToast(msg, ok);
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

  function build() {
    HOST.innerHTML =
      '<div class="srow"><div class="slabel">启用飞书通知<span class="shint">熔断 / 恢复 / 启动拦截等事件推送到飞书群</span></div>' +
      '<div class="sval"><label class="switch"><input type="checkbox" id="fs-enabled" aria-label="启用飞书通知">' +
      '<span class="switch-track"><span class="switch-knob"></span></span></label></div></div>' +
      '<div class="srow col"><div class="slabel">机器人 Webhook<span class="shint">飞书群自定义机器人的 HTTPS 地址</span></div>' +
      '<input class="in" id="fs-url" spellcheck="false" autocomplete="off" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/…"></div>' +
      '<div class="srow col"><div class="slabel">签名密钥（可选）<span class="shint">机器人开启“加签”时填写</span></div>' +
      '<input class="in" id="fs-secret" type="password" autocomplete="new-password" placeholder="留空则不修改"></div>' +
      '<div class="srow"><div class="slabel">清除已保存的密钥<span class="shint">勾选后保存，旧密钥会被删除</span></div>' +
      '<div class="sval"><label class="switch"><input type="checkbox" id="fs-clear" aria-label="清除已保存的密钥">' +
      '<span class="switch-track"><span class="switch-knob"></span></span></label></div></div>' +
      '<div class="srow"><div class="slabel">保存后立即验证<span class="shint">先保存，再发送一条测试消息</span></div>' +
      '<div class="sval"><button class="btn" type="button" id="fs-test">发送测试</button>' +
      '<button class="btn is-primary" type="button" id="fs-save">保存</button></div></div>' +
      '<div class="srow" id="fs-retry-row"><div class="slabel">补发失败通知<span class="shint">被拒绝或重试耗尽的通知会保留，可手动补发</span></div>' +
      '<div class="sval"><button class="btn" type="button" id="fs-retry">补发</button></div></div>' +
      '<div class="upd-status" id="fs-status" aria-live="polite">尚未启用</div>' +
      '<div class="formhint" id="fs-meta"></div>' +
      '<div class="formhint">' + (CG.platform === 'macos' ? '凭据经 AES-GCM 加密保存，密钥存放于 macOS 登录钥匙串。' : '凭据由 Windows 当前账户加密保存。') + '通知随守护器通过直连 HTTPS 发送；断网时会有限次重试。机器人若设置了关键词，请使用 ClaudeGuard。</div>';

    $("fs-save").addEventListener("click", onSave);
    $("fs-test").addEventListener("click", onTest);
    $("fs-retry").addEventListener("click", onRetry);
  }

  function paint(s) {
    if (!s || typeof s !== "object") return;
    const enabled = !!s.enabled;
    const url = $("fs-url");
    const secret = $("fs-secret");
    const clear = $("fs-clear");
    const sw = $("fs-enabled");
    if (sw && sw.checked !== enabled) sw.checked = enabled;
    if (url) {
      url.placeholder = s.hasWebhook
        ? "已保存 Webhook（留空则不修改）"
        : "https://open.feishu.cn/open-apis/bot/v2/hook/…";
      url.disabled = false;
    }
    if (secret) {
      secret.placeholder = s.hasSecret ? "已保存密钥（留空则不修改）" : "可选：机器人加签密钥";
      secret.disabled = false;
    }
    if (clear && !s.hasSecret) clear.checked = false;

    const status = $("fs-status");
    if (status) {
      if (!enabled) {
        status.textContent = s.queued > 0 ? "未启用 · 有 " + s.queued + " 条待发送" : "未启用";
        status.className = "upd-status";
      } else if (s.error) {
        status.textContent = "发送受阻：" + s.error;
        status.className = "upd-status is-bad";
      } else if (s.queued > 0) {
        status.textContent = "已启用 · 待发送 " + s.queued + " 条" + (s.nextRetry ? "，下次重试 " + fmtTime(s.nextRetry) : "");
        status.className = "upd-status is-warn";
      } else {
        status.textContent = "已启用 · 队列空闲" + (s.lastSent ? "，上次发送 " + fmtTime(s.lastSent) : "");
        status.className = "upd-status is-ok";
      }
    }

    const bits = [];
    if (s.imported) bits.push("已从旧版迁移凭据");
    if (s.failed > 0) bits.push("失败保留 " + s.failed + " 条");
    if (s.lastFailure) bits.push("最近失败：" + s.lastFailure);
    if (s.discarded > 0) bits.push("已丢弃 " + s.discarded + " 条");
    if (!s.hasWebhook) bits.push("还没有保存 Webhook 地址");
    const meta = $("fs-meta");
    if (meta) {
      meta.textContent = bits.join(" · ");
      meta.hidden = !bits.length;
    }
    const retryRow = $("fs-retry-row");
    if (retryRow) retryRow.hidden = !(s.failed > 0);
  }

  function payload() {
    const enabled = !!($("fs-enabled") && $("fs-enabled").checked);
    const url = (($("fs-url") && $("fs-url").value) || "").trim();
    const secret = (($("fs-secret") && $("fs-secret").value) || "").trim();
    const clear = !!($("fs-clear") && $("fs-clear").checked);
    if (url && !/^https:\/\//i.test(url)) {
      toast("Webhook 必须是 https:// 开头的地址");
      return null;
    }
    return { enabled: enabled, webhook: url || null, secret: secret || null, clear_secret: clear };
  }

  async function save(silent) {
    const cfg = payload();
    if (!cfg) return null;
    try {
      const s = await invoke(CMD.feishu_save, { cfgJson: JSON.stringify(cfg) });
      paint(s);
      const secret = $("fs-secret");
      if (secret) secret.value = "";
      const clear = $("fs-clear");
      if (clear) clear.checked = false;
      if (!silent) toast("飞书设置已保存", true);
      return s;
    } catch (e) {
      toast((e && e.message) || "保存飞书设置失败");
      return null;
    }
  }

  async function onSave() {
    if (busy) return;
    busy = true;
    try {
      await save(false);
    } finally {
      busy = false;
    }
  }

  async function onTest() {
    if (busy) return;
    busy = true;
    try {
      const ok = await save(true);
      if (!ok) return;
      const s = await invoke(CMD.feishu_test);
      paint(s);
      toast("测试消息已发送", true);
    } catch (e) {
      toast((e && e.message) || "测试消息发送失败");
    } finally {
      busy = false;
    }
  }

  async function onRetry() {
    if (busy) return;
    busy = true;
    try {
      const s = await invoke(CMD.feishu_retry_failed);
      paint(s);
      toast("已开始补发失败通知", true);
    } catch (e) {
      toast((e && e.message) || "补发失败");
    } finally {
      busy = false;
    }
  }

  async function refresh() {
    try {
      paint(await invoke(CMD.feishu_status));
    } catch (e) {
      /* 保持旧值 */
    }
  }

  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(tick, ms);
  }
  async function tick() {
    if (!mounted) return;
    if (!document.hidden) {
      try {
        await refresh();
      } catch (e) {
        /* 下一轮再试 */
      }
    }
    if (mounted) schedule(5000);
  }

  CG.feishu = {
    mount(host, opts) {
      if (mounted) return;
      HOST = host;
      OPTS = opts || {};
      mounted = true;
      build();
      const st = typeof OPTS.getState === "function" ? OPTS.getState() : null;
      if (st && st.feishu) paint(st.feishu);
      schedule(600);
    },
    setState(state) {
      if (state && state.feishu) paint(state.feishu);
    },
    refresh() {
      return refresh();
    },
  };
})();
