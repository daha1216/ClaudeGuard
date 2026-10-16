(() => {
  "use strict";
  if (!window.CG_IPC) return;
  const { invoke } = window.CG_IPC;
  let root = null;
  let status = null;
  let busy = false;
  const byId = (id) => root.querySelector(`#${id}`);

  function paint(value, initialize = false) {
    status = value;
    if (initialize) byId("fs-enabled").checked = value.enabled;
    byId("fs-url").placeholder = value.has_webhook ? "已保存；留空保持原地址" : "填写群机器人 Webhook";
    byId("fs-secret").placeholder = value.has_secret ? "已保存；留空保持原密钥" : "未启用签名校验时留空";
    const sent = value.last_sent ? new Date(value.last_sent * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }) : "暂无";
    const failed = value.failed || 0;
    const retry = value.next_retry ? `\n下次重试：${new Date(value.next_retry*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})}` : '';
    const retained = failed ? `\n保留失败通知：${failed} 条${value.last_failure ? '\n'+value.last_failure : ''}` : '';
    const discarded = value.discarded ? `\n更早的失败记录已超过保存上限：${value.discarded} 条` : '';
    byId("fs-status").textContent = `${value.enabled ? "通知已启用" : "通知未启用"} · 待发送 ${value.queued} 条\n最近成功发送：${sent}${retry}${retained}${discarded}${value.error && value.error!==value.last_failure ? `\n${value.error}` : ""}`;
    byId('fs-retry-row').style.display = failed ? 'flex' : 'none';
    byId('fs-retry').disabled = busy || !value.enabled || value.queued >= 100;
    byId('fs-retry').textContent = `补发失败通知（${failed} 条）`;
    byId("fs-migration").textContent = value.imported ? "已沿用原通知助手的机器人配置，无需重新填写。" : "凭据由 Windows 当前账户加密保存。";
  }

  async function save() {
    const result = await invoke("feishu_save", { settings: {
      enabled: byId("fs-enabled").checked,
      webhook: byId("fs-url").value.trim() || null,
      secret: byId("fs-secret").value.trim() || null,
      clear_secret: byId("fs-clear").checked,
    } });
    byId("fs-url").value = "";
    byId("fs-secret").value = "";
    byId("fs-clear").checked = false;
    paint(result, true);
  }

  async function action(test) {
    if (busy) return;
    busy = true;
    byId("fs-save").disabled = byId("fs-test").disabled = true;
    byId("fs-message").textContent = test ? "正在保存并发送测试通知…" : "正在保存…";
    try {
      await save();
      if (test) paint(await invoke("feishu_test"));
      byId("fs-message").textContent = test ? "测试通知发送成功，请在飞书群中查看。" : "已保存。关闭窗口收进托盘后，守护和通知继续运行。";
    } catch (error) {
      byId("fs-message").textContent = String(error);
    } finally {
      busy = false;
      byId("fs-save").disabled = byId("fs-test").disabled = false;
    }
  }

  function mount(host) {
    if (!root) {
      root = document.createElement("div");
      root.className = "feishu-settings";
      root.innerHTML = `
        <label class="fs-check"><input id="fs-enabled" type="checkbox"> 启用飞书群通知</label>
        <p class="st-desc">异常、熔断和恢复时通知，相同异常不刷屏。</p>
        <label class="fs-label" for="fs-url">群机器人 Webhook</label>
        <input id="fs-url" class="text-input" type="password" autocomplete="off" spellcheck="false">
        <label class="fs-label" for="fs-secret">签名密钥（可选）</label>
        <input id="fs-secret" class="text-input" type="password" autocomplete="new-password" spellcheck="false">
        <label class="fs-check fs-small"><input id="fs-clear" type="checkbox"> 清除已保存的签名密钥</label>
        <p id="fs-migration" class="st-desc"></p>
        <p class="st-desc">机器人若设置关键词，请使用 ClaudeGuard。通知随守护器运行，通过直连 HTTPS 发送。</p>
        <p class="st-desc">断网会有限次重试；被拒绝或重试耗尽的通知保留最近 100 条，可手动补发。更换机器人地址会清空旧待发记录。</p>
        <div class="fs-actions"><button id="fs-save" class="btn btn-outline">保存设置</button><button id="fs-test" class="btn btn-outline">测试通知</button></div>
        <div id="fs-retry-row" class="fs-actions" style="display:none"><button id="fs-retry" class="btn btn-outline">补发失败通知</button></div>
        <div id="fs-message" role="status" class="fs-message"></div>
        <div id="fs-status" class="st-desc fs-status" aria-live="polite">正在读取通知设置…</div>`;
      byId("fs-save").onclick = () => action(false);
      byId("fs-test").onclick = () => action(true);
      byId('fs-retry').onclick = async () => {
        if (busy) return;
        busy = true;
        byId('fs-retry').disabled = true;
        try {
          paint(await invoke('feishu_retry_failed'));
          byId('fs-message').textContent = '失败通知已重新排队，将按顺序发送。同一事件保留原编号；此前回执不确定时可能重复收到。';
        } catch(e) { byId('fs-message').textContent=String(e); }
        finally { busy=false; if(status)paint(status); }
      };
      invoke("feishu_status").then((value) => paint(value, true)).catch((error) => {
        byId("fs-message").textContent = String(error);
      });
      setInterval(() => {
        if (root.isConnected && !busy) invoke("feishu_status").then((value) => paint(value)).catch(() => {});
      }, 5000);
    }
    host.appendChild(root);
  }
  window.CG_FEISHU = { mount };
})();
