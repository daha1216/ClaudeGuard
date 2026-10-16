(() => {
  'use strict';
  if (!window.CG_IPC) return;
  const {invoke} = window.CG_IPC;
  let root;
  let editing = false;
  const el = id => root.querySelector(`#${id}`);
  const phases = {idle:'尚未检查',checking:'正在检查和验证',available:'发现新版本，自动更新未执行',
    current:'已是最新版本',downloading:'正在下载官方更新包',verifying:'正在验证官方签名和应用身份',waiting:'更新已准备，等待 Claude 和 Claude Code 退出',
    installing:'正在原位升级，请稍候',deferred:'新版尚未生效，正在核对 Windows 注册结果。',
    pending_stalled:'Windows 长时间未完成新版注册。可点击“完成已下载更新”，安排一次安装尝试。',
    restart_required:'更新尚未完成，Windows 存在待重启状态。请保存工作并重启整台电脑；可先点击“完成已下载更新”安排重启后处理。',
    resume_restart:'已安排重启后完成更新。请保存工作并重启整台电脑；守护器启动后会先核对结果，必要时尝试一次原位更新。',
    resume_waiting:'已安排完成更新。等待 Claude 和 Claude Code 退出、守护检查通过后尝试一次；失败会停止并通知。',
    updated:'更新完成',failed:'更新已停止，请检查错误后重试'};
  function paint(s) {
    if (!s) return;
    const busy = ['checking','downloading','verifying','installing'].includes(s.phase);
    el('cu-enabled').checked = s.enabled;
    el('cu-enabled').disabled = busy;
    el('cu-check').disabled = busy;
    el('cu-finish-row').style.display = s.pending_version ? 'flex' : 'none';
    el('cu-finish').disabled = busy || !!s.resume_pending;
    el('cu-finish').textContent = s.resume_pending ? '已安排完成更新' : '完成已下载更新';
    el('cu-check').textContent = s.pending_version ? '核对 Claude 更新结果' : '检查 Claude 更新';
    const time = s.last_check ? new Date(s.last_check*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'}) : '暂无';
    const next = !s.enabled ? '自动检查已关闭' : s.next_check ? new Date(s.next_check*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'}) : s.phase==='failed' ? '需要手动处理' : '先处理当前更新';
    const updated = s.last_updated ? `\n最近确认更新：${new Date(s.last_updated*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})}` : '';
    el('cu-versions').textContent = `当前版本：${s.installed_version || '待检查'}\n可用版本：${s.latest_version || '待检查'}\n最近检查：${time}\n下次自动检查：${next}${updated}`;
    const progress = s.phase === 'downloading' && s.total ? `（${Math.floor(s.downloaded/s.total*100)}%）` : '';
    const queued = s.pending_version ? `\n待生效版本：${s.pending_version}。关闭自动更新会取消守护器安排的安装尝试；Windows 已接收的更新仍需核对结果。` : '';
    el('cu-status').textContent = `${phases[s.phase] || phases.idle}${progress}${s.wait_reason ? '\n'+s.wait_reason : ''}${queued}${s.error ? '\n'+s.error : ''}`;
  }
  async function refresh() {
    if (!editing) paint(await invoke('claude_update_status'));
  }
  function mount(host) {
    if (!root) {
      root = document.createElement('div');
      root.className = 'feishu-settings';
      root.innerHTML = `
        <label class="fs-check"><input id="cu-enabled" type="checkbox"> 自动更新电脑上的 Claude</label>
        <p class="st-desc">每周自动检查一次；点击下方按钮可立即检查。下载完成后，等待 Claude 和 Claude Code 退出再更新，不打断正在进行的工作。</p>
        <div id="cu-versions" class="st-desc fs-status"></div>
        <div class="fs-actions"><button id="cu-check" class="btn btn-outline">检查 Claude 更新</button></div>
        <div id="cu-finish-row" class="fs-actions" style="display:none"><button id="cu-finish" class="btn btn-outline">完成已下载更新</button></div>
        <div id="cu-status" class="fs-message" role="status" style="white-space:pre-wrap;overflow-wrap:anywhere">正在读取…</div>
        <p class="st-desc">仅原位升级，保留登录数据；不卸载、不重置。官方要求重新登录或会话过期时仍可能需要登录。失败会停止并通过飞书通知。</p>
        <p class="st-desc">安装包保存在守护器目录的 ClaudeUpdates 文件夹；Claude 沿用原系统安装位置。此处更新的是 Claude 桌面客户端。</p>`;
      el('cu-enabled').onchange = async () => {
        editing = true;
        try { paint(await invoke('claude_update_configure',{enabled:el('cu-enabled').checked})); }
        catch(e) { el('cu-status').textContent=String(e); }
        finally { editing=false; }
      };
      el('cu-check').onclick = async () => {
        try { await invoke('claude_update_check'); await refresh(); }
        catch(e) { el('cu-status').textContent=String(e); }
      };
      el('cu-finish').onclick = async () => {
        el('cu-finish').disabled = true;
        try { await invoke('claude_update_check',{finish:true}); await refresh(); }
        catch(e) { el('cu-status').textContent=String(e); el('cu-finish').disabled=false; }
      };
      refresh().catch(e=>el('cu-status').textContent=String(e));
      setInterval(()=>{if(root.isConnected)refresh().catch(()=>{});},1500);
    }
    host.appendChild(root);
  }
  window.CG_CLAUDE_UPDATES={mount};
})();
