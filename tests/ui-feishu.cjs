const {chromium} = require(process.env.CG_PLAYWRIGHT || 'playwright');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
(async () => {
  const browser = await chromium.launch({channel:'msedge',headless:true});
  const page = await browser.newPage({viewport:{width:420,height:620},deviceScaleFactor:1});
  const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('http://guard.test/**',async route=>{
    const name=new URL(route.request().url()).pathname.slice(1)||'index.html';
    const p=path.join(__dirname,'..','ui',name);
    if(!fs.existsSync(p)){await route.fulfill({status:404,body:''});return;}
    await route.fulfill({path:p,contentType:name.endsWith('.js')?'application/javascript':name.endsWith('.css')?'text/css':'text/html'});
  });
  await page.addInitScript(()=>{
    window.testListeners={};window.testCalls=[];
    window.fsStatus={enabled:true,has_webhook:true,has_secret:true,imported:true,queued:0,last_sent:0,error:''};
    window.cuStatus={enabled:false,phase:'idle',installed_version:'2.31226.0.0',latest_version:'',last_check:0,downloaded:0,total:0,error:''};
    window.cxStatus={enabled:false,phase:'idle',installed_version:'26.928.1915.0',latest_version:'',last_check:0,downloaded:0,total:0,error:''};
    const config={proxy_port:7890,allowed_ips:['203.0.113.10'],egress_region:'',check_interval_secs:15,
      guarded_agents:['claude'],cli_warn:true,kill_on_fail:true,quarantine_on_fail:true,close_to_tray:true,
      auto_start_with_system:true,first_run:false};
    const invoke=async (cmd,args)=>{
      window.testCalls.push({cmd,args});
      if(cmd==='get_state')return {admin:true,installed:true,version:'2.11.0',smokeSettings:true,agentsRunning:[],cliRunning:[],launchError:null};
      if(cmd==='get_config')return config;
      if(cmd==='upd_state')return {state:'idle'};
      if(cmd==='recent_logs')return [];
      if(cmd==='feishu_status')return window.fsStatus;
      if(cmd==='feishu_save'){window.fsStatus.enabled=args.settings.enabled;return window.fsStatus;}
      if(cmd==='feishu_test'){window.fsStatus.last_sent=1700000000;return window.fsStatus;}
      if(cmd==='feishu_retry_failed'){window.fsStatus.queued=window.fsStatus.failed;window.fsStatus.failed=0;return window.fsStatus;}
      if(cmd==='claude_update_status')return window.cuStatus;
      if(cmd==='claude_update_configure'){window.cuStatus.enabled=args.enabled;return window.cuStatus;}
      if(cmd==='claude_update_check'){window.cuStatus.phase='waiting';window.cuStatus.latest_version='2.37337.1';return null;}
      if(cmd==='codex_update_status')return window.cxStatus;
      if(cmd==='codex_update_configure'){window.cxStatus.enabled=args.enabled;return window.cxStatus;}
      if(cmd==='codex_update_check'){window.cxStatus.phase=args?.finish?'resume_restart':'waiting';window.cxStatus.resume_pending=!!args?.finish;window.cxStatus.latest_version='26.1007.9446.0';return null;}
      return null;
    };
    window.__TAURI__={core:{invoke},event:{listen:async(n,f)=>{window.testListeners[n]=f;return ()=>{};}},
      window:{getCurrentWindow:()=>({minimize(){},close(){},toggleMaximize(){},onResized(){},isMaximized:async()=>false,startResizeDragging(){}})}};
  });
  await page.goto('http://guard.test/');
  await page.locator('#fs-migration').filter({hasText:'无需重新填写'}).waitFor();
  await page.evaluate(()=>window.testListeners['guard://status']({payload:{checking:false,manual:false,last:{passed:true,egress_ip:'203.0.113.10',proxy:{state:'pass',text:'ok'},port:{state:'pass',text:'ok'},egress:{state:'pass',text:'ok'}},launchError:'Windows 安装未完成（Servicing）。请保存工作并重启 Windows。<test>'}}));
  await page.locator('#launch-error').filter({hasText:'Servicing'}).waitFor();
  assert.strictEqual(await page.locator('#hero-title').innerText(),'网络检查通过');
  assert.strictEqual(await page.locator('#launch-error test').count(),0,'launch diagnostics must be escaped');
  await page.evaluate(()=>window.testListeners['guard://status']({payload:{checking:true,manual:false}}));
  assert(await page.locator('#launch-error').isVisible(),'background network checks must retain launch error');
  await page.evaluate(()=>window.testListeners['guard://status']({payload:{checking:false,manual:false}}));
  assert.strictEqual(await page.locator('#hero-title').innerText(),'网络检查通过');
  assert(await page.locator('#launch-error').isVisible(),'successful background checks must retain launch error');
  await page.evaluate(()=>window.testListeners['guard://status']({payload:{checking:false,manual:false,launchError:null}}));
  assert.strictEqual(await page.locator('#launch-error').count(),0);
  await page.locator('#fs-url').fill('https://open.feishu.cn/open-apis/bot/v2/hook/test-only');
  await page.evaluate(()=>window.testListeners['guard://status']({payload:{checking:true,manual:false}}));
  assert((await page.locator('#fs-url').inputValue()).endsWith('test-only'),'periodic updates must preserve form input');
  await page.locator('#fs-test').click();
  await page.locator('#fs-message').filter({hasText:'测试通知发送成功'}).waitFor();
  assert.strictEqual(await page.locator('#fs-url').inputValue(),'');
  const calls=await page.evaluate(()=>window.testCalls);
  assert(calls.some(c=>c.cmd==='feishu_save'&&c.args.settings.secret===null));
  assert(calls.some(c=>c.cmd==='feishu_test'));
  await page.locator('#fs-enabled').uncheck();
  await page.locator('#fs-save').click();
  await page.locator('#fs-status').filter({hasText:'通知未启用'}).waitFor();
  await page.locator('#fs-enabled').check();
  await page.locator('#fs-save').click();
  await page.locator('#fs-status').filter({hasText:'通知已启用'}).waitFor();
  await page.evaluate(()=>Object.assign(window.fsStatus,{failed:2,last_failure:'测试：签名被拒绝'}));
  await page.locator('#fs-status').filter({hasText:'保留失败通知：2 条'}).waitFor();
  await page.locator('#fs-retry').click();
  await page.locator('#fs-message').filter({hasText:'失败通知已重新排队'}).waitFor();
  assert((await page.evaluate(()=>window.testCalls)).some(c=>c.cmd==='feishu_retry_failed'));
  await page.locator('#feishu-group').scrollIntoViewIfNeeded();
  const output=path.resolve(__dirname,'output');fs.mkdirSync(output,{recursive:true});
  await page.screenshot({path:path.join(output,'native-feishu-preview.png')});
  const overflow=await page.locator('#feishu-group').evaluate(el=>el.scrollWidth>el.clientWidth);
  assert(!overflow,'Feishu settings should not overflow narrow card');
  assert.deepStrictEqual(errors,[]);
  await page.locator('#cu-enabled').check();
  await page.locator('#cu-check').click();
  await page.locator('#cu-status').filter({hasText:'等待 Claude 和 Claude Code 退出'}).waitFor();
  await page.evaluate(()=>Object.assign(window.cuStatus,{phase:'downloading',downloaded:50,total:100}));
  await page.locator('#cu-status').filter({hasText:'50%'}).waitFor();
  assert(await page.locator('#cu-check').isDisabled());
  await page.evaluate(()=>Object.assign(window.cuStatus,{phase:'failed',error:'signature failed'}));
  await page.locator('#cu-status').filter({hasText:'signature failed'}).waitFor();
  assert(await page.locator('#cu-check').isEnabled());
  await page.evaluate(()=>Object.assign(window.cuStatus,{phase:'deferred',pending_version:'2.37337.1',error:''}));
  await page.locator('#cu-status').filter({hasText:'新版尚未生效'}).waitFor();
  assert.strictEqual(await page.locator('#cu-check').innerText(),'核对 Claude 更新结果');
  assert(!(await page.locator('#cu-status').innerText()).includes('更新完成'));
  await page.locator('#claude-update-group').scrollIntoViewIfNeeded();
  await page.screenshot({path:path.join(output,'claude-update-preview.png')});
  assert(!(await page.locator('#claude-update-group').evaluate(el=>el.scrollWidth>el.clientWidth)));
  assert.deepStrictEqual(errors,[]);
  await page.locator('#cx-enabled').check();
  await page.locator('#cx-check').click();
  await page.locator('#cx-status').filter({hasText:'等待 Codex 和相关任务退出'}).waitFor();
  assert(await page.locator('#cu-enabled').isChecked(),'Codex settings must not reset Claude');
  assert(await page.locator('#codex-update-group').innerText().then(t=>t.includes('每周')));
  await page.evaluate(()=>Object.assign(window.cxStatus,{phase:'deferred',pending_version:'26.1007.9446.0',error:''}));
  await page.locator('#cx-status').filter({hasText:'新版尚未生效'}).waitFor();
  assert.strictEqual(await page.locator('#cx-check').innerText(),'核对 Codex 更新结果');
  await page.evaluate(()=>Object.assign(window.cxStatus,{phase:'restart_required'}));
  await page.locator('#cx-status').filter({hasText:'重启整台电脑'}).waitFor();
  assert(await page.locator('#cx-finish').isEnabled());
  await page.locator('#cx-finish').click();
  await page.locator('#cx-status').filter({hasText:'已安排重启后完成更新'}).waitFor();
  assert(await page.locator('#cx-finish').isDisabled());
  assert((await page.evaluate(()=>window.testCalls)).some(c=>c.cmd==='codex_update_check'&&c.args?.finish===true));
  assert(!(await page.locator('#codex-update-group').evaluate(el=>el.scrollWidth>el.clientWidth)));
  await page.screenshot({path:path.join(output,'codex-update-preview.png')});
  assert.deepStrictEqual(errors,[]);
  const standalone=await browser.newPage({viewport:{width:900,height:650}});
  await standalone.goto('file:///'+path.resolve(__dirname,'..','ui','index.html').replace(/\\/g,'/'));
  await standalone.getByRole('heading',{name:'请从桌面打开 ClaudeGuard'}).waitFor();
  await standalone.screenshot({path:path.join(output,'standalone-notice.png')});
  fs.writeFileSync(path.join(output,'ui-test.json'),JSON.stringify({passed:true,viewport:'420x620',checks:['settings migration flags','form retained on monitor update','save/test IPC','enable/disable','no horizontal overflow','no JavaScript errors']},null,2));
  await browser.close();
  console.log('UI integration checks passed (mock IPC, no real notification sent)');
})().catch(e=>{console.error(e);process.exit(1)});
