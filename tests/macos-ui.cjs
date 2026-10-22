// Render upstream's real static frontend against a deterministic IPC fixture.
// No external network, notifications, process termination or application installation.
const { chromium } = require(process.env.CG_PLAYWRIGHT || 'playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 980, height: 860 }, deviceScaleFactor: 2, reducedMotion: 'reduce' });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('http://guard.test/**', async route => {
      const name = new URL(route.request().url()).pathname.slice(1) || 'index.html';
      const file = path.resolve(__dirname, '../ui', name);
      if (!file.startsWith(path.resolve(__dirname, '../ui') + path.sep) || !fs.existsSync(file)) {
        await route.fulfill({ status: 404, body: '' });
        return;
      }
      await route.fulfill({ path: file, contentType: name.endsWith('.js') ? 'application/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html' });
    });
    await page.addInitScript(() => {
      window.calls = [];
      window.listeners = {};
      const target = { id: 'claude', name: 'Claude 出口', builtin: true, enabled: true, anchor_url: 'https://claude.ai/cdn-cgi/trace', anchor_kind: 'trace', expect_ips: ['203.0.113.7'], expect_regions: [], timeout_secs: 12, bind_agent: 'claude' };
      const cfg = { version: 3, proxy_host: '127.0.0.1', proxy_port: 7890, targets: [target], check_interval_secs: 15, trip_threshold: 2, cut_network: true, disable_network_adapters: false, kill_on_fail: true, quarantine_on_fail: true, guarded_agents: ['claude'], sweep_on_exit: true, close_to_tray: true, auto_start_with_system: false, first_run: false, notify: { enabled: true } };
      const client = { enabled: false, phase: 'idle', error: '' };
      const feishu = { enabled: false, hasWebhook: false, hasSecret: false, queued: 0, failed: 0, error: '' };
      window.fixture = { platform: 'macos', networkIsolationSupported: false, checking: false, checkedAt: 1700000000, intervalSecs: 15, tripThreshold: 2, overall: 'pass', targets: [{ id: 'claude', name: 'Claude 出口', enabled: true, state: 'pass', ip: '203.0.113.7', country: 'US', latencyMs: 12, reason: '出口在允许范围内' }], admin: false, installed: false, version: '3.5.0', upd: { state: 'idle' }, feishu, claudeUpdate: client, codexUpdate: client, agentsRunning: [], cliRunning: [], launchError: '', smokeSettings: false, notifyEnabled: true, cutMode: 'firewall', guardedAgents: ['claude'] };
      const invoke = async (cmd, args) => {
        window.calls.push({ cmd, args });
        if (cmd === 'get_state') return window.fixture;
        if (cmd === 'get_config') return cfg;
        if (cmd === 'recent_logs') return [];
        if (cmd === 'upd_state') return window.fixture.upd;
        if (cmd === 'feishu_status') return feishu;
        if (cmd === 'claude_update_status' || cmd === 'codex_update_status') return client;
        if (cmd === 'update_settings') { Object.assign(cfg, args.patch); return window.fixture; }
        if (cmd === 'pause') { window.fixture.overall = 'paused'; window.fixture.pausedUntil = Math.floor(Date.now() / 1000) + 1800; }
        if (cmd === 'resume') { window.fixture.overall = 'pass'; window.fixture.pausedUntil = null; }
        return null;
      };
      window.__TAURI__ = { core: { invoke }, event: { listen: async (name, callback) => { window.listeners[name] = callback; return () => {}; } }, window: { getCurrentWindow: () => ({ minimize() {}, close() {}, startDragging() {}, startResizeDragging() {} }) } };
      window.emitFixture = patch => {
        Object.assign(window.fixture, patch);
        window.listeners['guard://state']({ payload: window.fixture });
      };
    });
    await page.goto('http://guard.test/');
    await page.locator('body[data-overall="pass"]').waitFor();
    await page.locator('#banners').filter({ hasText: '进程守护模式' }).waitFor();
    const output = path.join(__dirname, 'output');
    fs.mkdirSync(output, { recursive: true });
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(450); // Allow upstream entrance/transparency layers to finish.
    await page.screenshot({ path: path.join(output, 'macos-pass.png') });
    await page.getByRole('button', { name: '设置', exact: true }).last().click();
    await page.locator('#st-port').waitFor({ state: 'attached', timeout: 3000 }).catch(async e => { console.error({errors, ui: await page.evaluate(() => ({ keys: Object.keys(window.CG_UI || {}), calls: window.calls, text: document.body.innerText.slice(-1600) }))}); throw e; });
    await page.locator('[data-g="guard"] .acc-head').click();
    assert.equal(await page.locator('#st-cut button:disabled').count(), 3);
    assert.equal(await page.locator('#st-cut [data-mode=off]').getAttribute('aria-pressed'), 'true');
    assert(await page.locator('#st-quarantine').isDisabled());
    assert.equal(await page.locator('#st-quarantine').isChecked(), false);
    await page.waitForTimeout(450);
    await page.screenshot({ path: path.join(output, 'macos-settings.png') });
    await page.locator('[data-g="detect"] .acc-head').click();
    await page.locator('#st-port').fill('7900');
    await page.locator('#st-port').blur();
    await page.waitForFunction(() => window.calls.some(c => c.cmd === 'update_settings' && c.args.patch.proxy_port === 7900));
    await page.locator('[data-g="update"] .acc-head').click();
    assert.equal(await page.locator('#cu-enabled').isDisabled(), false);
    assert.equal(await page.locator('#cu-check').isDisabled(), false);
    assert.equal(await page.locator('#cx-enabled').isDisabled(), false);
    await page.locator('[data-g="feishu"] .acc-head').click();
    assert((await page.locator('#feishu-group').innerText()).includes('macOS 登录钥匙串'));
    await page.locator('#link-settings').click();
    await page.evaluate(() => window.emitFixture({ overall: 'tripped', tripped: { reason: '<test>白名单不匹配', killed: 1, firewallRules: 0, quarantinedAgents: [], agents: ['Claude'], networkCut: 'off', networkNote: 'macOS 网络隔离未实现；网络未切断' } }));
    await page.locator('body[data-overall="tripped"]').waitFor();
    assert(await page.locator('#btn-primary').isDisabled(), 'trip disables launcher');
    assert((await page.locator('#btn-primary').innerText()).includes('启动已禁止'));
    assert((await page.locator('#banners').innerText()).includes('进程守护模式'));
    assert.equal(await page.locator('#banners test').count(), 0);
    await page.waitForTimeout(450);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: path.join(output, 'macos-trip.png') });
    await page.evaluate(() => window.emitFixture({ overall: 'paused', tripped: null, pausedUntil: Math.floor(Date.now() / 1000) + 1800 }));
    await page.locator('body[data-overall="paused"]').waitFor();
    await page.locator('[data-bact="resume"]').click();
    await page.waitForFunction(() => window.calls.some(c => c.cmd === 'resume'));
    await page.setViewportSize({ width: 520, height: 640 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    const cta = await page.locator('#btn-primary').boundingBox();
    assert(cta && cta.x >= 0 && cta.x + cta.width <= 520, 'primary action fits the minimum native window width');
    await page.screenshot({ path: path.join(output, 'macos-narrow.png') });
    // The same frontend must keep Windows capability controls available.
    await page.evaluate(() => window.emitFixture({ platform: 'windows', networkIsolationSupported: true, overall: 'pass' }));
    assert(!(await page.locator('#banners').innerText()).includes('macOS 移植预览'));
    assert.equal(await page.locator('#st-cut button:disabled').count(), 0);
    assert.equal(await page.locator('#st-quarantine').isDisabled(), false);
    assert.deepEqual(errors, []);
    console.log('PASS: upstream UI rendering, settings persistence, capability gates, trip/paused states, escaping, Windows banner parity; zero page errors');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
