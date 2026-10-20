# AGENTS.md — ClaudeGuard v3 维护者守则（人类与 AI 通用）

> 本文件是所有维护者（包括 AI agent）的约定与经验记录。改代码前先读完；不确定就按本文件保守执行。
>
> **CI 状态：已停用（2026-10-02，`gh workflow disable CI`），push 不触发任何 run。**
> **只有用户明确要求跑 CI 时才 `gh workflow enable` + push 验证；发版流程也不依赖 CI。**
> 期间质量由本地门禁兜底：`cargo fmt && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked`
> 以及前端 `node --check ui/*.js`。
>
> **v3 行为基准 = `docs/SPEC-v3.md`**（v2 的 `docs/PARITY-v2.md`、`docs/v2-spec.md` 已在 v3 重写时移除，需要时查 git 历史）。

## 项目一句话

Windows 桌面守护器：按监控目标分别校验本地代理出口（IP / 地区）→ 全部通过才放行 Claude 等 AI 桌面应用；
常驻托盘，任一启用目标出口异常即熔断（杀进程 + 防火墙隔离 + 可选断网两档）。单二进制、轻量、Apple 风格 UI。
**任何改动不得违背这三条定位。**

## 模块地图与所有权（v3）

| 模块 | 职责 | 允许 | 禁止 |
|---|---|---|---|
| `src/main.rs` | CLI 分派、单实例、建窗/托盘、启动自愈、退出恢复 | 改窗口/托盘/CLI 装配 | 塞业务逻辑；改恢复顺序 |
| `src/state.rs` | 进程内共享状态 `AppState` + `StateView`（UI 载荷）+ 事件 `guard://state\|log` | 加状态字段/派发事件 | 在持锁时做 IO/网络 |
| `src/monitor.rs` | 每轮并行探测、防抖计数、熔断/恢复编排、暂停、启动 Claude | 改编排与阈值语义 | 在 webview 线程做耗时操作 |
| `src/ipc.rs` | 全部 `#[tauri::command]`（31 条，含 `js_log` 诊断桥） | 加命令 | 绕过 `AppState` 直接摸全局 |
| `src/model.rs` | 纯数据类型：Target/ProbeResult/Evaluation/TargetStatus/TripInfo/UpdState 等 | 加类型/纯函数单测 | 把 IO 放进 model |
| `src/targets.rs` | 内置目标定义与整表校验（`validate`） | 改预置值与校验规则 | 允许内置目标被删除 |
| `src/anchors.rs` | 探测执行 + `auto/trace/json_ip/gemini_region/reachability` 解析 | 加锚点类型/解析器 | 让超大响应撑爆内存（有 3MB 上限） |
| `src/policy.rs` | 判定矩阵：期望 IP/地区命中、信息缺失不熔断、名单与地区皆空永不放行 | 改判定（先改 SPEC + 单测） | 在无信息时返回 Fail |
| `src/guard.rs` | 熔断执行：杀多 agent 进程、防火墙规则管理、日志裁剪、启动 Claude | 改指纹/规则名/杀进程语义 | 相对路径调子进程；杀 CLI agent |
| `src/netcut.rs` | 断网两档（防火墙出站阻断 / 禁用网卡）、恢复与启动自愈 | 改档位实现、自愈逻辑 | 让断网状态跨进程退出残留 |
| `src/notify.rs` | 桌面通知（PowerShell + WinRT Toast，无第三方 crate） | 改五类通知文案/开关 | 在通知里回显凭据 |
| `src/config.rs` | v3 配置读写（原子写）+ v2 旧配置迁移 | 加字段（带 serde default） | 破坏旧配置兼容 |
| `src/feishu.rs` | 飞书群通知：Webhook/签名、DPAPI 凭据、持久队列、去重与重试 | 改通知 | 在日志或状态里回显凭据 |
| `src/claude_update.rs` | Claude/Codex 桌面客户端 MSIX 检查、下载校验、原位升级状态机（内嵌 `src/claude_package.ps1`） | 改更新流程 | 绕过签名/包身份校验，或加卸载/重置等破坏性回退 |
| `src/update.rs` | ClaudeGuard 自身 GitHub Releases 检查/下载/自替换 | 改更新 | 改资产命名规则（见下） |
| `src/install.rs` | 安装/卸载/自启/快捷方式 | 改安装逻辑 | 写死用户路径；卸载不恢复网络 |
| `ui/` | 纯静态前端（index.html/app.css + ipc/icons/main/settings/updates/feishu.js，无构建步骤） | 改前端（先读 SPEC §8） | 引入 npm/框架/构建步骤 |

## 判定与熔断的不变量（改任何判定相关代码前必看）

1. 每个目标独立探测、独立判定；**任一启用目标 Fail**（信息充分且不匹配）才触发熔断。
2. **信息缺失不熔断**：探测失败 / 没有 IP 与地区 / 地区模式但拿不到国家 → `Unverified`，只记录。
3. 目标的期望 IP 列表与地区列表**都为空 → 永不放行**（宁可错杀），由 UI/配置校验提示补白名单。
4. 防抖：连续 `trip_threshold`（默认 2）次失败才熔断；任意一次通过清零。
5. 熔断动作 = 结束 `guarded_agents` 里全部 GUI agent 进程（CLI 只提醒不杀）+ 按开关做防火墙隔离 +
   按 `cut_mode` 断网（`off`/`firewall` 默认/`nics`）。Claude 沿用旧规则名 `ClaudeGuard Block Out/In`。
6. 恢复 = 删断网规则 + 恢复网卡 + 解除全部 agent 隔离，必须**幂等**且可重复执行。
7. 网络绝不能因程序退出而保持断开：`main` 的退出路径、托盘退出、`--restore` 都必须恢复。

## 构建与发版

```powershell
cargo build --offline          # debug 构建不带管理员清单，可开 CDP；release 带 requireAdministrator
cargo test  --offline          # 单测（v3 起 107 个）
cargo clippy --offline --all-targets -- -D warnings
cargo fmt
node --check ui/*.js           # 逐个检查，跨文件词法冲突查不出来，靠 IIFE 铁律兜底
```

扩展测试：`tests/package-deployment.ps1`（Windows PowerShell 5.1 跑客户端更新部署模拟）；
`tests/ui-feishu.cjs` 需要 Playwright（本机 Edge 无头，`CG_PLAYWRIGHT` 可指定模块路径）。产物写 `tests/output/`（已忽略）。

发版流程（顺序固定）：
1. `Cargo.toml` 升版本 → 门禁全绿。
2. release 资产**必须**命名 `ClaudeGuard-vX.Y.Z.exe`——更新器按
   "含 ClaudeGuard 且以 .exe 结尾"匹配。**带 `-setup` 的 Inno 安装包也满足该匹配**，挂资产时裸 exe 优先。
3. `powershell -File make-release.ps1 -Ver X.Y.Z` 产出 zip（便携）+ setup（Inno），并交叉校验版本；
   `gh release create --notes-file`（中文引号必须走文件）挂两个资产。
   发布脚本用 `/DMyAppVersionStr=X.Y.Z` 把 3 段规范版注入 ISCC；手动裸跑 ISCC 会得到 4 段文件名，别挂。
   **分发渠道 = GitHub release 一种**，不发本地副本。
4. `git commit` + tag `vX.Y.Z` + push（分支 master）。
5. 版本号语义：改 UI/功能升 minor，修 bug 升 patch。

### Inno 安装包（claude-guard.iss，仓库根目录）

- .iss **必须在根目录**：相对路径（`assets\`、`target\`、`installer\`）按 .iss 所在目录解析。
- 版本号不写在 .iss 里：发布脚本经 `/DMyAppVersionStr` 注入；无 define 时兜底读 exe。**先 build 再编安装包**。
- `AppId={{F5110E67-…}` 永不改（改了=系统认为是新软件，升级变双装）。
- 卸载注册表键名 = **AppId GUID + `_is1`**（`{F5110E67-…}_is1`），不是 `ClaudeGuard_is1`。
- `PrivilegesRequired=admin` → 全机器安装：桌面图标进 `C:\Users\Public\Desktop`。
- 安装前检测 WebView2 运行时（注册表 EdgeUpdate Clients `{F3017226-…}` 的 pv），缺失报错指路不自动下载。
- 卸载**故意保留** `%APPDATA%\ClaudeGuard`（配置/日志/队列）；安装/卸载前 taskkill 在 `[Code]` 段，
  中文向导文案来自 `installer\ChineseSimplified.isl`（需 BOM，编辑后重补 BOM）。.iss 本身保持纯 ASCII。
- ISCC 路径：`C:\Users\daha\AppData\Local\Programs\Inno Setup 6\ISCC.exe`（per-user 安装）。

## 已知坑（别再踩）

1. **classic script 共享全局词法作用域**：`ui/*.js` 顶层 `const/let` 跨文件撞名会让后加载的脚本**整个编译失败**
   （`SyntaxError: Identifier 'x' has already been declared`），且页面上没有任何 error 监听能捕到。
   `node --check` 逐文件独立解析查不出来。**对策：ui/*.js 一律 IIFE 包裹**，跨文件只走
   `window.ICONS` / `window.CG_IPC` / `window.CG_UI`。
2. **tauri 资源嵌入是编译期的**：改 `ui/` 后必须重新 `cargo build`（必要时 touch ui 文件强制重嵌），
   磁盘改完不重编=运行的还是旧前端。运行中的实例会锁 exe（os error 5），构建前先杀进程。
3. **tauri 权限**：`core:default` 不含窗口操作，`capabilities/default.json` 需显式放行
   minimize/close/start-dragging/start-resize-dragging；新增插件（如通知）要加对应权限。
4. **webview 前端诊断三板斧**（按序）：`js_log` 命令把 `[js] …` 写进 guard.log；CDP
   （debug 构建 + `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222`，node 连
   `/json/list` 的 webSocketDebuggerUrl，`Runtime.evaluate`/`Page.reload` 收真实报错；每次 evaluate 片段
   都要 IIFE 包住，否则 `const` 重声明会报错）；像素扫描截图（绿环/红横幅色值计数）。
5. **release exe 带 requireAdministrator 清单**：UAC 提权后子进程拿的是注册表重建的环境，父 shell 的
   `$env:` 传不进去（CDP 调试口因此对 release 开不了；CDP/像素调试一律跑 debug 构建）。
6. **中文 .ps1 必须 UTF-8 带 BOM**：很多工具写文件会剥 BOM，PowerShell 5.1 按 ANSI 读会吞代码。
   写完用 `[IO.File]::WriteAllText($p, $t, [Text.UTF8Encoding]::new($true))` 补。
7. pwsh 内嵌 C#（DllImport）时 `$`/引号转义会被外层吃掉：一律写 .ps1 文件再 `-File` 执行。
8. **测试钩子（仅 debug/截图用，生产路径不许依赖）**：`CG_WIN_H`=覆盖窗口高；
   `--settings`=启动即唤起主窗口并展开设置卡（截图最可靠）；`CG_SMOKE_SETTINGS=1` 只置 StateView 标记；
   `CG_SMOKE_STATE=pass|fail|trip|paused`=造界面状态且**跳过**真实探测/更新线程（不杀进程、不碰防火墙网卡）。
   截屏流程：杀干净驻留实例 → 设环境变量启动 debug exe → 等 CDP 9222 → node 脚本截图。冒烟脚本不入库。
9. 屏幕是 1080p@200% 缩放：窗口高度按工作区算（`main.rs`，`CG_WIN_H` 可覆盖）；窗口尺寸 API 传逻辑像素。
10. **netsh 输出是本地化的，禁止解析文本**：防火墙规则查询/删除走 PowerShell `Get-NetFirewallRule`
    （按 InstanceID GUID 精确删）；断网状态以 `%APPDATA%\ClaudeGuard\netcut.json` 为准，
    规则存在性只做幂等删除前的计数兜底。
11. **WinRT Toast 必须先加载类型**：PowerShell 5.1 里 `[Windows.UI.Notifications.ToastNotificationManager, …]
    | Out-Null` 不执行会报"找不到类型 [Windows.Data.Xml.Dom.XmlDocument]"。见 `notify.rs`。
12. **Toast 的 AUMID 必须登记，否则静默丢弃**：`CreateToastNotifier('ClaudeGuard').Show(..)` 在
    `HKCU\Software\Classes\AppUserModelId\ClaudeGuard` 不存在时不抛错也不弹通知（v3.1.2 之前
    “桌面通知不生效”就是这个）。`notify::ensure_identity()` 每次发送前幂等写入 DisplayName / IconUri；
    验证办法：发一条后看 `HKCU\…\Notifications\Settings\ClaudeGuard\LastNotificationAddedTime` 是否更新。
13. **v2 与 v3 共用 identifier 与配置目录**：本机若还驻留 v2.10.1，启动 v3（debug 也一样）会被
    single-instance 转到已有实例——**新进程静默退出、退出码 0**，看起来像"启动失败"。调试/升级/截屏前先
    `Get-CimInstance Win32_Process` 匹配 `*laudeguard*` 杀干净
    （装机 exe 名 `ClaudeGuard.exe` 无连字符）；装机实例是提权进程，普通 taskkill 会被拒，需
    `Start-Process taskkill -Verb RunAs`。v2 残留的 `ClaudeGuard Block In/Out` 规则 v3 会 dedupe，
    但解除隔离要用 v3 的"解除隔离并恢复网络"或 `--restore`。
14. **客户端更新只走官方 MSIX 源**：Claude 走 claude.ai 重定向后的 downloads.claude.ai，Codex 走
    persistent.oaistatic.com。部署脚本固定用 **Windows PowerShell 5.1**（Appx 模块只在 5.1 可用），
    参数全走环境变量；`Add-AppxPackage` 只用原位升级参数，不做卸载/重置/强制关闭。
    改 `src/claude_package.ps1` 后必须重跑 `tests/package-deployment.ps1` 的部署模拟。
15. 新增设置存**独立 json**（`feishu.json` / `claude-update.json` / `codex-update.json`），不进 `config.json`；
    飞书凭据用 DPAPI 加密，但通知队列正文是明文且含出口 IP——文档已披露，别把凭据写进日志或状态。
16. CLI 快照：`--check`（只读探测，exit 0 通过/2 不通过）、`--restore`（急救恢复网络+解隔离）、
    `--settings` 唤起设置页、`--feishu-status`/`--claude-update-status`/`--codex-update-status`
    只读本地状态文件，不联网、不发通知、不触发安装。
17. **每个目标的锚点要用目标自己的域名**：claude.ai / chatgpt.com / cloudflare.com 的 `/cdn-cgi/trace`
    回显的是该链路出口；Google 组域名没有 Cloudflare 回显，反重力用 `cloudcode-pa.googleapis.com` 仅测可达性
    （HTTP 任意响应都算通）。DoH ECS 只能拿到 /24，不能当精确 IP 用。
18. **UI 冒烟截图（CDP）三段式**：每轮用独立的 `WEBVIEW2_USER_DATA_FOLDER`——残留 profile 或孤儿
    `msedgewebview2` 会让新实例起不来/渲染旧帧，截图前先按 `claude-guard.exe` + 命令行含
    `com.daha.claudeguard` 循环清理。连上后先等 `document.readyState==="complete" && window.CG_IPC
    && document.body.dataset.overall` 再截，不要 `Page.reload` 后固定 sleep；`#card-settings/#card-details`
    折叠时 `display:none`，截图前先 `CG_UI.openSettings()/openDetails()` 并 `scrollIntoView`，
    动画要等 400ms 以上。截图后用像素扫描确认 PNG 尺寸（应 840×1240@2x）与色值，防止拿到空白页。
19. **本机出口（local）目标默认关闭**：本机常规流量出口通常与 AI 代理出口不是同一个 IP，默认开启会在
    首次启动/升级后立即熔断。`targets::default_targets` 里 local 的 `enabled:false` 是产品语义（用户可在
    设置里开启并补齐白名单），不要"修"成 true。
