# AGENTS.md — ClaudeGuard 维护者守则（人类与 AI 通用）

> 本文件是所有维护者（包括 AI agent）的约定与经验记录。CI 只做编译冒烟
> （build + 产物上传），不做格式/lint/测试红线。改代码前先读完；不确定就按本文件保守执行。
>
> **CI 状态：快速迭代期已 `gh workflow disable CI`（2026-10-02），push 不再触发。**
> 迭代结束发版前：`gh workflow enable CI` → push 确认全绿 → 再发版。
> 期间质量由本地门禁兜底：`cargo fmt && cargo clippy --locked -- -D warnings && cargo test --locked`。

## 项目一句话

Windows 桌面守护器：校验本地代理出口 IP → 通过才放行 Claude；常驻托盘监测；出口异常时
熔断（杀进程 + 防火墙隔离）。单二进制、轻量、Apple 风格 UI。**任何改动不得违背这三条定位。**

## 模块地图与所有权

| 模块 | 职责 | 允许 | 禁止 |
|---|---|---|---|
| `src/main.rs` | CLI 入口 + tauri 建窗/托盘/标题回调/单实例 | 改窗口与托盘装配 | 塞业务逻辑 |
| `src/monitor.rs` | 后台检测循环/熔断/解除/更新线程, `guard://status\|log\|update` 事件 | 改监测编排与事件载荷 | 在 webview 线程做耗时操作 |
| `src/ipc.rs` | 全部 `#[tauri::command]`（13 条 + `js_log` 诊断桥） | 加命令 | 绕过 `Shared` 直接摸全局 |
| `ui/` | 纯静态前端（index.html/app.css/icons.js/ipc.js/main.js，无构建步骤） | 改前端 | — |
| `src/checks.rs` | 三步校验（注册表代理/CONNECT 握手/出口 IP） | 改校验逻辑+单测 | panic（任何输入都必须返回失败步骤） |
| `src/guard.rs` | 熔断：杀进程/防火墙/日志/启动 Claude | 改熔断 | 相对路径调子进程 |
| `src/install.rs` | 安装/卸载/自启/快捷方式 | 改安装逻辑 | 写死用户路径 |
| `src/update.rs` | GitHub Releases 检查/下载/自替换 | 改更新 | 改资产命名规则（见下） |
| `src/tcp_table.rs` | GetExtendedTcpTable 解析 | 改解析 | 引入新 crate |
| `src/config.rs` | 配置读写（原子写） | 加字段（带 serde default） | 破坏旧配置文件兼容 |

## 构建与发版

```powershell
cargo build --release          # release 带管理员清单(requireAdministrator)，debug 不带
cargo test                     # debug 跑测试；cargo test --release 会因清单 740 失败，属预期
cargo clippy -- -D warnings
cargo fmt
```

发版流程（顺序固定）：
1. `Cargo.toml` 升版本 → build/test/clippy 全绿。
2. release 资产**必须**命名 `ClaudeGuard-vX.Y.Z.exe`——更新器 `exe_asset()` 按
   "含 ClaudeGuard 且以 .exe 结尾"匹配，命名错了用户端检查更新会拿不到资产。
   **注意：带 `-setup` 的 Inno 安装包也满足该匹配**，挂资产时 exe 命名保持裸版优先。
3. `powershell -File make-release.ps1 -Ver X.Y.Z` 一键产出 zip（便携）+ setup（Inno 安装包），
   并交叉校验 exe 版本号；`gh release create` 两个都挂。
   **注意：exe 的 win32 版本资源被 tauri_build 补成 4 段（2.0.0.0），所以发布脚本用
   `/DMyAppVersionStr=X.Y.Z` 把 3 段规范版注入 ISCC**——手动裸跑 ISCC 会产出
   `v2.0.0.0-setup.exe`（4 段文件名），别直接挂。
   **分发渠道 = GitHub release 一种**。不做"朋友包"本地副本，发版后无需复制/更新
   任何本地交付文件（用户已明确取消，勿再生成项目文件夹里的 vX.Y.Z.zip 副本）。
4. `git commit` + 打 tag `vX.Y.Z` + push。
5. 版本号语义：改 UI/功能升 minor，修 bug 升 patch。

### Inno 安装包（claude-guard.iss，仓库根目录）

- .iss **必须在根目录**：里面相对路径（`assets\`、`target\`、`installer\`）按 .iss 所在目录解析。
- 版本号不写在 .iss 里：发布脚本经 `/DMyAppVersionStr` 注入；无 define 时兜底读 exe。
  **先 build 再编安装包**。
- `AppId={{F5110E67-…}` 永不改（改了=系统认为是新软件，升级变双装）。
- 卸载注册表键名 = **AppId GUID + `_is1`**（`{F5110E67-…}_is1`），不是 `ClaudeGuard_is1`；
  查"应用与功能"按 `*_is1` 后缀找，别按 DisplayName 精确匹配踩坑。
- `PrivilegesRequired=admin` → 全机器安装：桌面图标进 `C:\Users\Public\Desktop`，
  开始菜单进 `C:\ProgramData\...\Start Menu\Programs\ClaudeGuard`——E2E 断言别查
  per-user 路径。
- v2 起安装前检测 WebView2 运行时（注册表 EdgeUpdate Clients `{F3017226-…}` 的 pv），
  缺失报错指路不自动下载（保持零捆绑）。
- 卸载**故意保留** `%APPDATA%\ClaudeGuard`（配置+日志）；安装/卸载前 taskkill 在
  `[Code]` 段，中文向导文案来自 `installer\ChineseSimplified.isl`（官方翻译，需 BOM，
  编辑后重补 BOM）。.iss 本身保持纯 ASCII。
- ISCC 路径：`C:\Users\daha\AppData\Local\Programs\Inno Setup 6\ISCC.exe`（per-user 安装）。

## 已知坑（别再踩）

1. **classic script 共享全局词法作用域**：`ui/*.js` 顶层 `const/let` 跨文件撞名会让后加载的
   脚本**整个编译失败**（`SyntaxError: Identifier 'x' has already been declared`），一行都不
   执行，且页面里没有任何 error 监听能捕到（监听器本身在那个脚本里）。v2 P0 实测踩过：
   `node --check` 逐文件独立解析查不出来。**对策：ui/*.js 保持 IIFE 包裹**，跨文件只走
   `window.ICONS` / `window.CG_IPC`。
2. **tauri 资源嵌入是编译期的**：改 `ui/` 后必须重新 `cargo build`（必要时 touch ui 文件强制
   重嵌），磁盘改完不重编=运行的还是旧前端。
3. **`document.title` → 原生窗口标题不自动**：wry 只回调不代设，需
   `.on_document_title_changed(|w, t| w.set_title(&t))`（main.rs 已接）。
4. **webview 前端诊断三板斧**（按序）：`js_log` 命令把 `[js] …` 写进 guard.log；
   CDP（`$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS='--remote-debugging-port=9222'` 启动
   + node 连 `/json/list` 的 webSocketDebuggerUrl，`Runtime.evaluate`/`Page.reload`+console 域
   收真实报错）；像素扫描截图（绿环/橙横幅色值计数）。
5. **中文 .ps1 必须 UTF-8 带 BOM**：很多工具写文件会剥 BOM，PowerShell 5.1 按 ANSI 读，
   中文字面量会吞掉后续代码。写完用 `[IO.File]::WriteAllText($p, $t, [Text.UTF8Encoding]::new($true))` 补。
6. pwsh 内嵌 C#（DllImport）时 `$`/引号转义会被外层吃掉：一律写 .ps1 文件再 `-File` 执行。
7. 测试钩子（仅 debug/截图用，别在生产路径依赖）：env `CG_WIN_H`=覆盖窗口高；
   env `CG_SMOKE_SETTINGS`=自动展开设置卡。冒烟脚本 `smoke-v2.ps1`（不入库；向导阶段有
   安全阀：claude.exe 在跑就跳过，空 required_ip 会触发真实熔断）。
8. 屏幕是 1080p@200% 缩放：窗口高度公式按工作区算（`main.rs` SPI_GETWORKAREA），改 UI 后
   用截图+像素扫描复核，不要凭想象改布局。窗口尺寸 API 传的是逻辑像素。
9. tauri 权限：`core:default` 不含窗口操作，`capabilities/default.json` 需显式放行
   minimize/toggle-maximize/close/start-dragging/start-resize-dragging。
10. **release exe 带 requireAdministrator 清单**：UAC 提权后子进程拿的是注册表重建的
    环境，**父 shell 的 `$env:` 传不进去**（CDP 调试口因此对 release 开不了；要用
    CDP/像素调试一律跑 debug 构建）。也正因如此 release 运行时 `is_admin=true`，
    管理员横幅只在 debug 出现——冒烟断言时记住这点。
11. v1 egui 时代条目已随模块删除失效（无字重字段等）；v1 行为基准全部迁入
    `docs/PARITY-v2.md`，文案/状态机以它为准。
