# AGENTS.md — ClaudeGuard 维护者守则（人类与 AI 通用）

> 本文件是所有维护者（包括 AI agent）的强制约定。CI 用 clippy/fmt/test 机械执法，
> 本文件解释"为什么"。改代码前先读完；不确定就按本文件保守执行。

## 项目一句话

Windows 桌面守护器：校验本地代理出口 IP → 通过才放行 Claude；常驻托盘监测；出口异常时
熔断（杀进程 + 防火墙隔离）。单二进制、轻量、Apple 风格 UI。**任何改动不得违背这三条定位。**

## 模块地图与所有权

| 模块 | 职责 | 允许 | 禁止 |
|---|---|---|---|
| `src/app.rs` | 唯一有状态类型 `GuardApp`、主视图、设置卡、监测编排 | 改状态字段/视图逻辑 | 再膨胀；新视图请建新文件 |
| `src/widgets.rs` | 全部无状态 UI 部件（按钮/开关/卡片/标题栏…） | 新部件=纯函数 `fn(ui, …) -> Response` | 持有任何状态、引用 GuardApp |
| `src/theme.rs` | 设计令牌（颜色/字体/样式）+ `init(ctx)` | 加常量 | 在别处内联魔法色值/字号 |
| `src/wizard.rs` | 首次运行向导（`impl GuardApp` 三页流程） | 改向导 | 塞入与向导无关的内容 |
| `src/checks.rs` | 三步校验（注册表代理/CONNECT 握手/出口 IP） | 改校验逻辑+单测 | panic（任何输入都必须返回失败步骤） |
| `src/guard.rs` | 熔断：杀进程/防火墙/日志/启动 Claude | 改熔断 | 相对路径调子进程 |
| `src/install.rs` | 安装/卸载/自启/快捷方式 | 改安装逻辑 | 写死用户路径 |
| `src/update.rs` | GitHub Releases 检查/下载/自替换 | 改更新 | 改资产命名规则（见下） |
| `src/tcp_table.rs` | GetExtendedTcpTable 解析 | 改解析 | 引入新 crate |
| `src/config.rs` | 配置读写（原子写） | 加字段（带 serde default） | 破坏旧配置文件兼容 |

## 硬性规则（CI 执法，违反即红）

1. `cargo clippy -- -D warnings` 零警告；`cargo fmt --check` 必须通过。
2. `cargo test` 必须通过；**修 bug 必须先补一个能复现的测试**再修。
3. 不新增依赖，除非同时给出：体积增量、必要性、无更轻替代 三项说明。当前依赖面是刻意收敛的。
4. 颜色/字号/圆角/字重只允许用 `theme.rs` 常量。Apple 风约束：无阴影、无渐变、
   字重上限 600、唯一彩色填充是蓝 `BLUE`（按钮）、正文 17px、卡 28px 圆角、按钮全圆胶囊。
5. 子进程一律绝对路径（`guard::sys32()` / `SystemRoot`），禁止裸名（PATH 提权面）。
6. `GuardApp` 是唯一有状态类型；新部件进 `widgets.rs` 且必须纯函数。
7. UI 文案与代码注释用中文；标识符/日志关键字用英文。
8. 任何 `unwrap/expect/panic` 只允许出现在程序启动期（配置目录创建等），运行路径一律返回错误。

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
4. `git commit` + 打 tag `vX.Y.Z` + push。
5. 版本号语义：改 UI/功能升 minor，修 bug 升 patch。

### Inno 安装包（claude-guard.iss，仓库根目录）

- .iss **必须在根目录**：里面相对路径（`assets\`、`target\`、`installer\`）按 .iss 所在目录解析。
- 版本号不写在 .iss 里：`GetVersionNumbersString('target\release\claude-guard.exe')`
  直接读 exe（build.rs 从 Cargo.toml 注入），**先 build 再编安装包**。
- `AppId={{F5110E67-…}` 永不改（改了=系统认为是新软件，升级变双装）。
- "应用与功能"里显示名取 `AppVerName`（"ClaudeGuard X.Y.Z"）；查注册表按
  `*_is1` 后缀找，别按 DisplayName 精确匹配踩坑。
- 卸载**故意保留** `%APPDATA%\ClaudeGuard`（配置+日志）；安装/卸载前 taskkill 在
  `[Code]` 段，中文向导文案来自 `installer\ChineseSimplified.isl`（官方翻译，需 BOM，
  编辑后重补 BOM）。.iss 本身保持纯 ASCII。
- ISCC 路径：`C:\Users\daha\AppData\Local\Programs\Inno Setup 6\ISCC.exe`（per-user 安装）。

## 已知坑（别再踩）

- **中文 .ps1 必须 UTF-8 带 BOM**：很多工具写文件会剥 BOM，PowerShell 5.1 按 ANSI 读，
  中文字面量会吞掉后续代码。写完用 `[IO.File]::WriteAllText($p, $t, [Text.UTF8Encoding]::new($true))` 补。
- pwsh 内嵌 C#（DllImport）时 `$`/引号转义会被外层吃掉：一律写 .ps1 文件再 `-File` 执行。
- 测试钩子（仅 debug/截图用，别在生产路径依赖）：env `CG_WIN_H`=覆盖窗口高；
  env `CG_SMOKE_SETTINGS`=只渲染设置卡视图。冒烟脚本 `smoke-ui3.ps1`（不入库）。
- `egui` 无字重字段：600 字重靠 `widgets::btext` 双重绘制模拟；无字距 API。
- 屏幕是 1080p@200% 缩放：窗口高度公式按工作区算（`main.rs` SPI_GETWORKAREA），改 UI 后
  用截图+视觉模型复核，不要凭想象改布局。

## 改 UI 的验收标准

改任何可见元素，提交前必须：截图三视图（主屏/向导/设置）→ 视觉复核无乱码/无溢出/无风格漂移。
风格漂移=出现了规范外颜色、阴影、渐变、居中大标题、700+ 字重。
