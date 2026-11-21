# 更新日志（CHANGELOG）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的格式约定，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

日期为实际发布日期（UTC / UTC+8）。更早的历史版本记录见 [GitHub Releases](https://github.com/daha1216/ClaudeGuard/releases)。

## [4.0.0] - 2026-11-21

**ClaudeGuard v4**：从 v3 单体 Tauri 2（WebView2）架构全面演进为 **Windows Service 守护端 + 原生 Rust GPUI 桌面端** 三端解耦架构，实现日常零 UAC 弹窗、崩溃 WAL 零残留自愈、4 维防漏护盾与只读生态巡检。

### 核心架构升级

- **三端解耦与权限分离**：拆分为 `claudeguard-daemon.exe`（`ClaudeGuardService` Session-0 系统服务）、`claudeguard-cli.exe`（脚本化检查与应急恢复 CLI）与 `claudeguard-gui.exe`（`asInvoker` 普通权限原生 GPUI 界面，无 WebView2 依赖）。
- **安全 Named Pipe IPC**：采用 SDDL ACL（`SY`/`BA` 完全控制、`AU` 读写）与 `PIPE_REJECT_REMOTE_CLIENTS` 绑定 `\\.\pipe\ClaudeGuardV4`，支持 4 MiB 帧长校验与 `Arc<RwLock<_>>` 零阻塞快照读取。
- **WAL 崩溃回滚账本（`journal.json`）**：所有系统级变更（防火墙隔离、手动封锁、全局断网、时区与位置对齐）均遵循「先持久化 WAL 再操作 OS」，并在服务启动及离线 `--restore` 时幂等自愈回滚。
- **配置 v4 无损迁移与旧版升级引导**：新增 `cg-v3-bridge`（`ClaudeGuard-v4.0.0-upgrade.exe`）对接 `v3.x` 自更新检查与下载流程，自动将 `%APPDATA%\ClaudeGuard\config.json` 迁入 `%ProgramData%\ClaudeGuard\config.json`（首次迁移生成 `config.v3.bak.json` 备份），并在安装完成后清理旧版 `ClaudeGuard.exe` 与开机启动残留。

### 新功能与界面重塑

- **Frost Ceramic 全新原生 GPUI 界面**：
  - **双模式交互**：模式 A 紧凑托盘快捷 HUD（`398×432`，右下角任务栏锚定，含只读出口速览与 2×2 安全启动台）；模式 B 七栏悬浮坞控制台（总览 / 目标 / 熔断 / 防漏 / 审计 / 更新 / 通知），支持浅色 / 暗夜 / 跟随系统切换与顶部「隐私打码」脱敏。
  - **2×2 安全启动台**：Claude Desktop、Claude Code CLI、ChatGPT、Antigravity 均以普通用户令牌经合规门禁安全拉起；越界熔断或注入缺失时自动锁定禁止直连启动。
  - **严格只读、不改代理策略**：彻底移除任何代切节点或改写代理分流规则的交互，总览与环境页明确展示只读探测，尊重用户既有代理策略。
- **防漏与环境三维守护**：
  - **4 维防漏护盾 + MCP 直连雷达**：精确绑定受管 AI 客户端可执行文件路径的 `UDP:443 QUIC`、`DNS:53 & DoH`、`公网 IPv6` 封堵规则与 `Antigravity` 注入联动，并自动豁免本机回环与 TUN 虚拟网卡。
  - **Antigravity 透明代理注入守护**：内置对 `yuaotian/antigravity-proxy`（`version.dll` 完整性校验、`config.json` 端口匹配、`language_server` 运行态挂载与客户端升级覆盖拦截）的检测与一键热修复。
  - **时区与区域指纹对齐**：纯本机辅助同步 Windows 时区与默认定位坐标，先备份 `env_backup.json` 再写入，支持一键或撤防/退出无损还原。
- **10 组件版本巡检与 Antigravity 插件精选弹窗**：
  - 全量经受管代理只读检查：`ClaudeGuard`、`antigravity-proxy`、`Claude Desktop`、`Claude Code CLI`、`ChatGPT / Codex 桌面端`、`Codex CLI`、`Antigravity IDE`、`Antigravity 中文汉化引擎`（`Silas-02/antigravity-desktop-cn`），以及精选弹窗中的 `antigravity-usage-monitor` 与 `agy-capsule` 本机/上游版本比对。
- **24 小时合规轨迹审计与脱敏诊断包**：48 格半小时粒度交互式时间轴 + `Ctrl+K` 搜索 + 分级过滤 + 一键导出自动隐藏用户名、本机路径与外网 IP 后两段的 `.zip` 诊断包。
- **Session-0 → Session-1 桌面与飞书通知**：6 类精细开关、去重冷却、`LocalMachine` DPAPI 加密持久化与指数退避离线重发队列，默认隐藏外网 IP 与主机名。

### 平台边界说明

- v4 目前专注于 **Windows 10 / 11 (x64)** 深度服务化防护；v3 时期的社区 macOS 预览代码保留于 `v3` 分支与 `v3.12.5` 标签。

## [3.12.5] - 2026-11-11

### 新增

- 首次运行向导：留空白名单直接「以后再说」会触发闸门与二次确认，避免守护启动约 30 秒后被熔断隔离网络（`55a598d`）。
- 主界面把「暂停守护」「完全恢复网络」「行内直连观察」三个功能提层，不再埋在折叠卡里（`67e25e5`）。
- 设置页内置即时搜索：按标题/提示过滤设置项并自动展开匹配分组（`b147b76`）。
- 主界面新增「24 小时时间线」卡：本次运行期间的正常/熔断/暂停状态一目了然，可复盘断网时段；日志行统一补上 `MM-DD HH:MM:SS` 时间戳（`8b77e5a`）。

### 修复

- 停止保护状态贯通主卡与主按钮，标题与按钮不再与实际状态脱节（`f32b054`）。
- 断网后置核验改为按 GUID 回查网卡状态，查不到网卡即判定核验失败（P2-5，`5b34db4`）。
- lockdown IPC 返回执行回执，回查失败不再谎报已生效（P2-4，`cbec541`）。
- 配置目录不再静默落在当前工作目录；`%APPDATA%` 缺失时逐级降级并写日志（P2-7，`5ee0317`）。
- 隔离规则解除按幂等判定，轮次处置抽出 `decide_round_outcome`，自更新退出前统一走恢复闸门。

### 变更

- 统一出网入口 `netpol::client`；依赖安全对齐（`zip` 9.x、`quick-xml` 0.42、`hmac` 0.13、`aes-gcm` 0.11.1）；示例 IP 统一改为 TEST-NET（`198.51.100.98`）。

## [3.12.4] - 2026-10-27

- 修复防火墙自愈在非英文系统上从不触发的问题（改用 `Get-NetFirewallProfile` 结构化状态判断），TLS 栈补丁升级，CI 接入单元测试与 MIT 许可。

---

[4.0.0]: https://github.com/daha1216/ClaudeGuard/releases/tag/v4.0.0
[3.12.5]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.5
[3.12.4]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.4
