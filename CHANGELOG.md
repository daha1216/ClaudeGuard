# 更新日志（CHANGELOG）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的格式约定，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

日期为实际发布日期（UTC / UTC+8）。更早的历史版本记录见 [GitHub Releases](https://github.com/daha1216/ClaudeGuard/releases)。

## [4.1.2] - 2026-11-24

**全链路更新巡检与本机/网络检测可靠性重构版**：彻底解决共享代理下检查更新频繁限流失败、`claude.ai` Cloudflare 403 拦截、10 组件串行卡顿、反重力代理热修复 URL 拼接错误以及 Session-0 多场景漏检与误判问题，真机 10 组件全量并发检查耗时压降至约 1.1 秒。

### 更新巡检与联网稳定性升级

- **10 组件全并发检查与多源抗限流回退（`cg-platform::update_check`）**：
  - 全量更新巡检改为 `std::thread::scope` 10 路并发执行，总耗时由串行最高 140s 降至 ~1.1s，并将后台定时更新巡检移出监控主循环避免阻塞。
  - **GitHub 零 API 限流链路**：全部 5 个 GitHub 跟踪仓库优先通过网页 `302 /releases/latest`、`releases/expanded_assets` 与 `commits.atom` 获取最新标签、资产与提交日期，彻底规避共享代理出口 `api.github.com` 60 次/小时未认证限流（403/429）。
  - **多渠道官方备份源**：`Claude 桌面端` 优先读取 `downloads.claude.ai` 官方 Squirrel `RELEASES` 清单（免疫 `claude.ai` Cloudflare 403 Challenge）；`Claude Code` / `Codex CLI` 支持 `npmjs.org` → `npmmirror.com` 自动回退；`ChatGPT / Codex 桌面端` 支持 `HEAD` → `Range GET` → 官方 Cask 元数据三级回退；`Antigravity IDE` 支持自定义源失败自动回退官方默认源并内置短重试。
- **修复 `antigravity-proxy` 一键热修复代理地址双重协议前缀必败 Bug**：
  - 修复 `repair_antigravity_proxy` 与 `NetworkPolicy::route` 在 `SystemProxy` 模式下拼出 `http://http://127.0.0.1:7890` 导致下载必败的问题，同时统一启用 `max_idle_connections(0)` 与分段连接/读取超时，消除代理连接池陈旧复用导致的 `UnexpectedEof` 报错。

### 本机检测、接入识别与守护编排全面加固

- **本机客户端、CLI 与插件跨工具链精准识别（`cg-platform::process_win`）**：
  - 修复 Microsoft Store `OpenAI.ChatGPT-Desktop_` 包名前缀漏检与活动 `ChatGPT Classic.exe` 被误判为孤儿进程清理的问题。
  - 新增零依赖 ASAR 头部解析校验反重力汉化补丁（`Silas-02/antigravity-desktop-cn`）：避免 IDE 升级覆盖 `app.asar` 后因残留 `app.asar.bak` 误报已汉化，修正补丁时间读取自 `app.asar`，并实现本地日期版本（`YYYY.MM.DD`）与上游 SemVer 发布日期跨轨精准对比。
  - Session-0 服务态支持通过 `ProfileList` 与 `Uninstall` 注册表发现非 C 盘自定义安装目录及 Squirrel `AnthropicClaude`；扩展 `nvm`、`fnm`、`Volta`、`pnpm`、`bun`、`.npmrc`、Scoop、`.cargo/.crates2.json`（解决 Rust 版 `codex.exe` 无 PE 版本资源问题）与 `.vsix` 扩展目录扫描。
- **接入路径、TUN 与直连雷达精准度加固（`access_win` / `netwatch_win` / `mihomo_win` / `envcheck`）**：
  - 支持 Entra ID / Azure AD 账户（`S-1-12-1-*`）及 RDP 活动会话注册表读取；修复 `Tailscale` / `ZeroTier` / `EasyTier` Wintun 描述误判为全局 TUN 的问题；过滤闲置 TAP 网卡 APIPA 地址与陈旧未启用的 `AutoConfigURL`；扩充 `sing-tun`、`flclash`、`nekobox`、`karing`、`hiddify`、`sparkle` 等主流 TUN 关键字。
  - 修复 `enforce_access_path = false` 时忽略已检测到的 TUN / 自定义系统代理端口而强绑 `7890` 的问题；修复监控循环忽略 `leak_watch` 开关、代理+TUN 双开误报直连、自定义代理端口未计入代理连接及 `28.0.0.0/8` / IPv6 Fake-IP 识别；修复跨境 Anycast `colo` 导致的环境区域误报与 Mihomo `"Taiwan"` 误命中 `"ai"` 分组问题。
- **飞书通知与前端 IPC 交互优化（`feishu` / `cg-gui`）**：
  - 飞书发送队列增加互斥防重入锁与按到期项扫描（消除重复发卡与队头阻塞），新增 `open.larkoffice.com` 支持与 `19021`/`19022`/`19024`/`19025` 中文排障提示。
  - 前端 Named Pipe 升级为 `FILE_FLAG_OVERLAPPED` 按请求独立超时，超时不再误判守护离线；更新页与插件弹窗改为按单组件独立忙碌态，不再检查单项时冻结全局按钮。

## [4.1.1] - 2026-11-24

**防误杀熔断优化版**：彻底修复代理网络波动导致反重力 IDE 被频繁强杀（看似“一直崩溃”）的问题，新增「出口 IP 不变时不熔断」与「仅监测不熔断」双开关，并在探测层加入瞬时抖动单次短重试。

### 修复与熔断逻辑升级

- **彻底消除反重力出口网络抖动误熔断**：
  - `cg-core::policy` 将 `AnchorKind::Reachability`（反重力后端连通探测 `cloudcode-pa.googleapis.com`）的传输层超时/不可达判定由 `Fail` 修正为 `Unverified`（`经代理暂不可达`），与其他出口目标保持同一安全契约：启动门禁与 Flow A 恢复依然严格拦截，但代理偶发波动不再累计 `fail_streak` 强杀正在运行的 `Antigravity.exe` 及其他受管应用。
  - 修正熔断原因文案，准确区分 `出口不在白名单` 与 `经代理不可达`，不再将连通失败误报为白名单越界。
- **新增「出口 IP 不变时不熔断」（`suppress_trip_when_ip_unchanged`，默认开启）**：
  - `GuardEngine` 在当前配置代次下自动维护各目标最近一次已核验合规（`Pass`）的出口 IP 基线（修改白名单/策略、撤防、熔断或重布防时自动清空）。
  - 当代理链路完好且本轮探测未出现任何偏离合规基线的新 IP（例如同一合规 IP 偶发 GeoIP/CDN 地区抖动或无 IP 目标波动）时，仅记录去重告警并保持启动门禁拦截，不再误触发熔断杀进程。
  - **绝不妥协安全底线**：从未通过合规校验的违规/直连 IP、探测到新 IP 越界、或代理/TUN 失效（`access_uncovered`）时，依然严格照常熔断。
- **新增「仅监测不熔断」一键开关（`monitor_only`，默认关闭）**：
  - 位于「熔断 → 策略与开关」页（与「出口 IP 不变时不熔断」并排，升级为对称 4×2 共 8 项规则），开启后保持只读巡检、时间轴记录、告警通知与启动门禁，但跳过所有自动熔断、自动进程终止与自动兜底封锁（手动紧急封锁仍可用），并在总览主状态卡清晰标注当前处于「仅监测模式」。
- **代理探测瞬时抖动吸收**：
  - `cg-daemon::PlatformProbeRunner` 在严格复用同一 `ProbeRoute`（绝不直连回退）的前提下，对快速发生的瞬时传输错误执行 1 次 350ms 短重试，吸收单包抖动减少界面闪黄。

## [4.1.0] - 2026-11-22

**原生 GPUI 精雕重塑版**：全面升级透明蓝宝石折纸晶盾图标体系、5 套高级主题 × 明暗自适应、120Hz 零重排 GPU 动效引擎、Windows 11 原生 DWM 丝滑窗口过渡与全界面精炼中文文案，并同步修复防漏护盾即时同步与反重力可选核验模式告警噪音。

### 新增与视觉精雕

- **全新透明蓝宝石折纸晶盾图标体系**：
  - 统一重绘 `assets/claude.ico`（6 尺寸 16–256px 全层级）、应用内品牌图标（含全套暗色主题高对比变体）与 UI 矢量图标；`cg-gui/build.rs` 通过 Windows SDK `rc.exe` 无冲突嵌入 `RT_GROUP_ICON #1` 与 `VERSIONINFO` 版本信息，并在 `make-release.ps1` 加入 PE 图标、`ProductVersion` 与 `asInvoker` 清单自动核验。
  - 重制系统托盘满幅高精折纸盾（64×64 紧裁母版 + 2×2 超采样双线性缩放 + 右下角珍珠描边状态宝石），高 DPI 托盘清晰饱满不显小。
- **5 套优雅色彩主题 × 浅色 / 暗夜 / 自动**：
  - 顶栏新增主题风格气泡并持久化至 `%LOCALAPPDATA%\ClaudeGuard\ui_style.json`：默认「琉璃冰晶（CrystalGlass）」、以及「线性星靛（LinearIndigo）」「莫兰迪雾（MinimalMist）」「深海蓝宝（AlpineSapphire）」「曜石极黑（ObsidianInk）」，统一保留高级纯净白与冷瓷灰画布底色。
- **120Hz 零重排 GPU 动效与 Windows 11 原生 DWM 丝滑过渡**：
  - 全新 `motion.rs` 临界阻尼弹簧引擎（`ζ = 1.0`，零回弹、零首帧时钟跳变、零拖尾爬行），配合自定义 `OffsetPane`（纯 GPU 偏移零 Taffy 重排）与 `BloomCard`（冻结布局尺寸 + 直接 GPU 绘制对称卡片舒展），实现主界面纯水平切换与逐卡轻盈舒展，消除高刷卡顿与空闲态 30fps 冗余重绘。
  - 修复 Windows 11 无边框窗口最小化/最大化/还原生硬跳变：通过 `WS_CAPTION` + `DWMWA_TRANSITIONS_FORCEDISABLED = 0` + `WM_SYSCOMMAND` 原生路由恢复系统级丝滑缩入任务栏动画，同时完整支持 Win11 Snap Layouts 与深色标题栏同步。
- **全界面文案精炼与细节打磨**：
  - 对 7 大主页面、子标签、托盘 HUD、首启向导、Antigravity 插件弹窗及输入占位提示逐条提炼，大幅压缩冗余长句同时完整保留操作含义；修复「目标」页底部说明裁切与「审计」页搜索框提示截断，并简化「更新」页嵌套网络报错文案。

### 修复与工程优化

- **4 维防漏护盾开关即时同步与可测试性增强**：`cg-daemon` 在保存防漏护盾开关变更时自动触发 OS 防火墙规则同步，避免开关已改但护盾仍滞留「待同步」状态，并补齐单元测试覆盖。
- **反重力透明代理可选核验模式降噪**：当关闭「反重力注入强制核验」（`require_antigravity_proxy = false`）时，不再反复弹出 `MissingDll` / `RuntimeUnhooked` 告警噪音；强制核验拦截提示明确指引 `antigravity-launcher` / TUN / 自定义代理用户的开关路径。
- **CLI 安全工作目录启动与本地时区轨迹投影**：优化 `cg-gui` 安全启动台 CLI 启动目录解析与 24 小时合规轨迹的本地时区对齐。
- **发布脚本跨机兼容**：`make-release.ps1` 自动探测本机 `PATH` 及常见用户/系统目录下的 Inno Setup 6（`ISCC.exe`），不再强绑定单一开发机绝对路径。

## [4.0.1] - 2026-11-21

### 修复

- **首启向导「一键保存并立即布防」校验失败并反复重弹**：
  - `cg-gui` 的 `build_onboarding_config` 补齐默认内置目标 `local`（本机出口）白名单并同步解析代理主机与端口，使用 `clean_guarded_agents` 清洗受管目标。
  - `cg-core` 的 `targets::validate` 改为仅对已启用（`enabled = true`）的非可达性目标强制要求白名单非空，与目标页前端校验一致。
  - 弹窗提交期间保持打开并显示「保存并布防中…」，等待守护确认进入 `Armed` 后再关闭，避免 1 秒轮询竞态重弹；若保存或探测失败则在弹窗内直接展示错误条，不再被遮罩遮挡。
- **脱敏诊断包 `snapshot_redacted.json` 原始 IP 泄露**：
  - `cg-core::redact::mask_snapshot` 与 `cg-daemon::diagnostics` 补全对 `config.targets[].expect_ips`、`targets[].expect_ips`、`targets[].matched_rule`、`tripped.expected_summary`、`launch_error` 与 `recent_toasts` 的打码/脱敏，确保导出压缩包中所有文件均不含原始外网 IP。
- **`v3 -> v4` 非提权升级引导残留旧版文件与暂存缓存**：
  - `cg-v3-bridge` 改用 `ShellExecuteExW`（`SEE_MASK_NOCLOSEPROCESS`）+ `WaitForSingleObject` 等待提权安装器退出并检查退出码，安装完成后自动清理旧版 `%LOCALAPPDATA%\Programs\ClaudeGuard\ClaudeGuard.exe`、`.exe.old`、旧版用户桌面/开始菜单快捷方式及 `%ProgramData%\ClaudeGuard\staging\` 暂存文件。

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

[4.1.2]: https://github.com/daha1216/ClaudeGuard/releases/tag/v4.1.2
[4.1.1]: https://github.com/daha1216/ClaudeGuard/releases/tag/v4.1.1
[4.1.0]: https://github.com/daha1216/ClaudeGuard/releases/tag/v4.1.0
[4.0.1]: https://github.com/daha1216/ClaudeGuard/releases/tag/v4.0.1
[4.0.0]: https://github.com/daha1216/ClaudeGuard/releases/tag/v4.0.0
[3.12.5]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.5
[3.12.4]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.4
