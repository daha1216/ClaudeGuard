# ClaudeGuard v3.0.0 重构规范（SPEC）

> 2026-10-20 需求定稿。本文件是 v3 的唯一实现依据；与 `PARITY-v2.md` / `v2-spec.md` 冲突时以本文件为准。
> 仓库 `D:\ClaudeGuard`，分支 `v3`（master 保持 v2.11.0 到发版）。Tauri 2 + 纯静态前端（零 node 构建），Inno AppId 不变。

## 0. 范围与不变项

**保留（功能不缩水）**：出口门禁、托盘常驻、首启向导、开机自启、熔断（杀进程 + 分 agent 防火墙）、多 agent 守护、CLI 仅提醒、飞书通知、Claude/Codex 客户端更新、自身更新、`--check` JSON、单实例、Inno 安装器（AppId `{F5110E67-B6E3-4B59-B8BE-7F12B33EF85E}`，数据目录 `%APPDATA%\ClaudeGuard`）。

**v3 新增**：①监控目标模型（每目标独立锚点与期望值，可增删改）；②三类锚点（Cloudflare trace / 页面地区标记 / 仅可达性）；③断网两档（默认防火墙全局出站阻断，可选禁用物理网卡）；④桌面通知五类；⑤"解除隔离并恢复网络"与启动自愈；⑥`--restore` 急救。

**移除**：`launch_on_pass`（v1 起即死配置）、`connect_target`/`app_id` 落盘字段、`tcp_table.rs` 兜底探测（由锚点模型取代）。**移植**：`feishu.rs`、`update.rs`、`claude_update.rs`、`claude_package.ps1`、`install.rs` 基本原样（只改接口适配）。

## 1. 术语与数据模型（`src/model.rs` 为唯一真源）

- **目标 Target**：一个被监控的出口链路 = 名称 + 探测锚点 + 期望值 + 校验方式。
- **锚点 AnchorKind**：`auto`（自动识别响应格式）/`trace`（Cloudflare trace 文本）/`json_ip`（JSON 含 ip/country）/`gemini_region`（Gemini 页面 `,2,1,200,"XXX"` 地区标记）/`reachability`（任何 HTTP 响应即算可达）。
- **探测结果 ProbeResult**：`reachable,status,ip,country,raw_region,colo,city,latency_ms,parsed_as,detail`。`country` 一律归一为 ISO alpha-2（Gemini 的 USA→US）。
- **目标状态 TargetStatus**：`state ∈ pending|checking|pass|fail|unverified|disabled`，叠加 `ip/country/raw_region/colo/latency_ms/checked_at/reason/fail_streak`。
- **整体状态**：`idle|checking|pass|fail|tripped|paused`。
- **熔断 TripInfo**：`since,reason,failing_ids,killed,firewall_rules,network_cut(off|firewall|nics),quarantined_agents,agents`。
- **配置 Config**（`config.json`，snake_case）：
  `version=3, proxy_host, proxy_port, targets[], check_interval_secs(默认15,5..3600), trip_threshold(默认2,1..5), enforce_access_path(默认true,详见§3.5), lockdown_on_uncovered(默认true,详见§3.6), cut_network(默认true), disable_network_adapters(默认false), kill_on_fail(默认true), quarantine_on_fail(默认true), guarded_agents(默认["claude"]), cli_warn(默认true), sweep_on_exit(默认true), close_to_tray(默认true), auto_start_with_system(默认false), notify{enabled,trip,recover,launch_blocked,warning,client_update,self_update}(默认全true), auto_upd_check(默认true), first_run(默认true)`。
- **Target**：`id, name, builtin, enabled, anchor_url, anchor_kind, expect_ips[], expect_regions[], timeout_secs(默认12,3..60), bind_agent: Option<String>`。

**内置目标（4 个，`builtin=true`，可禁用不可删除）**：

| id | 名称 | 锚点 | kind | bind_agent | 期望 |
|---|---|---|---|---|---|
| `local` | 本机出口 | `https://cloudflare.com/cdn-cgi/trace` | auto | — | 迁移自 v2 白名单；**默认关闭**（常规流量出口通常与 AI 代理出口不同，默认开启会导致首次启动即熔断） |
| `claude` | Claude 出口 | `https://claude.ai/cdn-cgi/trace` | auto | claude | 迁移自 v2 白名单 |
| `codex` | Codex 出口 | `https://chatgpt.com/cdn-cgi/trace` | auto | chatgpt | 迁移自 v2 白名单 |
| `antigravity` | 反重力出口 | `https://cloudcode-pa.googleapis.com/` | reachability | antigravity | 无（只判可达） |

## 2. 锚点与解析（`src/anchors.rs`，纯解析函数必须可单测）

请求：ureq Agent，代理地址按 §3.5 接入判定解析（系统代理开→其实际地址；关+TUN→直连被 TUN 接管；未接入→**不探测**；读不到地址时回退 `http://{proxy_host}:{proxy_port}`），超时 `timeout_secs`，跟随重定向，UA `ClaudeGuard/3.0`。任何 HTTP 响应（含 4xx/5xx）都算"有响应"；网络错误/超时算不可达。国内直连 claude.ai 可达（Cloudflare 前端，未被封）——但守护器刻意不在未接入时直连探测（隐私语义见 §3.5），改用注册表/TUN 确定性判定。

`auto` 解析顺序（命中即停）：
1. **trace**：按行匹配 `ip=`、`loc=`、`colo=`；要求至少 `ip` 或 `loc` 之一。
2. **json_ip**：解析 JSON，依次取 `ip/ip_address/query/origin` 与 `country/country_code/loc/region`（顶层或 `data.` 子对象）。
3. **gemini_region**：正则 `,2,1,200,"([A-Z]{3})"`。给地区，不给 IP。
4. 以上都没有但有响应 → `reachability` 语义（只判可达）。
显式 kind 覆盖 auto：`reachability` 不看 body；其它按对应解析器，解析失败即 `unverified`（不熔断）。

地区归一：alpha-3→alpha-2 表（至少覆盖 USA/CHN/JPN/HKG/TWN/SGP/KOR/GBR/DEU/FRA/CAN/AUS/NLD/RUS 等常见项），大小写不敏感；无法归一保留原文并只做原样比较。

## 3. 判定策略（`src/policy.rs`，纯函数）

对每个启用目标：`evaluate(target, probe) -> (Verdict, reason)`；`Verdict ∈ Pass|Fail|Unverified|Disabled`。

| 情况 | 结果 |
|---|---|
| 目标禁用 | Disabled（不参与判定） |
| kind=reachability 且有 HTTP 响应 | Pass（"可达 · {ms}ms"） |
| kind=reachability 且无响应 | **Fail**（"不可达"） |
| 有 IP/地区但期望 ips+regions 皆空 | **Fail**（"未配置白名单，按宁可错杀处理"） |
| ip ∈ expect_ips 或 country ∈ expect_regions | Pass |
| 有 ip/country 但都不命中 | **Fail**（"出口 {ip}（{country}）不在白名单"） |
| 只有地区且地区命中 | Pass |
| 有 ip 不命中、地区无信息（期望里也没有地区） | **Fail** |
| 期望里有地区、country 缺失（只有 ip）且 ip 不命中 | Fail？→ **不**：保守按 Unverified（防误杀），reason "只有 IP，无法核对地区" |
| 无 ip 也无 country 但可达（锚点不是 reachability） | Unverified（不熔断） |
| 网络错误/超时（无响应） | Unverified（不熔断） |

**整体判定**：任一启用目标 Fail → 整体失败（触发防抖计数）；全部 Pass → 通过；有 Unverified 其余非 Fail → "部分无法确认"（不算失败，也不能解除已熔断状态）。

### 3.5 接入路径检查（`src/access.rs`，v3.7 起，仅 Windows）

Claude 等桌面应用只认系统代理——系统代理没开时它们直连真实出口，守护器测代理出口测得再准也管不到应用本体。v3.7 做了两件事：**探测流量跟随系统代理**（测到的就是应用真实出口，换了端口/换了代理软件也成立），并额外判定**应用接入方式**：

| 系统代理开关 | ProxyServer | TUN 网卡 | 判定 | 探测走哪 |
|---|---|---|---|---|
| 开 | 读到任意地址 | 任意 | **SystemProxy**（已接入） | 该地址（不管是否等于配置端口） |
| 开 | 读不到 | 任意 | SystemProxy（地址未知，按已接入） | 回退配置端口 |
| 关 | — | 检测到 | **Tun**（已接入，界面标注"TUN 直连"） | 直连（被 TUN 接管，与应用同路） |
| 关 | — | 无 | **Uncovered**（应用直连真实出口） | **不探测**（守护器自身不直连；判定与熔断完全靠注册表/TUN 确定性检查） |

- 检测方式：`winreg` 读 `HKCU\...\Internet Settings` 的 `ProxyEnable`/`ProxyServer`（支持 `http=..;https=..` 分号形式，取 https 优先）；`GetAdaptersAddresses` 枚举 Up 状态适配器按描述/友好名匹配 TUN 关键词（mihomo/clash/meta/sing-box/singbox/wintun/wireguard/openvpn/tap-windows/tun2socks/bettbox/hysteria/juicity/v2ray/xray/utun 前缀；不含 tailscale——非默认全隧道）。`verdict()`/`parse_sys_proxyserver()`/`is_tun_name()` 为纯函数（单测覆盖），`read_system_proxy()`/`detect_tun_adapter()` 只做系统读取。
- 语义：Uncovered 按独立 `access_streak` 计数走同一 `trip_threshold` 防抖（阈值-1 时预警一次）；熔断动作与目标 Fail 完全一致（杀进程/隔离/断网档位），Launch 用途立即熔断；被跳过探测的目标标 Unverified（reason"未接入代理链路，已跳过探测"）；恢复条件额外要求 access 已重新覆盖（SystemProxy/Tun）。暂停同样压制 access 熔断。`enforce_access_path=false`（设置可关，此时未接入仍会直连探测）或非 Windows 时整段跳过。
- **隐私语义（v3.8）**：启用检查时，守护器自身流量在任何状态下都不带家宽 IP 出机器（探测只走代理或 TUN 接管的直连）；国内直连 claude.ai 本可测出家宽 IP，但守护器刻意不测，改用注册表/TUN 判定。
- `--check` JSON 增加 `access: {path, note}`；enforce 且 Uncovered → 整体不通过（exit 2）。设置页「检测」组有"接入路径检查"开关；未接入时主界面横幅+副标题提示。

### 3.6 防火墙兜底封锁（v3.9，Windows）

- 动机：未接入态（系统代理关+无 TUN）下应用直连真实出口；TUN 模式又不能拦（覆盖一切流量）。防火墙 Block 规则按 exe 生效且回环（127.0.0.1 系统代理）不受 Windows 防火墙过滤——正好实现"没连代理就出不去、连了照常走"。
- 语义：每轮监控按接入状态同步封锁意图——`未接入 && lockdown_on_uncovered` → 维持"每守护对象一组出站 Block 规则"（`ClaudeGuard Lockdown ({id})`，按 `agent_exes` 全 exe）；已接入（SystemProxy/Tun）或该开关关 → 全部解除。意图不变不重复增删（`state.sync_lockdown` 按上次意图差分；启动首轮强制对齐，顺带清理崩溃残留）。手动 `lockdown(on)` IPC 立即生效，下一轮自动逻辑按接入状态接管。
- 前置：`fw_ensure_on()`——防火墙整体关着时 Block 规则不生效（实测踩过：用户机器三 profile 全 Off，隔离规则从未真正执行）；因此 trip() 隔离前与 lockdown 前都会确保开启（只开不关，默认出站=允许，不影响正常流量）。
- 边界：按 exe 封锁=应用全部域名（Windows 防火墙无域名字段）；CLI 跑在 node 宿主不能拦（与熔断隔离同边界）；退出程序时 `lockdown_clear()` 只删规则不动防火墙总开关。
- UI：未接入横幅/副标题在封锁生效时注明"已启用防火墙兜底封锁"；设置「熔断与清理」组新增"防火墙兜底封锁"子节（自动开关+一键封锁/解除按钮）；`StateView.lockdown` 暴露当前意图。

## 4. 监控循环与防抖（`src/monitor.rs`）

- 启动 1s 后首轮；300ms tick；每 `check_interval_secs` 且非 busy 跑一轮；间隔实时读配置。
- 一轮 = 并行探测所有启用目标（`std::thread::scope`），逐一判定，更新 TargetStatus；记录 `checked_at`。
- **防抖**：每个目标维护 `fail_streak`；Fail → +1，非 Fail → 清零。`max(fail_streak) >= trip_threshold` 且未 tripped 且未暂停 → 执行熔断；`fail_streak == trip_threshold - 1` 且通知开启 → 预警通知一次（每个目标每轮触发状态变化时最多一次）。
- **熔断执行**（`monitor` 调 `guard::trip` + `netcut::cut`）：失败目标名并入 reason；结束 `guarded_agents` 全部 GUI 进程；按开关加隔离防火墙；按档位断网；桌面通知 + 飞书；写 TripInfo；`trip()` 成功则 state=tripped。
- **已熔断期间**：每轮仍探测；仍有 Fail → 再次 kill（日志"持续异常：再次结束 N 个进程"）；**恢复条件**：无 Fail 且至少 1 个 Pass → `netcut::restore` + 解除隔离 + 清零 streaks + 通知恢复；若全部 Unverified → 保持 tripped（横幅"等待确认出口"）。
- **暂停**：`paused_until` 期间照常检查与更新状态，但不 engage/kill/断网；到点自动恢复；托盘可提前恢复。
- **启动门禁**：`launch()` 走 `run_check(Purpose::Launch)`，要求所有启用目标 Pass；否则阻止启动 + 桌面通知（launch_blocked）+ 记录 `launch_error`；Fail 时同样执行熔断（与 v2 一致）。启动成功后 `close_to_tray` 则收托盘。
- **手动解除**：`release()` = `netcut::restore` + 解除隔离 + 清 tripped + 清 streaks + 日志；不清用户配置。

## 5. 熔断执行与断网（`src/guard.rs`、`src/netcut.rs`）

`guard.rs`（移植 v2 语义）：GUI agents = claude / chatgpt / antigravity（fingerprint 不变；claude 指纹排除 CLI 原生二进制路径 `\claude\claude-code\` 与 `\.local\bin\claude`）；CLI agents = claude-code（指纹含 npm js、`\.local\bin\claude`、新安装布局 `%APPDATA%\Claude\claude-code\<ver>\<hash>\claude.exe`）/ codex / gemini。v3.2 起 Claude 是守护对象时熔断连 Claude Code CLI 一并结束（codex/gemini 仍只提醒）；`trip()` 结束进程 + 按 agent 加防火墙（claude 沿用旧规则名 `ClaudeGuard Block Out/In`，其他带 agent 后缀）。

Claude 进程清理引擎（v3.2）：`ProcInfo` 快照 + 纯函数判定（`classify_claude` 桌面/CLI 二分、`pick_manual` 全量、`pick_residual` 残留=桌面家族全部 + 孤儿 CLI【父进程已死】，桌面端仍在运行时返回 None 不清理）；`sweep_claude(mode)` 三态 Manual（一键全清）/ CliOnly（熔断路径）/ Residual（退出后清理）返回 `SweepReport{scanned,killed,desktopKilled,cliKilled,detail[],note}`。残留监视线程（`monitor.rs::spawn_sweeper`）：2 秒一拍盯桌面端在否，消失后宽限 4 秒复查（自动更新/快速重启自救）再清残留；`sweep_on_exit=false`、未守护 claude、暂停守护时不动作。

防火墙兜底封锁（v3.9，详见 §3.6）：`fw_ensure_on()`/`lockdown_apply(cfg)`/`lockdown_clear()`；trip() 隔离前确保防火墙开启；退出时清兜底规则。

`log_line` 写 `%APPDATA%\ClaudeGuard\guard.log`（>1MB 原子裁剪保留约 400KB，行边界）；`version_key`、`find_windowsapps_dir`、`find_claude_dir`、`find_chatgpt_dir`、`resolve_app_id`、`launch_claude`、`is_admin`、`firewall_dedupe`。

`netcut.rs`（新增）：
- 档位：`off`（cut_network=false）/`firewall`（默认）/`nics`（disable_network_adapters=true 时，额外禁用物理网卡）。
- firewall 档：`netsh advfirewall firewall add rule name="ClaudeGuard Cut All" dir=out action=block profile=any enable=yes`；恢复删除同名规则。
- nics 档：`powershell.exe -NoProfile -Command "Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name | ConvertTo-Json"` 枚举启用中的物理网卡 → 逐个 `Disable-NetAdapter -Name ... -Confirm:$false`；恢复 `Enable-NetAdapter`。用 cmdlet 名避免本地化文本解析。
- 断网状态持久化 `%APPDATA%\ClaudeGuard\netcut.json`（`{mode,firewall,nics,since}`）。
- 恢复：删规则 + 重新启用记录在案的网卡 + 删持久化文件。
- 自愈：启动时若存在 `netcut.json` → 恢复并日志"检测到上次熔断残留，已恢复网络"；若存在 `ClaudeGuard Cut All` 规则而无状态文件 → 删除；清理旧版重复规则（同名多份只留一份，或全部删除由 v3 重加）。
- 退出：真退出前必须 `netcut::restore`（网络绝不能因程序退出保持断开）；隔离规则是否保留：v3 一并解除（比 v2 更干净，AGENTS 记录）。
- `--restore` CLI：执行恢复并输出 JSON，退出码 0。

## 6. 桌面通知（`src/notify.rs`，powershell.exe + WinRT Toast，无第三方 crate）

六类（均受 `notify.*` 开关与总开关控制；发送失败只写日志不 panic；发送在后台线程，最多阻塞 15 秒）：

**身份登记（必须）**：`CreateToastNotifier('ClaudeGuard')` 要求该 AUMID 已在
`HKCU\Software\Classes\AppUserModelId\ClaudeGuard` 登记（DisplayName / IconUri = 当前 exe）。
未登记时 `Show()` 既不抛错也不投递——即“通知不生效”。`notify::ensure_identity()` 在启动时与每次发送前幂等补登记，安装版与便携版同样生效。

1. `trip`："ClaudeGuard 已熔断" / "{失败目标名} 出口不符合白名单，已结束相关应用并切断网络。修正后自动恢复。"
2. `recover`："ClaudeGuard 已恢复" / "出口检查通过，已解除隔离并恢复网络。"
3. `launch_blocked`："ClaudeGuard 已阻止启动" / reason。
4. `warning`："ClaudeGuard 检查未通过" / "第 {n} 次连续失败，再失败一次将熔断。"
5. `client_update`：来自客户端更新模块（"Claude 有新版本 {ver}" / "ChatGPT 更新已安装"）。
6. `self_update`："ClaudeGuard 有新版本" / "v{ver} 已发布，打开 设置 → 更新 一键升级。"（由 `update::spawn_periodic_check` 静默检查触发；同一版本跨重启只提醒一次，去重记录 `%APPDATA%\ClaudeGuard\upd-notify.json`。）

**自身更新静默检查**：`update::spawn_periodic_check`（GUI 启动即开，`auto_upd_check` 配置门控）——启动 90 秒后首查、每 6 小时一轮，与手动检查共用 `check_latest`；静默模式不打 `Checking` 状态、失败不写 `Failed` 只记日志；发现新版本写 `Available` 并弹 `self_update` 通知。调试用 `CG_UPD_FIRST_DELAY_MS` / `CG_UPD_INTERVAL_MS` 覆盖周期（最小 100ms）。

飞书（移植 `feishu.rs`）：trip / recover 事件照发；队列、签名、DPAPI 凭据、去重、手动补发语义不变。

## 7. 模块结构与接口契约

```
src/main.rs        CLI 解析、单实例、窗口/托盘装配、启动 self-heal、监控线程
src/state.rs       AppState：cfg Mutex、statuses、tripped、pause、log 环(200)、upd、feishu/claude-codex 状态；log() 落盘+事件；guard://state / guard://log 事件
src/model.rs       Target/AnchorKind/ProbeResult/TargetStatus/Verdict/TripInfo/StateView/UpdState
src/config.rs      Config load/save(原子)/migrate(v2→v3)/validate
src/targets.rs     内置默认目标、校验(normalize)、CRUD(保存整表)、恢复默认
src/anchors.rs     探测执行 + 解析器（纯函数可测）
src/policy.rs      判定矩阵（纯函数可测）
src/monitor.rs     调度、fail_streak、trip/recover 编排、launch 门禁、暂停
src/guard.rs       进程扫描/结束、防火墙、日志、路径与版本工具（移植 v2）
src/netcut.rs      断网两档 + 恢复 + 自愈 + 规则去重
src/notify.rs      桌面通知五类
src/feishu.rs      飞书通知（移植）
src/update.rs      自身更新（移植）
src/claude_update.rs Claude/Codex 客户端更新（移植，含 src/claude_package.ps1）
src/install.rs     安装/自启（移植）
src/macos/         macOS 移植预览（PR #2，cfg(target_os="macos")；进程守护模式，不防火墙/不断网）——详见 docs/MACOS.md
src/ipc.rs         #[tauri::command]
ui/index.html|app.css|main.js|ipc.js|icons.js|settings.js|updates.js|feishu.js
```

**IPC 命令**（`invoke('cmd', {args})`，Tauri 2 snake_case↔camelCase 自动映射）：
`get_state`、`get_config`、`update_settings(patch)`、`save_targets(targets)`、`reset_targets`、`recheck`、`launch`、`recheck_target(id)`、`release`、`pause`、`resume`、`sweep_claude`（一键清理，返回 SweepReport）、`lockdown(on)`（v3.9 一键防火墙兜底封锁/解除，返回 bool）、`recent_logs(limit)`、`open_data_folder`、`install_app`、`set_autostart(on)`、`upd_state`、`upd_check`、`upd_download`、`feishu_status`、`feishu_save(cfgJson)`、`feishu_test`、`feishu_retry_failed`、`claude_update_status`、`claude_update_configure(json)`、`claude_update_check`、`codex_update_status`、`codex_update_configure(json)`、`codex_update_check`、`js_log(level,msg)`、`notify_test(kind)`。
**事件**：`guard://state`（StateView）、`guard://log`（单行）。

**StateView（camelCase）**：`checking,checkedAt,intervalSecs,tripThreshold,overall,targets[TargetStatus],tripped, pausedUntil,admin,installed,version,upd,feishu,claudeUpdate,codexUpdate,agentsRunning[{id,name,count}],cliRunning[],guardedAgents[],launchError,smokeSettings,notifyEnabled,cutMode`。

## 8. UI 规格（初版方向 A·极简仪表盘；设计稿为唯一视觉基准）

- 窗口 420 × clamp(工作区逻辑高−8, 420, 620)，min 400×420；`decorations:false`，`data-tauri-drag-region`；标题栏 44px 毛玻璃、左侧纯文字 `ClaudeGuard`（13px/600，无图标）、右侧仅最小化/关闭；边缘八向缩放（tao 自带）。
- 结构（自上而下，主区可滚动，footer sticky）：hero（128px 环、stroke 5.6、平色 #03AA49/#E4002B/灰，中心勾/叉/暂停/spinner；h1 22px/600；sub 12px #86868B；不再有 meta 行）→ 目标列表卡（圆角 14、白 88% + blur 20px、行高 54px（熔断/暂停压缩为 50px）、分隔 hairline；每行：状态点 + 左列（名称 13px/600 + 地区/组说明 11px） + 右列（IP 12.5px 等宽 tabular + 延迟 10.5px））→ 横幅区（仅熔断红/暂停灰/未通过橙/启动失败橙；CLI 运行提醒只在详情卡与日志，不占首屏）→ CTA（全宽 46px 渐变蓝主按钮：启动 Claude / 重新检查 / 启动已禁止；下方一行文字链接：立即检测（熔断态变红色「解除隔离并恢复网络」）+ 清理 Claude 进程（v3.4 起常驻，两段确认：首击 3.2s 内变红「确认结束全部 Claude 进程？」，再击执行 sweep_claude，防误触））→ 详情卡（默认收起：每目标一行的判定步骤、锚点 host、延迟、原因、运行中进程）→ 设置卡（默认收起；展开后为**折叠手风琴，同一时间只展开一组**，组头含动态摘要（端口/间隔、断网档位、守护对象名、目标启用数、通知开关）与旋转箭头，默认展开「检测」；组=检测（端口/间隔/立即检查）、熔断与清理（断网档位/停进程/隔离 + 进程清理子节=退出清扫开关；一键清理在主界面 CTA 旁 + **防火墙兜底封锁子节**=未接入自动封锁开关+一键封锁/解除按钮）、守护对象、监控目标（列表编辑+添加+恢复默认）、通知（六开关+测试）、飞书通知、通用（关窗驻留/开机自启/数据文件夹/用户指南）、更新（自身+Claude 客户端+Codex 客户端三子节））→ 日志卡（默认收起，11px mono）→ footer（左：详情/设置/日志 链接；右：`vX.Y.Z`）。
- 状态语义：环/标题跟随 overall；busy 只在手动检查/首查转圈（后台刷新不动环）；目标行四态点：绿/红/橙（unverified）/灰（disabled）；熔断态红色横幅 + 置灰 CTA + 解除隔离按钮。
- 动效红线（沿用 v2 标准）：只动 transform/opacity；无 transition:all/ease-in/scale(0)；按压 :active scale(0.97)；入场 scale(0.95)+opacity；≤300ms；stagger 30–80ms；reduced-motion → 交叉淡入；reduced-transparency → 实底；hover 包 `@media(hover:hover) and (pointer:fine)`。所有 JS 文件 IIFE 包裹（跨文件只经 `window.CG_IPC`/`window.ICONS`/`window.CG_UI`）。
- 首启向导 3 页（沿用 v2 文案结构）：页 0 欢迎；页 1 代理端口 + 白名单 IP（逗号分隔）+ 出口地区（写入 local/claude/codex 三个目标的 expect）；页 2 安装 vs 便携。向导期间监测照跑。
- 测试钩子：`CG_SMOKE_STATE=pass|fail|trip|paused` 造界面状态且不启动探测线程；`CG_WIN_H` 覆盖窗高；`--settings` 启动即展开设置卡（截图用；`CG_SMOKE_SETTINGS=1` 仅置 StateView 标记）。
- 托盘菜单：显示主窗口 / 立即检测 / 暂停守护 30 分钟（恢复守护）/ 解除隔离并恢复网络 / 打开数据文件夹 / 退出；tooltip `ClaudeGuard`。

## 9. 配置迁移（`config.rs::migrate`）

v2 字段 → v3：
- `allowed_ips` + `egress_region`（含 legacy `required_ip`）→ 迁移时作为 `expect_ips/expect_regions` 写入 `local`、`claude`、`codex` 三个内置目标（若用户 v2 白名单为空则保持空，语义"宁可错杀"不变）。
- `guarded_agents` 清洗规则沿用 v2（去重、剔除未知 id、全垃圾回填 claude、显式空尊重）。
- `cli_warn`、`check_interval_secs`、`kill_on_fail`、`quarantine_on_fail`、`close_to_tray`、`auto_start_with_system`、`first_run`、`proxy_host/port` 原样迁移。
- 丢弃 `connect_target`、`app_id`、`launch_on_pass`、`required_ip`（迁移后不落盘）。
- 迁移后立即落盘（v2 行为）；损坏/非法 JSON → 用默认值但先备份为 `config.json.bak-{ts}` 并日志告警。

## 10. CLI

`--check`（JSON stdout，退出码 0 通过 / 2 未通过；含每目标结果）、`--restore`（恢复网络与隔离，JSON，退出 0）、`--settings`（唤起窗口并展开设置）、`--tray`（隐藏启动）、`--install`、`--uninstall`、`--feishu-status`、`--claude-update-status`、`--codex-update-status`、`--update-selftest`、`--notify-test <kind>`。无 flag = GUI。单实例：二次启动唤起主窗口。

## 11. 测试计划（目标 ≥50 个）

- anchors：trace/json/gemini/auto 判定与边界（无字段、坏 JSON、超大 body 截断、alpha3 归一）≈12
- policy：矩阵全表 + 期望空/单 IP/多 IP/地区/地区+IP/Unverified 各态 ≈12
- targets：默认表、校验（URL/超时/IP/重复 id/内置禁删/地区归一/非法输入拒绝）≈8
- config：v2→v3 迁移（required_ip、多 IP、空名单、脏 guarded_agents、损坏 JSON）≈8
- monitor：fail_streak 防抖与恢复判定、tripped 期间重复 kill 决策（纯逻辑抽出可测）≈6
- guard：指纹/规则名/version_key/裁剪 ≈6；netcut：规则名/网卡 JSON 解析/状态持久化 ≈4
- 移植模块保留原 28 测试（feishu 10 / claude_update 18）。

## 12. 质量门与发版

本地门禁（CI 保持停用，用户明确要求才开）：`cargo fmt`、`cargo clippy --locked -- -D warnings`、`cargo test --locked`、`node --check ui/*.js`、`cargo build` debug + CDP 冒烟（`CG_SMOKE_SETTINGS`、`--check`、`--notify-test`、托盘/事件）、截图核验（正常态/熔断态/设置卡，gemini 视觉复核）。

发版：Cargo.toml `3.0.0` + Cargo.lock 重生（`cargo build --offline`）→ commit/push `v3` → 合并 master（fast-forward）→ tag `v3.0.0` → `make-release.ps1` → GitHub release（先 exe、再 zip、再 setup）→ 本机静默升级（先结束 v2.10.1 驻留进程）→ RunAs 重启 v3 → 交付报告。README/AGENTS/GUIDE 同步到 v3 事实版。

## 13. 非目标

- 不做代理控制器/端口联动（不读 mihomo API、不改用户分流脚本）。
- 不做域名级拦截（熔断按进程 + 网络档位）。
- 不做云同步/账号体系；不做自动启动 Claude（`launch_on_pass` 已移除）。
