# ClaudeGuard v3.10 修复契约（M0 冻结）

> **状态：已批准（2026-10-24）。** 本文件是修复主线 R 的唯一实现依据；本文件未覆盖的语义沿用 `docs/SPEC-v3.md`，两者冲突时以本文件为准。
> 基线：v3.9.0，提交 `7e5c75c76453d21f24f66f75fa6b0ea8165ed371`。规划：`docs/REPAIR-PLAN-v3.9.0.md`。审查：`target/AUDIT-v3.9.0-20261024.md`。
> M0 只冻结契约，不含实现。实现按 M1–M5 分批，每批先提交能暴露原问题的失败用例。

## 0. 批准记录

- **D1–D7 按推荐方案批准生效**；D8（连接级强约束）不启动，单独立项，未纳入本主线。
- 修复范围：R01–R17（见 §5）。S 路线不在本次交付内，也不作为发布卖点。
- 版本：修复主线完成后默认 **v3.10.0**（默认策略、权限流程、UI 状态均有变化）。仅当最终范围收敛为纯确定性修补时才发 v3.9.x；不提前打 tag。

## 1. 决策定稿（D1–D7）

### D1 默认隔离范围

- 新装默认：`kill_on_fail=true`、`quarantine_on_fail=true`、`cut_network=false`、`disable_network_adapters=false`。
- 熔断默认只做**应用级隔离**：结束受管 GUI 进程 + 每个 agent 的出/入站 Block 规则。全局断网仅在 `cut_network=true` 且 D2 能力就绪时执行。
- 旧配置迁移：首次 v3.10 启动读取旧配置 → 备份为 `config.v3.9.bak.json` → UI 展示迁移差异 → **不静默改档位**。若旧 `cut_network=true` 而恢复执行器未就绪：进入 `Degraded`，全局断网暂停并在界面写明原因，保留配置值由用户决定。
- 禁止以"更安全"为由擅自把应用级隔离升级为全局断网。

### D2 全局断网

- `cut_network` / `disable_network_adapters` 保留为高级应急能力。只有 R06 的独立恢复执行器就绪且自检通过，才允许新增该动作；未就绪时请求返回 `Blocked`/`Unsupported` 并在 UI 说明。
- 恢复网络与解除应用隔离分两步执行（§3.3 流程 A/B），不再承诺"联网探测可无条件自动解开全局断网"。
- 全局断网状态必须可被离线入口（`--restore`、卸载前阶段、独立执行器）完整恢复。

### D3 暂停、解除与退出

| 动作 | 停止新副作用 | 保留既有隔离 | 恢复本产品网络改动 | 之后 |
|---|---|---|---|---|
| 暂停（30 分钟） | 是（kill/清扫/断网/应用更新） | 是 | 否 | 到点恢复检查；**不自动解除隔离** |
| 解除隔离 `release` | 否（仍布防） | 清除 | 是 | 下一轮若仍 Fail 会再次隔离 |
| 关闭窗口到托盘 | 否 | 是 | 否 | 驻留 |
| 恢复并退出（正常退出） | 是 | 恢复前保留 | 是（流程 B） | **核验成功才退出**；失败保持运行并报错 |
| 强退/崩溃/断电 | 无退出代码 | 保持 | 否 | 账本 + 恢复执行器在下次启动处理，fail-closed |
| 卸载 | 是 | — | 是（流程 B） | 恢复失败禁止自删 |
| `--restore` 急救 | 是（通知存活实例停止重施规则） | 清除本产品资源 | 是 | 输出结构化分项结果；失败非零退出码 |

- 暂停不是保护状态，不改变 `Protection` 值；暂停期间不自动解除既有隔离（fail-closed）。
- 手动 `lockdown(on)` 意图有独立生命周期，不被下一轮自动逻辑覆盖（R13）。

### D4 信息不足

- `Unverified`：不计 `fail_streak`、不触发 kill、**禁止通过守护器启动**、不自动解除既有隔离。
- 已 tripped 且全部 `Unverified` → 保持 tripped，横幅"等待确认出口"。
- 严格模式（`Unverified` 即隔离）**不在本主线实现**，避免新增未经批准的策略。

### D5 外发策略

- 所有出网（探测、自身更新、客户端更新、飞书）统一经 `NetworkPolicy`：有代理配置时强制走代理；代理不可用 → 失败并如实报告，**禁止静默直连回退**。
- 通知正文默认脱敏：只含目标别名、状态、原因码、时间；不含 IP、地区、节点名、主机名、用户名。新增 `notify.include_egress`（默认 `false`），开启后才附带出口 IP/地区，且发送前可预览。
- 飞书队列中的历史消息迁移时不自动重发，保留为待确认状态。

### D6 自身更新

- 验签：清单 Ed25519 签名 + 清单绑定（产品/版本/平台/架构/渠道/制品类型/文件名/大小/SHA-256/发布序号/协议版本）+ Windows Authenticode 发布者校验。
- 首次信任根：安装器内嵌公钥 + 发布页公示指纹，用户可核对。信任根未就绪前：**只检查与提醒，不自动下载应用**。
- 保护中（`Isolating`/`Quarantined`/`GlobalCut`/`Recovering`/`Degraded`/存在未完成恢复事务/系统状态未知）禁止应用更新。
- 受控暂存目录 + 交接事务 + 认证 Ready 回执；`spawn` 成功不算升级成功。

### D7 权限

- 目标架构：**普通权限 UI + 窄接口高权限执行器**（优先同一签名二进制的 helper 角色）。
- 过渡期（M1–M3）：保持 `requireAdministrator`，但所有系统动作集中在 coordinator/platform 层；不新增通用命令执行接口；WebView 只提交结构化意图，不提交路径/PID/脚本/URL 作为执行参数。
- helper 拆分在 M4 实施；安装常驻服务或计划任务需用户单独授权。

## 2. 状态模型

### 2.1 生命周期 `Lifecycle`

| 值 | 含义 | 进入 | 允许 | 禁止 |
|---|---|---|---|---|
| `Unconfigured` | 首次运行或配置从未有效完成 | `first_run=true` 且未完成向导；或配置损坏且无可用备份 | 只读检测、向导、退出 | launch、kill、隔离、断网、lockdown |
| `Armed` | 已布防，正常守护 | 向导完成或旧配置迁移成功 | 全部守护动作 | — |
| `Maintenance` | 更新应用、卸载、恢复事务进行中 | 显式进入 | 事务内动作、恢复 | 新的自动 kill/断网；启动应用 |
| `Stopping` | 正在退出/卸载 | 正常退出或卸载开始 | 恢复、核验、退出 | 任何新的保护动作 |
| `Disarmed` | 用户显式停止保护但进程仍运行 | `set_protection(false)`、`--restore` 通知存活实例 | 检测、重新布防、退出 | kill、隔离、断网、launch |

- `Disarmed` 为最小新增界面能力：一个"停止保护/重新布防"动作 + 状态展示，用于让流程 B 在 GUI 存活时可解释，避免用户被困在无保护却显示"守护中"的状态。

### 2.2 保护状态 `Protection`

| 值 | 含义 |
|---|---|
| `Pending` | 已布防但尚未完成首轮检查 |
| `Monitoring` | 正常监控，无隔离 |
| `Isolating` | 正在执行隔离，尚未核验 |
| `Quarantined` | 应用级隔离已核验（规则 + 有效策略 + 对象清单） |
| `GlobalCut` | 全局断网已核验（在 `Quarantined` 基础上叠加） |
| `Recovering` | 恢复事务进行中 |
| `NetworkReadyAppHeld` | 网络已恢复、应用隔离仍保留（流程 A 中间态） |
| `Degraded` | 保护不完整或能力缺失，需用户处理 |

### 2.3 暂停

`paused_until: Option<Instant>` 与生命周期/保护状态正交。语义见 D3；暂停期间继续只读检查与状态更新，不新增副作用、不自动解除隔离。

### 2.4 合法组合

| 生命周期 | 允许的保护状态 |
|---|---|
| `Unconfigured` | `Pending`（仅表示未布防） |
| `Armed` | `Pending`、`Monitoring`、`Isolating`、`Quarantined`、`GlobalCut`、`Recovering`、`NetworkReadyAppHeld`、`Degraded` |
| `Maintenance` | `Recovering`、`Quarantined`、`GlobalCut`、`Degraded` |
| `Stopping` | `Recovering`、`Degraded` |
| `Disarmed` | `Monitoring`（无隔离）、`NetworkReadyAppHeld`（残留待恢复） |

非法组合必须由状态机测试拒绝，例如 `Unconfigured + Quarantined`、`Maintenance + Isolating`、`Stopping + Isolating`。

### 2.5 转移（关键路径）

| 从 | 到 | 触发 | 守卫 | 副作用 |
|---|---|---|---|---|
| `Armed/Pending` | `Monitoring` | 首轮检查完成 | 无 Fail | 更新状态 |
| `Monitoring` | `Isolating` | `max(fail_streak) >= trip_threshold` | 未暂停、非 `Maintenance` | 写账本 → kill → 规则 |
| `Isolating` | `Quarantined` | 规则与有效策略核验通过 | 对象清单非空 | 记录 `verified_at` |
| `Isolating` | `Degraded` | 核验失败/部分失败/权限拒绝 | — | 保留账本、告警 |
| `Quarantined` | `GlobalCut` | `cut_network` 且能力就绪且核验通过 | 非 `Maintenance` | 断网 + 核验 |
| `Quarantined/GlobalCut` | `NetworkReadyAppHeld` | 流程 A 第 1 段完成 | 应用隔离仍核验通过 | 恢复网络 |
| `NetworkReadyAppHeld` | `Monitoring` | 当前代次目标全 Pass 且策略允许 | 无 Fail、无 `Unverified` 阻断项 | 解除应用隔离 |
| `Quarantined/GlobalCut/NetworkReadyAppHeld` | `Monitoring`/`Disarmed` | `release` 或流程 B | 用户显式请求 | 清除隔离、恢复网络 |
| 任意 | `Degraded` | 恢复失败/账本损坏/查询失败 | — | 保留现场、提示 |
| `Armed` | `Maintenance` | 更新应用/卸载开始 | 用户确认 | 交接 |
| `Maintenance` | `Armed`/`Stopping` | 事务完成/失败 | 核验 | 记录结果 |

### 2.6 不变量

1. `ProtectionObserved = Verified` 只能来自**当前** `config_revision + runtime_epoch` 的后置核验。
2. 存在隔离意图时，不得出现"无规则且未报告"；查询失败必须表现为 `Unknown`，不能表现为"无资源"。
3. 恢复事务未提交前，不得删除账本、不得清除 tripped、不得发送成功通知。
4. Launch 仅当 `Armed` ∧ 未暂停 ∧ 当前代次检查全部 Pass 时允许；`Unverified` 一律拒绝。
5. 同一时刻只有一个操作所有者（机器级），跨进程同样成立。
6. `Unverified` 不得转化为 `Pass`；不得触发 kill；不得解除隔离。
7. 配置保存失败不得改变内存配置，也不得提示"已保存"。
8. 暂停确认返回后不得再开始新的自动 kill；已发出且无法确认取消的命令记为 `Unknown` 并核对。
9. 旧代次的检查结果不得更新新代次状态或触发旧策略。

## 3. 关键流程

### 3.1 一轮检查

1. 捕获 `config_revision`、`runtime_epoch`、`operation_id`。
2. 并行探测所有启用目标（有界并发），各自超时。
3. 解析接入证据（`AccessEvidence`）与目标结果（`PolicyVerdict`）。
4. 若代次已失效 → 丢弃结果，不提交。
5. 提交状态；更新 `fail_streak`、`access_streak`；按 §2.5 决策。
6. 需要副作用时交由协调器串行执行，并写账本。

### 3.2 熔断

1. 写恢复账本（事务 ID、代次、计划、原状态）。
2. 结束受管 GUI 进程（记录每个 PID/结果）；Claude 同时结束 CLI（既有语义）。
3. 添加并核验应用级防火墙规则（先加新覆盖，再撤旧覆盖）。
4. 若 `cut_network` 且能力就绪：执行全局断网并核验；否则跳过并记录 `Blocked`。
5. 更新 `Protection`，发通知（脱敏），写 TripInfo。
6. 任一步失败：进入 `Degraded`，保留账本，如实报告，不宣称已隔离。

### 3.3 恢复

**流程 A（安全恢复业务网络）**

1. 暂停新的副作用（代次递增）。
2. 核对应用隔离仍完整（规则 + 有效策略 + 对象清单）。
3. 恢复本产品禁用的网卡（按 GUID）→ 核验。
4. 撤全局 Block → 核验网络恢复。
5. 状态置 `NetworkReadyAppHeld`（应用仍隔离）。
6. 当前代次重新检查；满足策略后解除应用隔离 → `Monitoring`。

任一步失败或无法确认：停止流程 A，保留账本与现有保护，进入 `Degraded`，提供流程 B 的明确选择；不得临时开网试探，不得擅自杀共享代理。

**流程 B（停止保护并恢复网络）**

1. 用户显式确认停止保护。
2. 协调器停止重施规则（代次递增、写入"不再施规则"意图）。
3. 恢复本产品全部改动（规则、网卡、全局 Block）并逐项核验。
4. 置 `Disarmed` 或退出；输出结构化回执。

流程 B 不依赖外部探测成功，用于急救、卸载与正常退出。

### 3.4 启动门禁

`launch()` 走 `run_check(Purpose::Launch)`：要求当前代次全部启用目标 `Pass`；否则阻止启动、发 `launch_blocked` 通知、记录原因。`Unverified` 与 `Fail` 都拒绝。

### 3.5 退出、卸载、急救与更新交接

- 所有入口（托盘退出、窗口关闭后退出、`--restore`、旧 `--uninstall`、Inno 卸载、更新应用）必须走同一恢复协议并取得执行权。
- 正常退出：流程 B + 核验成功才退出；失败保持运行并显示错误。
- 卸载：先恢复并核验，再停止进程与删除文件；恢复失败禁止自删。
- 更新：`Maintenance` 事务，交接保护责任，等待旧实例退出与单实例锁释放，替换后等待认证的 Ready 回执。
- 崩溃/断电：下次启动优先处理 `RecoveryPending`，不得当作首启清场。

### 3.6 配置提交

`save` 返回 `Result`：校验 → 序列化 → 原子写 → 读回校验 → 提交内存 → `config_revision += 1`。任一步失败：内存不变、返回错误、UI 保留输入并提示未保存。

## 4. 数据模型（草案，实施时定名）

```rust
enum PolicyVerdict { Pass, Fail, Unverified }
enum AccessLevel { SystemProxy, Tun, Uncovered, Unknown }
struct AccessEvidence { level: AccessLevel, proxy_addr: Option<String>, tun_iface: Option<String>, route_hint: bool, observed_at: Instant, revision: u64 }
enum ProtectionReason { Manual, Uncovered, EgressFail }
struct ProtectionIntent { reasons: BTreeSet<ProtectionReason>, agents: Vec<String>, global_cut: bool, epoch: u64 }
struct ProtectionObserved { rules: Vec<RuleRef>, effective_policy: Option<String>, targets: Vec<String>, nics: Vec<String>, verified_at: Option<Instant>, scope: String }
enum OperationStatus { Verified, Partial, Failed, Unknown, Unsupported, NotApplicable }
struct OperationReceipt { id: String, status: OperationStatus, items: Vec<(String, OperationStatus)>, error: Option<String>, verified_scope: String, remaining: Vec<String> }
struct RecoveryJournal { version: u32, tx_id: String, epoch: u64, created_at: i64, plan: Vec<JournalStep>, baseline: Baseline, committed: bool }
```

`StateView` 新增：`lifecycle`、`protection`、`pausedUntil`、`protectionDetail{scope, verifiedAt, rules}`、`recovery{pending, lastError}`、`capability{globalCut, isolation}`。

## 5. 覆盖矩阵（R01–R17）

| ID | 缺陷/目标 | 现状证据 | 验收断言 | 测试组 | 批次 |
|---|---|---|---|---|---|
| R01 | 防火墙状态以文本/条数冒充有效 | `guard.rs:1200-1244` | 查询失败/本地化/部分创建 → `Unknown`/`Partial`；规则被删或路径变化后重建并核验 | T02 | M2 |
| R02 | 全局断网与自动恢复自锁 | `netcut.rs:366-378`、`monitor.rs:355-361` | 流程 A 不依赖被自己阻断的请求；隔离不足不自动开网 | T03/T04 | M3 |
| R03 | 接入判定误判（UTF-16、缺地址、PAC） | `access.rs:88-99,180-200` | 信息不足不判已接入；PAC/绕过不猜测；不直连探测 | T01 | M1 |
| R04 | 残留清理以"桌面仍在"为由跳过 | `guard.rs` pick_residual、`monitor.rs:610-632` | 主进程退出后 renderer 可处理；不误杀无关宿主/PID 复用 | T05 | M2 |
| R05 | 防护对象按最高目录名取 exe | `guard.rs:find_windowsapps_dir` | 注册包 + 运行映像 + 升级过渡清单全覆盖；先加新覆盖再撤旧 | T02/T05 | M2 |
| R06 | 恢复无写前账本、多入口不一致 | `netcut.rs:143-208`、`install.rs:134-166`、`main.rs:398-404` | 崩溃/断电可恢复；部分恢复不清熔断；两条卸载路径恢复失败均不自删 | T03/T08 | M3 |
| R07 | macOS 缺 lockdown 接口致编译阻断 | `macos/guard.rs:423-428` | Mac 可编译；不支持能力后端明确拒绝 | T08 | M1 |
| R08 | 首启未配置仍可能杀进程/断网 | `monitor.rs` engage 路径 | `Unconfigured` 无破坏性动作；完成配置并布防后才动作 | T06 | M1 |
| R09 | 更新无签名/清单/限额/受控暂存 | `update.rs:122-244` | 篡改/降级/错架构/错来源/竞态均拒绝；拒绝不改变保护 | T07 | M4 |
| R10 | 无跨进程执行权、旧结果可覆盖新配置 | `state.rs:188-222`、`main.rs:100-116` | 唯一所有者；旧代次结果不提交；暂停后无新自动 kill | T04 | M2 |
| R11 | 保存失败被忽略 | `config.rs:256-314`、`ipc.rs:57-85` | 磁盘满/权限失败 → 明确未保存；只读 CLI 不改文件 | T06 | M1 |
| R12 | UI 吞错误/覆盖输入/事件契约过期 | `ui/main.js`、`tests/ui-*.cjs` | 错误持久可见；编辑不被刷新覆盖；测试契约与真实事件一致 | T09 | M1 |
| R13 | 暂停/手动封锁语义不一致 | `monitor.rs:344-361`、`state.rs` | 暂停保留隔离；手动封锁不被自动清除 | T04/T09 | M1 |
| R14 | 外发可静默直连、通知含敏感字段 | `update.rs`、`feishu.rs`、`notify.rs` | 统一策略；默认脱敏；旧队列不自动重发 | T10 | M4 |
| R15 | UI 持管理员权限、无 CSP | `app.manifest`、`capabilities/default.json` | CSP + 导航限制；窄接口 helper；非法调用被拒 | T07/T10 | M4 |
| R16 | 多扫描器、状态读取触发系统调用 | `state.rs`、`monitor.rs`、`ipc.rs` | 单一进程快照服务；状态读取零扫描；资源预算达标 | T05 | M2/M5 |
| R17 | 能力边界与文档漂移 | `README.md`、`docs/GUIDE.md`、`AGENTS.md` | 可达性不表述为 IP 合格；文档与实现一致 | T09 | M5 |

## 6. 测试计划映射

详细用例见 `docs/TESTPLAN-v3.10.md`。分组与覆盖：T01 接入、T02 规则核验、T03 恢复账本、T04 竞争与执行权、T05 进程与对象清单、T06 持久化与首启、T07 更新与权限、T08 生命周期、T09 UI、T10 隐私外发。

## 7. 平台能力矩阵

| 能力 | Windows | macOS |
|---|---|---|
| 进程守护/启动门禁/通知 | 支持 | 支持（按现有移植） |
| 客户端更新（Claude/Codex） | 支持 | 支持 |
| 自身更新 | 支持（D6 后需验签） | 支持（Minisign 既有） |
| 应用级防火墙隔离 | 支持 | **不支持**（后端返回 `Unsupported`，UI 明示） |
| 防火墙兜底封锁 | 支持 | **不支持** |
| 全局断网/禁网卡 | 仅 D2 能力就绪后 | **不支持** |
| 接入路径检测（注册表/TUN） | 支持 | **不支持**（按现有设计跳过） |
| 恢复执行器 | 支持（R06） | 仅进程/客户端更新范围 |

不支持项必须在 UI 与 `--check` 输出中明确标注，不得以 `true`/`0` 冒充成功。

## 8. 规范变更（本轮同步）

1. `AGENTS.md` 判定不变量第 5–7 条改写为 D1–D3 语义；顶部新增本契约指针。
2. `docs/SPEC-v3.md` 顶部声明：契约优先（含 §0③、§1 默认值、§4 恢复/暂停/解除、§5 档位与退出、§6 文案）；§7 IPC / §8 UI 列表随对应里程碑落地时同步更新。
3. `docs/SPEC-v3.md` §0③ 改为"应用级隔离为默认；全局断网/禁网卡为高级可选，需独立恢复能力"。
4. `docs/SPEC-v3.md` §1 `Config`：`cut_network` 新装默认 `false`、`version=4`、新增 `notify.include_egress`。
5. `docs/SPEC-v3.md` §4：恢复条件改为流程 A；暂停不自动解除隔离；`release` 语义按 D3。
6. `docs/SPEC-v3.md` §6：`trip` 文案"修正后自动恢复"改为"确认出口正常后可恢复"；通知默认脱敏。
7. `docs/GUIDE.md` / `README.md` 在 M5 按最终能力重写，不提前承诺。

## 9. 失败模式矩阵

| 失败 | 状态 | 用户可见 | 恢复 |
|---|---|---|---|
| 防火墙查询失败 | `Degraded` | "无法确认隔离状态" | 限频重试；`--restore` 可离线恢复 |
| 规则部分创建 | `Degraded` | 列出缺失对象 | 重试差量；不撤旧覆盖 |
| 断网后恢复失败 | `Degraded` + 账本 | "网络恢复未完成" | 提供流程 B / 离线入口 |
| 账本损坏 | `Degraded` | "恢复记录损坏，已保留" | 保留文件，引导手动恢复 |
| 配置保存失败 | 内存不变 | "未保存" | 用户修正后重试 |
| 更新验签失败 | 状态不变 | 原因码 | 不应用、不改变保护 |
| 交接超时 | `Maintenance` 停留 | "等待旧实例退出" | 超时回滚，保留可启动版本 |
| 探测超时 | `Unverified` | "无法确认出口" | 不 kill、不解除、禁启动 |

## 10. 里程碑

| 阶段 | 工作包 | 出口条件 |
|---|---|---|
| M0（本轮） | 契约、状态机、覆盖矩阵、测试计划、规范同步 | 本文件 + TESTPLAN 定稿；无代码改动 |
| M1 | R03/R07/R08/R11/R12/R13 + 失败用例与平台假实现 | 已确认缺陷用例转绿；无系统副作用测试可跑 |
| M2 | R10/R04/R05/R01 + 协调器与进程快照 | 唯一执行权、对象清单、规则核验达标 |
| M3 | R02/R06 + 账本、流程 A/B、离线急救、两类卸载 | 故障注入可恢复；失败不误报、不删现场 |
| M4 | R09/R14/R15 + 验签更新、外发策略、权限拆分 | 篡改/竞态拒绝；保护责任交接完整 |
| M5 | R16/R17 + UI/文档、性能、Windows/Mac 原生验收、迁移回滚演练 | 验收矩阵完成；未测能力不宣称支持 |

## 11. 未决与不做

- D8 连接级强约束：未启动；需单独可行性验证与决策。
- 严格模式（`Unverified` 即隔离）：不实现。
- 常驻服务/计划任务安装：需用户单独授权。
- macOS 原生验收：缺环境时保持"未验证"，不宣称通过。
- 发版、上传 GitHub、本机升级：需用户明确指令。
