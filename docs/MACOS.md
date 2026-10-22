# macOS 移植预览：实现与验收边界

此分支从上游 `daha1216/ClaudeGuard` 的 `master`、提交
`f2c84ddeecc4b8b4ab7651fba53fe182fc442d50`（v3.5.0）直接移植。
保留 Windows 实现，通过条件编译选择 `src/macos/` 适配器；没有新增固定 IP 策略、
额外浏览器诊断或代理控制器功能。

**本次 PR 提供 macOS 进程守护移植预览，不发布 Release；外部验收边界见记录。**

完整实测范围见 [macOS 验收记录](MACOS-VALIDATION.md)。

## 上游一致性

以下四个核心文件与上述上游提交逐字节相同：
`src/model.rs`、`src/anchors.rs`、`src/policy.rs`、`src/targets.rs`。
因此保留原版 IP 或地区任一命中放行、每目标独立探测、信息不足不放行也不误报确切出口变化、
连续失败阈值、默认关闭本机出口目标等语义。显式 reachability 仍沿用原版：无响应即 Fail。

调度仍使用上游 `monitor.rs`，macOS 分支使用不断网档位并提供进程守护状态和通知文案。
配置仅增加 macOS 存储路径适配，目标模型与运行规则保持上游语义。
原版 v3.5 的手动清理与 Claude 熔断会包括 Claude Code CLI，不能把旧版“绝不杀 CLI”当作此版本行为。
初次运行和未完成向导期间仍沿用上游监控语义，没有新增观察模式。

## 当前确认的 macOS 防护范围

本实现采用进程守护模式，无需开发者账号、第三方防火墙或管理员授权。
出口连续失败达到原版阈值后，按 `kill_on_fail` 结束 `guarded_agents` 中的应用；
通过守护器启动 Claude 时必须重新检测，全部启用目标通过且熔断解除才允许启动。
自动恢复不会自行重启应用。信息不足保持原版不主动熔断的规则，但启动门禁拒绝放行。
保持“结束守护对象进程”开启才能自动关闭；暂停期间不触发新的熔断。
此范围不包括系统级禁止启动、连接级阻断或零检测窗口。守护器目前只提供 Claude 启动入口。
macOS 熔断明确使用 `off` 网络档位，不尝试全局阻断或停用网络服务；Windows 行为不变。

## 支持情况

| 能力 | 此预览状态 |
|---|---|
| 原版目标模型、解析、判定、配置迁移 | 保留，单元测试和隔离 CLI 测试通过 |
| 原版配置和 IPC 界面 | 保留；macOS 增加平台能力提示 |
| UI / Dock / 菜单栏 | 深色、系统字体和随 PR 提供的盾牌图标；不新增业务功能 |
| GUI 应用进程指纹 | 使用完整 `.app/Contents/` 路径边界，支持 Claude、ChatGPT、Antigravity |
| 进程终止 | 发信号前刷新 PID，核验可执行路径与启动时间；只用临时 sleep 子进程做真实终止测试 |
| Claude 清理 | 复用上游清理语义，适配 macOS CLI 路径；真实 Claude 与隔离 CLI 进程均已验收 |
| 飞书签名、队列、重试 | 共享上游实现；测试通过，未发送真实飞书消息 |
| 飞书凭据 | AES-256-GCM 密文写入配置，密钥在登录钥匙串；不能直接迁移 Windows DPAPI 密文 |
| 桌面通知 | 原生 UserNotifications 库在应用进程内发送；实际授权及通知中心送达查询通过，显示仍受系统设置影响 |
| 安装 | 校验源包与副本签名，完整 .app 暂存后原子安装到用户 Applications；已存在（含符号链接）时拒绝覆盖，失败不留下半成品 |
| 登录自启 | LaunchAgent 注册/执行/移除隔离实测通过；未更改用户真实登录项，未执行注销登录验收 |
| 解除隔离 / 恢复 | 此构建不创建网络规则，恢复入口幂等且不操作其他程序规则 |
| 按应用防火墙、全局阻断、禁用网卡 | 不在已确认的进程守护范围内；UI 禁用，执行器不能返回虚假成功 |
| Claude / Codex 自动更新 | 已实现官方源检查、发布者/系统信任校验、条件变化取消及原子部署/回滚；Claude/Codex 官方完整包下载、解压及签名/系统信任验证均通过；替换与回滚使用隔离应用验收，未替换真实客户端 |
| 守护器自身更新 | 完整 ZIP + 编译期固定 Minisign 公钥认证清单、摘要/版本/架构校验、互斥安装、原子交换、启动恢复与旧包保留已实现并做本地验收；维护者尚未提供信任公钥或发布 Mac 资产，当前不提供远端安装 |
| 签名、公证及跨架构 | Apple Silicon 与 Intel 独立包均 ad-hoc 签名；Intel 包通过 Rosetta 运行验收；无 Developer ID、公证或 Intel 真机验收 |

检测请求只能证明检测请求的路径，不能证明目标桌面应用的全部 DNS、UDP、IPv6 或 VPN/TUN 流量路径。
关闭进程有检测窗口，不能替代网络连接阻断。

## 出口检查失败的排查

如果界面同时显示 Claude、Codex“地区未确认”或“不可达”，先核对两个独立设置：

1. ClaudeGuard 的“代理端口”必须与代理软件实际监听的本机 HTTP/mixed 端口一致。
   例如混合端口配置可能使用 `7900`，而 ClaudeGuard 默认值是 `7890`；
   端口不一致会在日志中表现为 `Connection refused`。
2. Claude 和 Codex 目标的 `auto` 锚点至少要配置白名单 IP 或地区。
   上游安全语义是“两者都为空时永不放行”。如果当前代理已确认使用美国出口，
   可填入 `US`；目标会同时核对探测链路的国家，而不是只检查端口是否能连接。

修改后点击“重新检查”，或运行应用内的 `--check`。只有在三个启用目标都通过时，
守护器才会开放 Claude 启动按钮。TUN 模式下流量可以正常出网，但本地 mixed 端口仍可能
使用代理软件配置中的独立编号；这两件事不能混为一谈。

## 构建与测试

声明最低 macOS 12，Rust stable、Command Line Tools；不需要 Node 构建前端。
打包器为 Swift 通知库显式设置 `*-apple-macos12.0`，避免继承构建机的最低部署版本；
这只解决静态部署目标，尚未在 macOS 12 或 Intel 真机验收。

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
# 需要解锁登录钥匙串，只创建并删除一个随机合成测试条目：
cargo test --locked macos::credentials::tests::keychain_roundtrip -- --ignored --exact
python3 scripts/package-macos.py
python3 tests/macos-cli.py dist/ClaudeGuard.app/Contents/MacOS/claude-guard
python3 tests/macos-acceptance.py dist/ClaudeGuard.app/Contents/MacOS/claude-guard --notification-status
# 仅创建并移除唯一的合成 LaunchAgent，不更改实际登录项：
cargo test --locked macos::autostart::tests::real_launchd_registration_execution_and_disable -- --ignored --exact
# 真实回环代理 + 生产调度隔离验收，不操作用户进程或公网：
dist/ClaudeGuard.app/Contents/MacOS/claude-guard --macos-monitor-selftest
# 临时测试密钥、真实打包/签名/验签，不发布：
python3 tests/macos-self-update-packaging.py
# 可选：Node + Playwright + 本机 Chrome
CG_PLAYWRIGHT=/path/to/playwright node tests/macos-ui.cjs
```

应用包为 `dist/ClaudeGuard.app`。脚本只构建和签名，不自动安装、启动或设置登录项。
macOS 默认配置目录为 `~/Library/Application Support/ClaudeGuard`；
`CG_DATA_DIR` 可指定独立测试目录。
钥匙串服务名为 `com.daha.claudeguard.feishu`；卸载应用不删除配置、日志或密钥。
`--uninstall` 只移除登录项并提示在 Finder 删除应用；登录项移除失败时明确报错，不能当成卸载成功。

GUI 冒烟测试必须同时使用隔离的 `CG_DATA_DIR`、`CG_SMOKE_STATE`，
并禁用测试配置的通知、kill_on_fail 和 guarded_agents。
LaunchServices 启动要显式传 `open --env CG_DATA_DIR=... --env CG_SMOKE_STATE=...`，
不能假设 Finder/open 继承父 shell 环境；完成后退出模拟状态，避免将测试画面误当真实检测。

## 自更新发布准备（维护者操作，尚未发布）

自身更新信任根与 Apple Developer 签名独立：编译时通过 `CG_MACOS_UPDATE_PUBLIC_KEY`
提供维护者 Minisign 公钥的 base64 行，不能在运行时换成下载获得的公钥。
未配置时诚实禁用远端安装，不会下载 Windows EXE；私钥不得写入源码或日志。

维护者使用已有密钥准备已验证的完整应用包资产：

```sh
python3 scripts/package-self-update-macos.py --app dist/ClaudeGuard.app --output-dir dist/self-update --architecture arm64 --secret-key /path/to/maintainer.key --public-key /path/to/maintainer.pub
```

脚本只本地打包、签名与独立验签，不生成维护者密钥、不上传。
资产名为 `ClaudeGuard-vX.Y.Z-macos-arm64.zip` 或
`ClaudeGuard-vX.Y.Z-macos-x86_64.zip`，每个 ZIP 同时需要同名 `.json` 与 `.json.minisig`。
认证清单绑定版本、架构、官方仓库地址、大小及 SHA256；完整 `.app` 仍须代码签名校验。

本地合成签名包验收与资产脚本验收已通过。远端发布、实际从上游下载后替换当前运行版本、
真实更新重启仍待维护者公钥和 Mac Release 资产，不得把本地验收当成这些操作已经发生。

## 双架构构建与重启验收

默认构建本机架构。Intel 构建输出到独立目录，不覆盖 Apple Silicon 产物：

```sh
rustup target add x86_64-apple-darwin
python3 scripts/package-macos.py --target x86_64-apple-darwin
python3 tests/macos-lifecycle.py dist/ClaudeGuard.app
cargo test --locked update::self_update::relaunch_tests -- --ignored --nocapture --test-threads=1
```

Intel 产物为 `dist/x86_64-apple-darwin/ClaudeGuard.app`，通知库也按 x86_64 构建。
已在 Rosetta 下验证实际 Intel 二进制、通知库、CLI、调度、UI/IPC 和生命周期；不等同于 Intel 真机验收。
生命周期脚本使用隔离模拟模式，验证后台重开、Finder/Dock 重开、单实例转交和正常退出，不修改真实登录项。
生产重启助手位于 `native/relaunch.sh`，嵌入应用；真实合成应用测试覆盖等待精确进程退出后只启动一次、
出生时间不符时不误等或发信号、超时不启动。正式远端自更新仍需维护者公钥和已签名 Mac 发布资产。

## 已排除的网络隔离路线（研究记录）

本实现采用异常时关闭所选应用并对守护器启动实施门禁，因此以下路线不属于本次交付范围。
不再将额外防火墙安装、整机断网或 Network Extension 授权作为完成进程模式的前提。

- Apple 系统防火墙主要管入站，不能等价替换原版按应用出站隔离。
- 管理员授权下可以用 `networksetup` 或 SystemConfiguration 停用网络服务，
  但这是整机断网，必须精确记录此前已启用服务、原子持久化、错误回滚并验证崩溃恢复、VPN 和热插拔。
  此预览未实现、未更改任何真实网络服务。
- PF 可用于个人实验的整机包过滤；它没有按可执行文件路径的规则，已有 state 也可能绕过新增规则。
  Apple 明确说明 PF 不是供产品依赖的公开 API，不采用它冒充等价应用防火墙。
- Little Snitch 已由厂商签名，可作为需要另行安装/许可证/系统授权的可选后端。
  官方 CLI 有规则组启停能力，未来只应管理 ClaudeGuard 专属规则组，不覆盖用户现有规则。
  此路线尚未安装或实测，不能宣称支持。
- LuLu 主要管出站，不能直接承诺按应用双向隔离及自动规则管理。
- 调研中的 Network Extension 实验构建使用 ad-hoc 签名，helper 返回 unavailable，
  系统扩展列表为空；没有匹配签名与授权时不能直接激活。

参考：[Apple 系统防火墙](https://support.apple.com/en-ie/guide/mac-help/mh34041/mac)、
[Apple TN3165：PF 不是 API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)、
[SCNetworkServiceSetEnabled](https://developer.apple.com/documentation/systemconfiguration/scnetworkservicesetenabled(_:_:))、
[Little Snitch 规则](https://help.obdev.at/littlesnitch7/concepts-rules)、
[Little Snitch CLI](https://help.obdev.at/littlesnitch7/admin-command-line)、
[LuLu 官方说明](https://objective-see.org/products/lulu.html)。
