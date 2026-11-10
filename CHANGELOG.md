# 更新日志（CHANGELOG）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的格式约定，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

日期为实际发布日期（UTC）。更早的历史版本见 [GitHub Releases](https://github.com/daha1216/ClaudeGuard/releases)。

## [未发布]（v3.12.5）

> 版本号已在 `Cargo.toml` 升至 3.12.5，但**尚未打 tag / 发布 Release**；以下为当前 master 上相对 v3.12.4 的全部变更。

### 新增

- 首次运行向导：留空白名单直接「以后再说」会触发闸门与二次确认，避免守护启动约 30 秒后被熔断隔离网络（`55a598d`）。
- 主界面把「暂停守护」「完全恢复网络」「行内直连观察」三个功能提层，不再埋在折叠卡里（`67e25e5`）。

### 修复

- 停止保护状态贯通主卡与主按钮，标题与按钮不再与实际状态脱节（`f32b054`）。
- 断网后置核验改为按 GUID 回查网卡状态，查不到网卡即判定核验失败，不再假定断网成功（P2-5，`5b34db4`）。
- lockdown IPC 返回执行回执，回查失败不再谎报已生效（P2-4，`cbec541`）。
- 配置目录不再静默落在当前工作目录；`%APPDATA%` 缺失时逐级降级并写日志（P2-7，`5ee0317`）。
- 隔离规则解除按幂等判定：本来就没有规则时不再误报失败（P2-9，`623965d`）。
- 轮次处置抽出 `decide_round_outcome`，未熔断的失败不再被死分支吞掉（P1-1，`b379543`）。
- 自更新退出前同走恢复闸门，恢复失败不再用 `process::exit(0)` 绕过（P1-3，`90edbb1`）。
- 统一不合规计数口径，加固设置保存与恢复默认（`ca46280`）。
- UI 可访问性四件套与小字对比度修正，toast 避让 CTA（`4025f4f`）。

### 变更

- 依赖安全对齐：`zip` 升到 9.x、`quick-xml` 升到 0.42（PR #13，`44ade22`）；`hmac` 升到 0.13 并同步 `sha2` 0.11（PR #10，`5546f18` / `04a1c01` / `e45b987`）。
- 补齐 macOS 移植缺的符号，macOS CI job 首次真正编译通过（`a48330c`）。
- 放宽 inspection 用例超时，避免 CI 冷启动 PowerShell 时误报（`63cd2b8`）。

### 文档

- README 双语化：英文主版 + `README.zh-CN.md` 中文版（语言切换、封号潮背景引用、核心能力、3 步上手、FAQ），并修正向导步骤、设置分组数与主卡布局的描述漂移。
- 新增 GitHub 社区基建：Bug / 功能建议 Issue 表单模板、PR 门禁勾选模板。
- 新增 `CONTRIBUTING.md`（中文门禁、模块边界、TEST-NET 夹具与禁 npm 约定）与 `SECURITY.md`（Security Advisories 私密报告）。
- 新增本文件。

## [3.12.4] - 2026-10-27

### 修复

- 防火墙自愈不再解析本地化文本：改按 `Get-NetFirewallProfile` 的结构化状态判断，非英文 Windows 上从不触发的问题（`3f42c67`）。
- 修正 netsh「找不到规则」提示的匹配串。
- TLS 依赖栈补丁升级（rustls / rustls-webpki / webpki-roots / tokio）。

### 变更

- CI 接入单元测试（发版时 212 个）并新增 macOS job。
- 补充 MIT 许可文件。

## [3.12.3] - 2026-10-26

### 新增

- 设置「更新」组新增 GitHub 仓库入口（`e369478`）。

## [3.12.2] - 2026-10-26

### 修复

- 下载更新包时正确跟随 GitHub 资产重定向（302 白名单逐跳校验，`f612d55`）。

## [3.12.1] - 2026-10-25

### 修复

- TUN fake-ip 网段 `198.18.0.0/15` 不再被误判为直连，消除该模式下的误报熔断。
- GitHub API 限流（60 次/时）时给出明确提示，不再表现为空失败。

## [3.12.0] - 2026-10-24

### 新增

- 直连泄露观察：发现绕过代理的外连即告警。
- 环境一致性检查：探测环境与目标环境不一致时提前暴露。
- 时区 / 默认位置的自动对齐与一键还原，全部走账本、可随时恢复。

### 变更

- 单元测试增至 208 个。

## [3.11.0] - 2026-10-24

### 新增

- 主界面按「主卡 + 分组卡」方向 A 重构：CTA 移出滚动区，熔断与暂停改用主卡标题与主按钮表达。

### 变更

- 设置改为 8 组手风琴折叠。
- 删除旧版状态圆环（状态改由主卡标题承载）。

---

[未发布]: https://github.com/daha1216/ClaudeGuard/compare/v3.12.4...HEAD
[3.12.4]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.4
[3.12.3]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.3
[3.12.2]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.2
[3.12.1]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.1
[3.12.0]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.12.0
[3.11.0]: https://github.com/daha1216/ClaudeGuard/releases/tag/v3.11.0
