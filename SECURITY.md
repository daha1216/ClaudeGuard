# 安全政策（SECURITY）

## 私密报告方式

请**不要**在公开 Issue、Discussion 或 Pull Request 里披露安全漏洞。请使用 GitHub 的私密报告通道：

**[Report a vulnerability（GitHub Security Advisories）](https://github.com/daha1216/ClaudeGuard/security/advisories/new)**

维护者会通过该渠道与你私下沟通、确认影响范围并协调修复与公开时间。

报告里请尽量包含：

- 受影响的版本（`claudeguard-daemon.exe --version` 或 `claudeguard-cli.exe --version`）；
- 漏洞类型与复现步骤；
- 预期影响（例如：绕过出口校验或安全启动门禁、Named Pipe ACL 提权、`LocalSystem` 守护进程交互问题、WAL 崩溃回滚失效、凭据或诊断包脱敏泄露、更新来源校验绕过）；
- 已知的修复建议（可选）。

## 适用范围

- 本项目是 **Windows 网络出口门禁与隔离守护系统**：
  - 核心守护工作区（`cg-protocol`、`cg-core`、`cg-platform`、`cg-daemon`），以 Windows Service（`ClaudeGuardService`）与应急命令行（`claudeguard-cli.exe`）运行；
  - 原生桌面客户端（`claudeguard-gui.exe`，`asInvoker` 权限，仅通过受限 Named Pipe `\\.\pipe\ClaudeGuardV4` 与守护通信）；
  - 重点关注：未达标时绕过安全启动门禁、防火墙隔离/回滚协议（WAL `journal.json`）被破坏、4 维防漏旁路、`antigravity-proxy` `version.dll` 校验绕过、飞书 DPAPI 凭据或 `.zip` 脱敏诊断包泄露。
- 对**代理软件、Windows 系统组件或被守护 AI 应用**自身漏洞的报告不适用，请向对应上游披露。

## 支持版本

仅最新 release（`v4.x`）及 `master` 上的修复接受安全报告；旧版 `v3.x` 分支已归档，不再单独出补丁。版本列表见 [Releases](https://github.com/daha1216/ClaudeGuard/releases)。
