# 安全政策（SECURITY）

## 私密报告方式

请**不要**在公开 Issue、Discussion 或 Pull Request 里披露安全漏洞。请使用 GitHub 的私密报告通道：

**[Report a vulnerability（GitHub Security Advisories）](https://github.com/daha1216/ClaudeGuard/security/advisories/new)**

维护者会通过该渠道与你私下沟通、确认影响范围并协调修复与公开时间。

报告里请尽量包含：

- 受影响的版本（主界面右上角或 `ClaudeGuard.exe --version`）；
- 漏洞类型与复现步骤；
- 预期影响（例如：绕过出口校验、熔断/恢复逻辑被破坏、配置或凭据泄露、提权）；
- 已知的修复建议（可选）。

## 适用范围

- 本项目是**网络出口门禁**：重点关注绕过校验（未通过白名单仍可启动被守护应用）、熔断与恢复协议被破坏（隔离不生效 / 恢复不幂等 / 断网不解除）、凭据与配置泄露（`%APPDATA%\ClaudeGuard\` 下的 DPAPI 凭据、飞书队列）、更新链路被劫持（守护器自更新与客户端 MSIX 升级的校验）。
- 对**代理软件、系统本身或被守护应用**自身漏洞的报告不适用，请向对应上游披露。

## 支持版本

仅最新 release 及 master 上的修复接受安全报告；旧版本不单独出补丁。版本列表见 [Releases](https://github.com/daha1216/ClaudeGuard/releases)。
