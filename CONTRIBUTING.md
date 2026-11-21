# 贡献指南（CONTRIBUTING）

感谢你愿意为 ClaudeGuard 出力！本项目面向中文社区，文档与 commit 推荐使用中文；代码标识符、命令、日志保持原文。

## 仓库结构（v4 多 Crate 架构）

- `crates/cg-protocol`：IPC Named Pipe 线缆协议（`PipeRequest` / `PipeResponse` / 帧编解码）、配置 Schema v4（含 v2/v3 无损迁移）、状态机与组件更新数据模型。
- `crates/cg-core`：纯逻辑核心（无 Windows API 依赖）——目标锚点解析、策略评估与防抖、多 Agent 进程判定、接入路径评估、直连泄露判断、时区校验、脱敏引擎、24h 时间线统计与状态机转换。
- `crates/cg-platform`：Windows 系统平台层——HTTP/SOCKS 代理探测（无直连回退）、Windows COM 防火墙规则引擎、进程树扫描与精准清理、4 维防漏护盾、`antigravity-proxy` 检测与热修复、WinRT Toast、DPAPI 加解密、时区/传感器位置同步与多组件只读更新巡检。
- `crates/cg-daemon`：Windows Service 常驻守护（`claudeguard-daemon.exe` / `ClaudeGuardService`）、WAL 崩溃恢复账本（`journal.json`）、Named Pipe 服务端、飞书持久化重发队列、脱敏诊断包导出与命令行工具（`claudeguard-cli.exe`）。
- `crates/cg-gui`：独立工作区成员（`asInvoker` 普通用户权限），基于 Zed `gpui` 构建的 Frost Ceramic 双主题原生桌面端（模式 A 托盘快捷 HUD + 模式 B 完整控制台），以及可零守护脱离运行的 `--demo` / `--hud` 模式。

## 本地门禁（提 PR 前必须全部通过）

### 核心工作区

```powershell
cargo fmt --all
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
```

### 原生 GUI（`crates/cg-gui`）

```powershell
cargo fmt --manifest-path crates/cg-gui/Cargo.toml
cargo clippy --locked --manifest-path crates/cg-gui/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path crates/cg-gui/Cargo.toml
```

- 不要为了过门禁去放宽 lint（例如随意加 `#![allow(...)]`）；确有必要的例外请在 PR 描述里写明理由。

## 工程红线

1. **只读代理探测原则**：严禁任何自动切换代理节点、篡改用户代理软件规则或绕开代理直接发外网探测的代码（飞书推送按其明确 Webhook URL 直连 HTTPS，通知正文默认经 `cg_core::redact` 脱敏）。
2. **账本先行，恢复幂等**：任何修改系统状态的操作（防火墙规则、断网、系统时区/默认位置）必须先写 `journal.json` / `env_backup.json` 并落盘后再操作 OS；恢复路径必须幂等。
3. **测试 IP 夹具规范**：新增或修改测试夹具、文档示例、Demo 数据时，IPv4 **只允许使用 RFC 5737 TEST-NET 保留段**（`198.51.100.0/24`、`203.0.113.0/24`、`192.0.2.0/24`），禁止写入真实外网 IP、真实代理节点或真实 Webhook。

## Commit Message 风格

```text
<type>(<scope>): <简述>
```

- 常用 `type`：`feat`、`fix`、`docs`、`chore`、`refactor`、`test`、`ci`。

## 报告问题

- Bug 与功能建议请走 [Issue 模板](.github/ISSUE_TEMPLATE/)，上传日志或 `.zip` 诊断包前注意二次核验敏感信息；安全漏洞请走 [SECURITY.md](SECURITY.md) 私密上报。
- 贡献代码即表示同意以核心 [MIT](LICENSE) / GUI `Apache-2.0` 协议许可你的改动。
