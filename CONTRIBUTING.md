# 贡献指南（CONTRIBUTING）

感谢你愿意为 ClaudeGuard 出力！本项目面向中文社区，文档与 commit 使用中文；代码标识符、命令、日志保持原文。

## 开始之前

- 先读 [AGENTS.md](AGENTS.md)：里面有**模块边界**（哪个目录/文件归谁管）、状态分组约定、已知坑，以及各子系统的语义基准。
- 行为基准见 [docs/SPEC-v3.md](docs/SPEC-v3.md)；CLI 与配置契约见 `docs/CONTRACT-v3.10.md`。
- 大改动建议先开 Issue 讨论方案，再提 PR。

## 本地门禁（提 PR 前必须全部通过）

```powershell
cargo fmt
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
node --check ui/*.js
```

- 改动了 `ui/` 才需要最后一条；前端是**纯静态 IIFE**，没有 npm、没有构建步骤。
- 不要为了过门禁去放宽 lint（例如给 clippy 加 allow）；确有必要的例外要在 PR 里说明理由。

## 模块边界

以 [AGENTS.md](AGENTS.md) 的模块表为准，常见的几条硬约定：

- `src/monitor.rs`（探测与熔断决策）、`src/netpol.rs`（防火墙/断网系统动作）、`src/state.rs`（状态机与账本）等核心文件的改动要格外小心，语义变化必须同步更新 `docs/SPEC-v3.md` 相关章节。
- 任何改系统的动作（防火墙、断网、进程清理）必须**先写账本再执行**，恢复必须幂等、可重复。
- `ui/*.js` 必须保持 IIFE 结构，禁止引入 npm 包、前端框架或任何构建步骤。

## 测试约定

- 新增/修改测试时，夹具 IP **只用 TEST-NET 保留段**：`198.51.100.0/24`、`203.0.113.0/24`。
- 不要在测试、示例或文档里写真实出口 IP、真实代理地址或真实 Webhook。
- 能用单元测试覆盖的判定逻辑（期望比对、防抖、接入路径、恢复账本）请补测试；跑 `cargo test --locked` 确认全绿。

## Commit message 风格

中文 conventional commits，与仓库历史一致：

```
<type>: <中文简述>
```

- `type` 用 `feat` / `fix` / `docs` / `chore` / `refactor` / `test` / `ci` 等。
- 简述说明**改了什么**，范围较小时可带上模块前缀，例如 `fix(ui): 暂停守护恢复后主按钮回落启动态`。
- 一个 commit 只做一件事；行为变化、配套测试与文档放同一主题的 commit 里。

## 提 Pull Request

- 用 [PR 模板](.github/PULL_REQUEST_TEMPLATE.md)勾选门禁。
- 描述里写清：动机、行为改前/改后、关联 Issue。
- 保持 diff 聚焦；与本改动无关的文件（包括他人正在改的文件）不要带上。

## 报告问题

- Bug 与功能建议走 [Issue 模板](.github/ISSUE_TEMPLATE/)，日志先脱敏（真实 IP、节点地址、Webhook 替换为占位符）。
- 安全漏洞请看 [SECURITY.md](SECURITY.md)，**不要**公开开 Issue。

## 许可

贡献即表示同意以 [MIT](LICENSE) 许可你的代码。
