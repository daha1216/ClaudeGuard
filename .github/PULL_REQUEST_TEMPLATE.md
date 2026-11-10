## 改了什么

<!-- 一句话概括；对应 Issue 请写 #编号 -->

## 为什么改

<!-- 背景 / 解决的问题；行为变化请写清改前 → 改后 -->

## 本地门禁（提交前全部通过）

- [ ] `cargo fmt`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked`
- [ ] `node --check ui/*.js`（改动了 `ui/` 时必跑；前端为纯静态 IIFE，无 npm/构建步骤）

## 约定自查

- [ ] 没有越界改动（模块边界见 [AGENTS.md](../AGENTS.md)，与本改动无关的文件未动）
- [ ] 新增/修改的测试夹具 IP 只用 TEST-NET（`198.51.100.0/24`、`203.0.113.0/24`）
- [ ] 没有引入 npm 包、前端框架或构建步骤
- [ ] 涉及系统改动（防火墙 / 断网 / 进程）的逻辑走账本先行，恢复幂等
- [ ] 文档与行为同步（README / docs / CHANGELOG 视需要更新）
