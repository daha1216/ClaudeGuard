## 改了什么

<!-- 一句话概括；对应 Issue 请写 #编号 -->

## 为什么改

<!-- 背景与动机；涉及行为变化请写清改前 → 改后 -->

## 本地门禁（提交前全部通过）

- [ ] `cargo fmt --all`（已对本次改动文件完成格式化）
- [ ] `cargo clippy --workspace --locked --all-targets -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] 如改动 `crates/cg-gui`：`cargo clippy --locked --manifest-path crates/cg-gui/Cargo.toml --all-targets -- -D warnings` 与 `cargo test --locked --manifest-path crates/cg-gui/Cargo.toml`

## 约定自查

- [ ] 严格只读探测，未添加自动切换代理节点或篡改用户代理分流策略的代码
- [ ] 测试夹具、Demo 与文档中仅使用 RFC 5737 TEST-NET 网段（`198.51.100.0/24`、`203.0.113.0/24`）
- [ ] 系统状态变更均走 WAL 账本先行（`journal.json` / `env_backup.json`），恢复路径幂等
- [ ] 如涉及接口、CLI 或 UI 变更，已同步更新 README / CHANGELOG
