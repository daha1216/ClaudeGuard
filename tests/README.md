# 本地验证

从仓库根目录执行。Rust 构建需要 Windows、Rust MSVC 工具链和 C++ 构建工具；PowerShell 包模拟使用 Windows PowerShell 5.1。前端测试另外需要 Node.js、Playwright 和 Microsoft Edge，应用本身不依赖 Node.js。

## Rust 门禁

```powershell
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
```

本次扩展的基准为 44 项 Rust 测试，覆盖通知去重与失败保留、重复保存同一凭据时保留通知、凭据公开状态隔离、更新版本比较与恢复状态、启动失败诊断等。数量以当前测试输出为准。使用 debug 测试；不要用 `cargo test --release`，release 程序的管理员清单会影响测试进程启动。

## Windows 包部署模拟

`package-deployment.ps1` 调用实际内嵌部署脚本，但用假的 Windows 包 API、进程结果和签名结果替代系统操作。它只在 `tests/output/mock-package` 创建测试包，不安装应用、不操作真实用户档案。

下面在独立的 Windows PowerShell 5.1 进程中运行每个场景，避免模拟函数和环境变量影响后续命令：

```powershell
$windowsPowerShell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$cases = @('running', 'deferred', 'updated', 'current', 'blocked',
           'servicing', 'incomplete', 'race', 'bad-signature', 'wrong-version')
foreach ($product in @('claude', 'codex')) {
    foreach ($action in @('install', 'finish')) {
        foreach ($case in $cases) {
            & $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                -File .\tests\package-deployment.ps1 -Product $product -Action $action -Case $case
            if ($LASTEXITCODE -ne 0) { throw "Package mock failed: $product / $action / $case" }
        }
    }
}
```

共 40 个组合，覆盖正常更新和一次性完成两条路径、仍在运行、延后注册、版本达到目标、系统拒绝、包维护中、注册不完整、进程竞争、错误签名与错误版本。模拟返回与 `Get-AppxPackage` 一致的字符串版本，包含数字段 `928 → 1007` 的比较回归。

## 前端模拟 IPC

```powershell
node .\tests\ui-feishu.cjs
```

Node.js 需能解析 `playwright`；若已在其他目录安装，可设置 `CG_PLAYWRIGHT` 为其模块路径。测试使用已安装的 Edge 无头模式，不自行安装浏览器。

测试通过本地路由加载 `ui/`，以模拟 Tauri IPC 验证通知设置、保存与测试按钮、失败补发、周期状态刷新不覆盖输入、两个客户端的更新等待状态、一次性完成操作、启动错误显示及窄窗口布局。所有通知和更新动作均为模拟，不向真实群发消息，不调用原生安装接口。

截图、模拟包和结果 JSON 写入已忽略的 `tests/output/`，不应作为个人运行状态提交到仓库。

## 这些测试不证明什么

模拟测试不证明真实 Webhook 能送达，也不证明某台电脑的 Windows 包注册、实际启动窗口或更新后登录状态正常。真实验收应在保存工作并明确配置测试目标后，分别确认飞书业务成功回执、当前用户注册版本及健康状态、应用能够启动，以及账户会话状态。不要为了验收强制结束客户端、运行中的 CLI 或其他用户任务。
