# Claude 守护器 (ClaudeGuard)

一个轻量的 Claude 桌面端守护工具：启动前校验代理出口，常驻后台持续监测，
一旦发现出口 IP 不符立即关停 Claude 并用防火墙隔离其联网。

## 功能

- **启动闸门**：三步校验（系统代理配置 → 代理握手 → 出口 IP），全部通过才放行启动 Claude。
- **自定义检测项**：代理端口、要求的出口 IP 均可在界面里修改。
- **常驻监测**：最小化到系统托盘，按间隔（默认 15 秒）复检端口与出口 IP 健康。
- **异常熔断**：检测到出口 IP 不符时：
  1. 结束所有 Claude 进程；
  2. 为 Claude 全部可执行文件添加防火墙出/入站阻止规则（ClaudeGuard Block Out/In）。
  3. 重新检测通过后可一键解除隔离。
- **自安装**：以管理员身份运行一次即安装到 `%LOCALAPPDATA%\Programs\ClaudeGuard`，
  创建桌面/开始菜单快捷方式，并注册到"设置-应用"可卸载列表。
- **开机自启**（可选）：默认关闭；开启后驻留托盘静默监测。
- **检查更新**：从 GitHub Releases 检查新版本，下载后自动替换重启（优先走本地代理）。

## 使用

1. 右键"以管理员身份运行"（防火墙规则需要管理员权限）；
   首次运行会让你选择"立即安装"或"仅本次运行"。
2. 安装后从桌面快捷方式启动（快捷方式会自动请求管理员权限）。
3. 界面上可修改：代理端口（默认 7890）、要求的出口 IP、
   监测间隔、是否异常时杀进程/隔离网络。
4. 右键托盘图标：显示主界面 / 立即检测 / 解除隔离 / 退出。

## 下载

到 [Releases](https://github.com/daha1216/ClaudeGuard/releases) 页面下载最新的 `ClaudeGuard.exe`，
右键以管理员身份运行即可。

## 卸载

- 从"设置-应用-安装的应用"里找到 Claude 守护器卸载；或运行 `ClaudeGuard.exe --uninstall`。
- 卸载会自动解除防火墙隔离并删除快捷方式与配置。

## 文件位置

- 配置：`%APPDATA%\ClaudeGuard\config.json`
- 日志：`%APPDATA%\ClaudeGuard\guard.log`
- 安装目录：`%LOCALAPPDATA%\Programs\ClaudeGuard`

## 技术说明

- Rust + egui/eframe 原生 GUI，单文件 exe，无运行时依赖。
- 出口 IP 检测经代理请求 ipinfo.io（备用 ipify），双失败时回退为 TCP 连接观察。
- 防火墙操作通过 netsh（Windows 自带），无需额外驱动。
- 更新检查走 GitHub Releases API（匿名、带本地代理回退），下载校验大小后自替换。

## 从源码构建

```
cargo build --release
```

需要 Rust stable (MSVC toolchain)；图标与清单由 `build.rs` 自动嵌入。
