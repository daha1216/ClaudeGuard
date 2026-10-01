$ErrorActionPreference = 'Stop'
$dir = 'C:\Users\daha\Desktop\ClaudeGuard'
$tmp = Join-Path $env:TEMP 'ClaudeGuard-v1.3.0.exe'
Copy-Item (Join-Path $dir 'target\release\claude-guard.exe') $tmp -Force
$zip = Join-Path $dir 'ClaudeGuard-v1.3.0.zip'
$notes = @'
## ClaudeGuard v1.3.0

### 新功能
- **检查更新**: 设置里点一下, 从 GitHub Releases 检查并自动完成 下载 → 替换 → 重启
- 开机自启固定指向安装位置, 移动手动运行的 exe 不再影响自启

### 重构(防屎山)
- app.rs 拆分为 theme / widgets / wizard / app 四个模块, 界面部件全部无状态化

### 安全与健壮性
- 所有子进程调用改用系统目录绝对路径, 消除 PATH 劫持提权面
- 代理地址解析失败不再崩溃, 明确提示
- 修复字体优先级颠倒、等宽字体被污染、版本号字典序比较(2.10 < 2.9)等问题
- 配置文件解析失败会记录日志并回退默认值

> 首次使用: 下载 zip 解压运行, 或直接下载 exe。需要管理员权限(防火墙熔断需要)。
'@
gh release create v1.3.0 --repo daha1216/ClaudeGuard --title 'ClaudeGuard v1.3.0' --notes $notes $tmp $zip 2>&1
Write-Output '--- release assets ---'
gh release view v1.3.0 --repo daha1216/ClaudeGuard --json assets --jq '.assets[].name' 2>&1
