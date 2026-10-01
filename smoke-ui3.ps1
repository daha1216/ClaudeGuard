$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
try {
  Add-Type -Namespace Win32 -Name Native -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
public struct RECT { public int L; public int T; public int R; public int B; }
'@
  [Win32.Native]::SetProcessDPIAware() | Out-Null
  $pinvoke = $true
} catch { $pinvoke = $false }

$exe = 'D:\dsh work\claude-guard\target\debug\claude-guard.exe'
$ws = New-Object -ComObject WScript.Shell
$log = Join-Path $env:APPDATA 'ClaudeGuard\guard.log'
$marks = @{}

function MoveWin($p) {
  if (-not $pinvoke) { return }
  $p.Refresh()
  Start-Sleep -Milliseconds 1500
  $h = $p.MainWindowHandle
  if ($h -eq [IntPtr]::Zero) { return }
  $r = New-Object Win32.Native+RECT
  [Win32.Native]::GetWindowRect($h, [ref]$r) | Out-Null
  $marks[$p.Id] = "before: L=$($r.L) T=$($r.T) R=$($r.R) B=$($r.B)"
  # 移到 (60,40) 并置顶
  [Win32.Native]::SetWindowPos($h, [IntPtr](-1), 60, 40, ($r.R - $r.L), ($r.B - $r.T), 0x0040) | Out-Null
  Start-Sleep -Milliseconds 400
}

function ShotRect($p, $out) {
  MoveWin $p
  $p.Refresh()
  $hh = $p.MainWindowHandle
  if ($pinvoke -and $hh -ne [IntPtr]::Zero) { [Win32.Native]::SetForegroundWindow($hh) | Out-Null }
  $null = $ws.AppActivate($p.Id)
  Start-Sleep -Milliseconds 800
  if ($pinvoke) {
    $h = $p.Refresh(); $p.Refresh()
    $h2 = $p.MainWindowHandle
    $r = New-Object Win32.Native+RECT
    [Win32.Native]::GetWindowRect($h2, [ref]$r) | Out-Null
    $w = $r.R - $r.L; $ht = $r.B - $r.T
    if ($w -gt 50 -and $ht -gt 50) {
      $bmp = New-Object System.Drawing.Bitmap($w, $ht)
      $g = [System.Drawing.Graphics]::FromImage($bmp)
      $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
      $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
      $g.Dispose(); $bmp.Dispose()
      return "rect ${w}x${ht}"
    }
  }
  # 兜底全屏
  $bd = [System.Windows.Forms.SystemInformation]::VirtualScreen
  $bmp = New-Object System.Drawing.Bitmap($bd.Width, $bd.Height)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($bd.X, $bd.Y, 0, 0, $bmp.Size)
  $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  return "fullscreen"
}

# --- 主屏: 等检测完成(log 出现 result:) 再截 ---
Remove-Item $log -Force -ErrorAction SilentlyContinue
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -PassThru
$done = $false
while ($sw.Elapsed.TotalSeconds -lt 25) {
  Start-Sleep -Seconds 2
  if (Test-Path $log) {
    $tail = Get-Content $log -Tail 6 -ErrorAction SilentlyContinue
    if ($tail -match 'result:') { $done = $true; break }
  }
}
$r1 = ShotRect $p 'D:\dsh work\claude-guard\shot-main3.png'
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 900

# --- 向导 ---
$cfg = Join-Path $env:APPDATA 'ClaudeGuard\config.json'
$enc = New-Object Text.UTF8Encoding($false)
Remove-Item $cfg -Force -ErrorAction SilentlyContinue
$p2 = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 4
$r2 = ShotRect $p2 'D:\dsh work\claude-guard\shot-wizard3.png'
Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 900

# --- 恢复配置 ---
$def = @{
  proxy_host = '127.0.0.1'; proxy_port = 7890; required_ip = '204.1.100.98'
  connect_target = 'api.anthropic.com:443'; app_id = ''
  check_interval_secs = 15; kill_on_fail = $true; quarantine_on_fail = $true
  launch_on_pass = $false; close_to_tray = $true
  auto_start_with_system = $false; first_run = $false
}
[IO.File]::WriteAllText($cfg, (ConvertTo-Json $def -Depth 5), $enc)
Write-Output "pinvoke=$pinvoke main=$r1 done=$done wizard=$r2"
Write-Output "marks: $($marks.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" })"
Get-Content $log -Tail 8 -ErrorAction SilentlyContinue
