# ClaudeGuard v4 release & Inno Setup staging script.
# Usage: powershell -ExecutionPolicy Bypass -File make-release.ps1 [-Ver 4.0.0]
param(
    [string]$Ver = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if ([string]::IsNullOrWhiteSpace($Ver)) {
    $daemonToml = Get-Content (Join-Path $root "crates\cg-daemon\Cargo.toml") -Raw
    $m = [regex]::Match($daemonToml, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $m.Success) { throw "failed to parse version from crates\cg-daemon\Cargo.toml" }
    $Ver = $m.Groups[1].Value
}

$iscc = "C:\Users\daha\AppData\Local\Programs\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { throw "ISCC not found at $iscc" }

$daemonCargoVer = ([regex]::Match((Get-Content (Join-Path $root "crates\cg-daemon\Cargo.toml") -Raw), '(?m)^version\s*=\s*"([^"]+)"')).Groups[1].Value
$guiCargoVer = ([regex]::Match((Get-Content (Join-Path $root "crates\cg-gui\Cargo.toml") -Raw), '(?m)^version\s*=\s*"([^"]+)"')).Groups[1].Value
if ($daemonCargoVer -ne $Ver) { throw "cg-daemon version mismatch: Cargo.toml=$daemonCargoVer, -Ver=$Ver" }
if ($guiCargoVer -ne $Ver) { throw "cg-gui version mismatch: Cargo.toml=$guiCargoVer, -Ver=$Ver" }

Write-Host "Building backend release binaries (target-ws\release)..."
cargo build --release --offline --manifest-path (Join-Path $root "Cargo.toml") --target-dir (Join-Path $root "target-ws") --bins
if ($LASTEXITCODE -ne 0) { throw "backend release build failed with exit code $LASTEXITCODE" }

Write-Host "Building GUI release binary (target-gui\release)..."
$gpuiCargoHome = "F:\_dl\claudeguard-gpui-probe\cargo-home"
$prevCargoHome = $env:CARGO_HOME
try {
    if (Test-Path $gpuiCargoHome) {
        $env:CARGO_HOME = $gpuiCargoHome
    }
    cargo build --release --offline --locked --manifest-path (Join-Path $root "crates\cg-gui\Cargo.toml") --target-dir (Join-Path $root "target-gui")
    if ($LASTEXITCODE -ne 0) { throw "GUI release build failed with exit code $LASTEXITCODE" }
} finally {
    if ($null -eq $prevCargoHome) {
        Remove-Item Env:CARGO_HOME -ErrorAction SilentlyContinue
    } else {
        $env:CARGO_HOME = $prevCargoHome
    }
}

$stageDir = Join-Path $root "target\release"
if (-not (Test-Path $stageDir)) { New-Item -ItemType Directory -Path $stageDir | Out-Null }

$daemonSrc = Join-Path $root "target-ws\release\claudeguard-daemon.exe"
$cliSrc    = Join-Path $root "target-ws\release\claudeguard-cli.exe"
$guiSrc    = Join-Path $root "target-gui\release\claudeguard-gui.exe"

foreach ($p in @($daemonSrc, $cliSrc, $guiSrc)) {
    if (-not (Test-Path $p)) { throw "missing release binary: $p" }
}

Copy-Item $daemonSrc (Join-Path $stageDir "claudeguard-daemon.exe") -Force
Copy-Item $cliSrc    (Join-Path $stageDir "claudeguard-cli.exe")    -Force
Copy-Item $guiSrc    (Join-Path $stageDir "claudeguard-gui.exe")    -Force

$daemonProdVer = (Get-Item (Join-Path $stageDir "claudeguard-daemon.exe")).VersionInfo.ProductVersion
if ($daemonProdVer -ne $Ver) {
    throw "claudeguard-daemon.exe ProductVersion='$daemonProdVer' does not match '$Ver'"
}

$guiBytes = [System.IO.File]::ReadAllBytes((Join-Path $stageDir "claudeguard-gui.exe"))
$guiAscii = [System.Text.Encoding]::ASCII.GetString($guiBytes)
if (-not $guiAscii.Contains("asInvoker")) {
    throw "claudeguard-gui.exe manifest missing level='asInvoker'"
}
if ($guiAscii.Contains("requireAdministrator")) {
    throw "claudeguard-gui.exe must NOT contain requireAdministrator"
}

$outDir = Join-Path $root "installer"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

& $iscc "/DMyAppVersionStr=$Ver" (Join-Path $root "claude-guard.iss") | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

$setup = Join-Path $outDir "ClaudeGuard-v$Ver-setup.exe"
if (-not (Test-Path $setup)) { throw "setup exe not produced: $setup" }
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash
$len = (Get-Item $setup).Length
Write-Host ("setup: {0}  sha256={1}  {2:N0} bytes" -f $setup, $hash.Substring(0, 16), $len)
