# ClaudeGuard v4 release & Inno Setup staging script.
# Usage: powershell -ExecutionPolicy Bypass -File make-release.ps1 [-Ver 4.0.0] [-BridgeOnly]
param(
    [string]$Ver = "",
    [switch]$BridgeOnly
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

$outDir = Join-Path $root "installer"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$setup = Join-Path $outDir "ClaudeGuard-v$Ver-setup.exe"
$portableZip = Join-Path $outDir "ClaudeGuard-v$Ver-portable.zip"
$upgradeBridge = Join-Path $outDir "ClaudeGuard-v$Ver-upgrade.exe"

if (-not $BridgeOnly) {
    $isccCmd = Get-Command iscc.exe -ErrorAction SilentlyContinue
    $isccCandidates = @(
        $(if ($isccCmd) { $isccCmd.Source }),
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe",
        "C:\Users\daha\AppData\Local\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) {
        throw "ISCC.exe not found. Checked: $($isccCandidates -join '; ')"
    }
    Write-Host "Using Inno Setup compiler: $iscc"

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

    $guiStageExe = Join-Path $stageDir "claudeguard-gui.exe"
    $guiProdVer = (Get-Item $guiStageExe).VersionInfo.ProductVersion
    if ($guiProdVer -ne $Ver) {
        throw "claudeguard-gui.exe ProductVersion='$guiProdVer' does not match '$Ver'"
    }

    if (-not ("CgPeResourceProbe" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CgPeResourceProbe {
    private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr FindResourceW(IntPtr hModule, IntPtr lpName, IntPtr lpType);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);

    public static bool HasGroupIcon(string exePath, int resourceId) {
        IntPtr hMod = LoadLibraryExW(exePath, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
        if (hMod == IntPtr.Zero) {
            return false;
        }
        try {
            IntPtr hRes = FindResourceW(hMod, (IntPtr)resourceId, (IntPtr)14);
            return hRes != IntPtr.Zero && SizeofResource(hMod, hRes) > 0;
        } finally {
            FreeLibrary(hMod);
        }
    }
}
"@
    }
    if (-not [CgPeResourceProbe]::HasGroupIcon($guiStageExe, 1)) {
        throw "claudeguard-gui.exe missing embedded RT_GROUP_ICON (#1)"
    }

    $guiBytes = [System.IO.File]::ReadAllBytes($guiStageExe)
    $guiAscii = [System.Text.Encoding]::ASCII.GetString($guiBytes)
    if (-not $guiAscii.Contains("asInvoker")) {
        throw "claudeguard-gui.exe manifest missing level='asInvoker'"
    }
    if ($guiAscii.Contains("requireAdministrator")) {
        throw "claudeguard-gui.exe must NOT contain requireAdministrator"
    }

    & $iscc "/DMyAppVersionStr=$Ver" (Join-Path $root "claude-guard.iss") | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

    if (-not (Test-Path $setup)) { throw "setup exe not produced: $setup" }

    $portableStage = Join-Path $root "target\portable-stage"
    if (Test-Path $portableStage) { Remove-Item $portableStage -Recurse -Force }
    New-Item -ItemType Directory -Path $portableStage | Out-Null
    try {
        Copy-Item (Join-Path $stageDir "claudeguard-daemon.exe") $portableStage -Force
        Copy-Item (Join-Path $stageDir "claudeguard-cli.exe")    $portableStage -Force
        Copy-Item (Join-Path $stageDir "claudeguard-gui.exe")    $portableStage -Force
        if (Test-Path $portableZip) { Remove-Item $portableZip -Force }
        Compress-Archive -Path (Join-Path $portableStage "*") -DestinationPath $portableZip -CompressionLevel Optimal
    } finally {
        if (Test-Path $portableStage) { Remove-Item $portableStage -Recurse -Force }
    }
}

foreach ($req in @($setup, $portableZip)) {
    if (-not (Test-Path $req)) { throw "required artifact missing: $req" }
}

Write-Host "Building v3->v4 upgrade bridge (target-bridge\release)..."
$prevBridgeSetup = $env:CG_V3_BRIDGE_SETUP_EXE
try {
    $env:CG_V3_BRIDGE_SETUP_EXE = $setup
    cargo build --release --offline --manifest-path (Join-Path $root "crates\cg-v3-bridge\Cargo.toml") --target-dir (Join-Path $root "target-bridge")
    if ($LASTEXITCODE -ne 0) { throw "v3 bridge build failed with exit code $LASTEXITCODE" }
} finally {
    if ($null -eq $prevBridgeSetup) {
        Remove-Item Env:CG_V3_BRIDGE_SETUP_EXE -ErrorAction SilentlyContinue
    } else {
        $env:CG_V3_BRIDGE_SETUP_EXE = $prevBridgeSetup
    }
}
$bridgeSrc = Join-Path $root "target-bridge\release\claudeguard-v3-bridge.exe"
if (-not (Test-Path $bridgeSrc)) { throw "missing bridge binary: $bridgeSrc" }
Copy-Item $bridgeSrc $upgradeBridge -Force

$sumsPath = Join-Path $outDir "SHA256SUMS.txt"
$sumLines = @(
    $setup,
    $portableZip,
    $upgradeBridge
) | ForEach-Object {
    $h = (Get-FileHash $_ -Algorithm SHA256).Hash.ToLowerInvariant()
    "$h  $([System.IO.Path]::GetFileName($_))"
}
[System.IO.File]::WriteAllText($sumsPath, ($sumLines -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))

$hash = (Get-FileHash $setup -Algorithm SHA256).Hash
$len = (Get-Item $setup).Length
$zipHash = (Get-FileHash $portableZip -Algorithm SHA256).Hash
$zipLen = (Get-Item $portableZip).Length
$upHash = (Get-FileHash $upgradeBridge -Algorithm SHA256).Hash
$upLen = (Get-Item $upgradeBridge).Length
Write-Host ("setup:    {0}  sha256={1}  {2:N0} bytes" -f $setup, $hash.Substring(0, 16), $len)
Write-Host ("portable: {0}  sha256={1}  {2:N0} bytes" -f $portableZip, $zipHash.Substring(0, 16), $zipLen)
Write-Host ("upgrade:  {0}  sha256={1}  {2:N0} bytes" -f $upgradeBridge, $upHash.Substring(0, 16), $upLen)
Write-Host ("sums:     {0}" -f $sumsPath)
