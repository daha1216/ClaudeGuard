# Embedded by claude_update.rs; runs under Windows PowerShell 5.1 (Appx support).
# Parameters arrive as environment variables, never interpolated executable code.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
function CurrentPackage {
    if ($env:CG_UPDATE_PRODUCT -eq 'claude') { $name='Claude'; $family='Claude_pzs8sxrjxfjjc' }
    elseif ($env:CG_UPDATE_PRODUCT -eq 'codex') { $name='OpenAI.Codex'; $family='OpenAI.Codex_2p2nqsd0c76g0' }
    else { throw 'Unknown product' }
    $packages = @(Get-AppxPackage -Name $name | Where-Object { $_.PackageFamilyName -eq $family })
    if ($packages.Count -ne 1) { throw 'Expected exactly one installed official package' }
    return $packages[0]
}
function Running {
    # Also wait for Claude Code tasks; never force-close user work.
    if ($env:CG_UPDATE_PRODUCT -eq 'claude') { return [bool](Get-Process -Name Claude -ErrorAction SilentlyContinue) }
    # Conservative: wait for desktop windows and CLI tasks. Do not wait for the
    # packaged sandbox service, whose lifetime is managed by Windows deployment.
    return [bool](Get-Process -Name ChatGPT,Codex,'codex-command-runner' -ErrorAction SilentlyContinue)
}
function BlockerNames {
    $names = if ($env:CG_UPDATE_PRODUCT -eq 'claude') { @('Claude') } else { @('ChatGPT','Codex','codex-command-runner') }
    @(Get-Process -Name $names -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
}
function PackageHealthy($package) { return $package.Status.ToString() -eq 'Ok' }
function VerifyPackage($installed, $file) {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Update package missing' }
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid') { throw ('Package signature is not valid: ' + $signature.Status) }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($file)
    try {
        $entry = $zip.GetEntry('AppxManifest.xml')
        if (!$entry -or $entry.Length -gt 1048576) { throw 'Invalid package manifest' }
        $reader = [IO.StreamReader]::new($entry.Open())
        try {
            $xml = [Xml.XmlDocument]::new()
            $xml.XmlResolver = $null
            $xml.LoadXml($reader.ReadToEnd())
        } finally { $reader.Dispose() }
        $identity = $xml.DocumentElement.SelectSingleNode("*[local-name()='Identity']")
        if ($identity.GetAttribute('Name') -ne $installed.Name -or $identity.GetAttribute('Publisher') -ne $installed.Publisher) {
            throw 'Update package identity or publisher differs from installed application'
        }
        if ($identity.GetAttribute('ProcessorArchitecture') -ne $installed.Architecture.ToString().ToLowerInvariant()) {
            throw 'Update package architecture differs from installed application'
        }
        $version = [version]$identity.GetAttribute('Version')
        if ($version -ne [version]$env:CG_UPDATE_VERSION) { throw 'Package version differs from requested version' }
        return $version
    } finally { $zip.Dispose() }
}
try {
    $installed = CurrentPackage
    if ($env:CG_UPDATE_ACTION -eq 'inspect') {
        $reboot = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        $boot = ''
        try { $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o') } catch { }
        @{version=$installed.Version.ToString(); architecture=$installed.Architecture.ToString().ToLowerInvariant(); running=(Running); blockers=@(BlockerNames); family=$installed.PackageFamilyName; healthy=(PackageHealthy $installed); package_status=$installed.Status.ToString(); reboot_required=$reboot; boot_id=$boot} | ConvertTo-Json -Compress
    } elseif ($env:CG_UPDATE_ACTION -in @('verify','install','finish')) {
        $version = VerifyPackage $installed $env:CG_UPDATE_FILE
        if ($env:CG_UPDATE_ACTION -eq 'verify') {
            @{version=$version.ToString(); state='verified'} | ConvertTo-Json -Compress
        } elseif (!(PackageHealthy $installed)) {
            @{version=$installed.Version.ToString(); state='unavailable'; package_status=$installed.Status.ToString()} | ConvertTo-Json -Compress
        } elseif ($version -le [version]$installed.Version) {
            @{version=$installed.Version.ToString(); state='current'; healthy=$true} | ConvertTo-Json -Compress
        } elseif (Running) {
            @{version=$installed.Version.ToString(); state='waiting'} | ConvertTo-Json -Compress
        } else {
            # Update the existing per-user package only. No removal, reset, repair,
            # force-close, downgrade, provisioning, or profile/token manipulation.
            # The Add parameter set updates the same installed package family.
            # -Update is the dependency-update parameter set and cannot be combined
            # with deferred registration. Windows may retain an active AUMID even
            # after the visible processes exit; let it finish on later activation.
            try {
                if ($env:CG_UPDATE_ACTION -eq 'finish') {
                    # Explicit one-shot completion: do not defer again indefinitely.
                    Add-AppxPackage -Path $env:CG_UPDATE_FILE -RetainFilesOnFailure -ErrorAction Stop
                } else {
                    Add-AppxPackage -Path $env:CG_UPDATE_FILE -DeferRegistrationWhenPackagesAreInUse -RetainFilesOnFailure -ErrorAction Stop
                }
            }
            catch {
                if ($_.Exception.ToString() -match '80073D02') {
                    $next = if ($env:CG_UPDATE_ACTION -ne 'finish' -and (Running)) { 'waiting' } else { 'blocked' }
                    @{version=$installed.Version.ToString(); state=$next} | ConvertTo-Json -Compress
                    exit 0
                }
                throw
            }
            $after = CurrentPackage
            # Appx exposes Version as a string: compare numeric components (928 < 1007).
            $next = if ([version]$after.Version -lt $version -or !(PackageHealthy $after)) { 'deferred' } else { 'updated' }
            @{version=$after.Version.ToString(); state=$next; healthy=(PackageHealthy $after)} | ConvertTo-Json -Compress
        }
    } else { throw 'Unknown update action' }
} catch {
    # Only deployment diagnostics; no profile files or authentication state are read.
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
