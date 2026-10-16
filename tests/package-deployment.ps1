# Runs the real embedded deployment script with fake Windows package APIs only.
# No installed application, service, profile, or actual deployment is touched.
param(
    [ValidateSet('running','deferred','updated','current','blocked','servicing','incomplete','race','bad-signature','wrong-version')][string]$Case,
    [ValidateSet('claude','codex')][string]$Product = 'claude',
    [ValidateSet('install','finish')][string]$Action = 'install'
)
$ErrorActionPreference = 'Stop'
$global:cgTestDeploymentCount = 0
$global:cgTestIdentity = if ($Product -eq 'claude') {
    @{ Name='Claude'; Family='Claude_pzs8sxrjxfjjc'; Old='2.31226.0.0'; Target='2.37337.1.0' }
} else {
    @{ Name='OpenAI.Codex'; Family='OpenAI.Codex_2p2nqsd0c76g0'; Old='26.928.1915.0'; Target='26.1007.9446.0' }
}
$env:CG_UPDATE_PRODUCT = $Product
$env:CG_UPDATE_ACTION = $Action
$env:CG_UPDATE_VERSION = $global:cgTestIdentity.Target
$tempDir = Join-Path $PSScriptRoot 'output\mock-package'
[IO.Directory]::CreateDirectory($tempDir) | Out-Null
$env:CG_UPDATE_FILE = Join-Path $tempDir ($Product + '-' + $Case + '.msix')
Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
$stream = [IO.File]::Open($env:CG_UPDATE_FILE, 'Create')
$zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
$entry = $zip.CreateEntry('AppxManifest.xml')
$writer = [IO.StreamWriter]::new($entry.Open())
$manifestVersion = if ($Case -eq 'wrong-version') { $global:cgTestIdentity.Old } else { $global:cgTestIdentity.Target }
$writer.Write(('<Package><Identity Name="{0}" Publisher="CN=Test only" ProcessorArchitecture="x64" Version="{1}" /></Package>' -f $global:cgTestIdentity.Name,$manifestVersion))
$writer.Dispose()
$zip.Dispose()
$stream.Dispose()
function Get-AppxPackage {
    param($Name)
    if ($Name -ne $global:cgTestIdentity.Name) { throw 'Wrong product queried' }
    $v = if ($Case -eq 'current' -or ($Case -in @('updated','incomplete') -and $global:cgTestDeploymentCount -gt 0)) { $global:cgTestIdentity.Target } else { $global:cgTestIdentity.Old }
    $status = if ($Case -eq 'servicing' -or ($Case -eq 'incomplete' -and $global:cgTestDeploymentCount -gt 0)) { 'Servicing' } else { 'Ok' }
    # Get-AppxPackage returns Version as System.String, not System.Version.
    # The Codex 928 -> 1007 case must not use lexicographic comparison.
    [pscustomobject]@{ Name=$global:cgTestIdentity.Name; Publisher='CN=Test only'; Architecture='X64'; Version=[string]$v; PackageFamilyName=$global:cgTestIdentity.Family; Status=$status }
}
function Get-Process {
    param($Name,$ErrorAction)
    if ($Case -eq 'running' -or ($Case -eq 'race' -and $global:cgTestDeploymentCount -gt 0)) { [pscustomobject]@{Name='Claude'} }
}
function Get-AuthenticodeSignature {
    param($LiteralPath)
    [pscustomobject]@{Status=$(if ($Case -eq 'bad-signature') { 'NotSigned' } else { 'Valid' })}
}
function Add-AppxPackage {
    [CmdletBinding()]
    param([string]$Path,[switch]$DeferRegistrationWhenPackagesAreInUse,[switch]$RetainFilesOnFailure)
    if (!$RetainFilesOnFailure) { throw 'Missing safe deployment flags' }
    if ([bool]$DeferRegistrationWhenPackagesAreInUse -ne ($Action -eq 'install')) { throw 'Explicit completion must not silently defer again' }
    $global:cgTestDeploymentCount++
    if ($Case -in @('blocked','race')) { throw 'HRESULT 0x80073D02' }
}
$result = & (Join-Path $PSScriptRoot '..\src\claude_package.ps1')
if ($Case -in @('bad-signature','wrong-version')) {
    if ($LASTEXITCODE -ne 2 -or $global:cgTestDeploymentCount -ne 0) { throw 'Invalid package was not rejected before deployment' }
    @{product=$Product;action=$Action;case=$Case;state='rejected';deploymentCalls=0;mockOnly=$true} | ConvertTo-Json -Compress
    exit 0
}
$parsed = $result | ConvertFrom-Json
$expected = switch ($Case) { 'running' { 'waiting' }; 'servicing' { 'unavailable' }; 'incomplete' { 'deferred' }; 'race' { if ($Action -eq 'finish') { 'blocked' } else { 'waiting' } }; default { $Case } }
if ($parsed.state -ne $expected) { throw "Expected $expected, got $($parsed.state)" }
$expectedCount = if ($Case -in @('running','current','servicing')) { 0 } else { 1 }
if ($global:cgTestDeploymentCount -ne $expectedCount) { throw 'Unexpected deployment count' }
@{product=$Product;action=$Action;case=$Case;state=$parsed.state;deploymentCalls=$global:cgTestDeploymentCount;mockOnly=$true} | ConvertTo-Json -Compress
