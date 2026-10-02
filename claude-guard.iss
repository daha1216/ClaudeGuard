; ClaudeGuard Inno Setup script
; Build: ISCC.exe installer\claude-guard.iss  (from repo root)
; All wizard text comes from ChineseSimplified.isl (official Inno translation),
; so this file is pure ASCII on purpose - do NOT add non-ASCII here without
; saving as UTF-8 with BOM (write/edit tools strip BOM).
; Note: uninstall intentionally KEEPS user data in %APPDATA%\ClaudeGuard.

#define MyAppName "ClaudeGuard"
; Version: prefer the /DMyAppVersionStr=X.Y.Z passed by make-release.ps1 (the
; exe's win32 version resource is padded to 4 parts, e.g. 2.0.0.0). When
; compiled manually without the define we fall back to reading the exe.
#ifndef MyAppVersionStr
#define MyAppVersionStr GetVersionNumbersString('target\release\claude-guard.exe')
#endif
#define MyAppVersion MyAppVersionStr
#define MyAppPublisher "daha1216"
#define MyAppURL "https://github.com/daha1216/ClaudeGuard"
#define MyAppExeName "ClaudeGuard.exe"

[Setup]
AppId={{F5110E67-B6E3-4B59-B8BE-7F12B33EF85E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName=ClaudeGuard
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=installer
OutputBaseFilename=ClaudeGuard-v{#MyAppVersion}-setup
SetupIconFile=assets\claude.ico
Compression=lzma/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
DisableProgramGroupPage=yes
CloseApplications=no

[Languages]
Name: "chs"; MessagesFile: "installer\ChineseSimplified.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "target\release\claude-guard.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent shellexec

[Code]
var
  TaskkillResultCode: Integer;

// v2 UI runs on WebView2 (Edge Evergreen runtime). Most Windows 10/11 boxes
// have it via Edge updates; we do NOT bundle or auto-download it -- just fail
// with a pointer if it is missing (keeps installer small and dependency-free).
function WebView2Present(): Boolean;
var
  V: String;
begin
  if RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', V) and (V <> '') then begin
    Result := True;
    exit;
  end;
  Result := RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', V) and (V <> '');
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not WebView2Present() then begin
    MsgBox('ClaudeGuard v2 needs the Microsoft Edge WebView2 Runtime, which is not installed on this PC.' + #13#10 + #13#10 +
           'Please install it from:' + #13#10 +
           'https://developer.microsoft.com/microsoft-edge/webview2/' + #13#10 + #13#10 +
           '(Chinese page: search "WebView2 运行时" or visit the same link.)',
           mbError, MB_OK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  // Stop a running instance so the exe can be replaced.
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM ClaudeGuard.exe >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, TaskkillResultCode);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM ClaudeGuard.exe >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, TaskkillResultCode);
    // Remove autostart entry the app may have written (HKCU Run).
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuard');
    // Remove legacy self-install registry key (pre-1.3.3 --install) to avoid
    // a duplicate entry in Add/Remove Programs.
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeGuard');
  end;
end;
