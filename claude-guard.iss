; ClaudeGuard Inno Setup script
; Build: ISCC.exe installer\claude-guard.iss  (from repo root)
; All wizard text comes from ChineseSimplified.isl (official Inno translation),
; so this file is pure ASCII on purpose - do NOT add non-ASCII here without
; saving as UTF-8 with BOM (write/edit tools strip BOM).
; Note: uninstall intentionally KEEPS user data in %APPDATA%\ClaudeGuard.

#define MyAppName "ClaudeGuard"
; Single source of truth: read version straight from the built exe (set by
; build.rs from Cargo.toml). Keep the exe built BEFORE compiling the installer.
#define MyAppVersion GetVersionNumbersString('target\release\claude-guard.exe')
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
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
var
  TaskkillResultCode: Integer;

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
