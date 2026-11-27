; ClaudeGuard v5 Inno Setup script
; Build: ISCC.exe claude-guard.iss  (from repo root)
; All wizard text comes from ChineseSimplified.isl (official Inno translation),
; so this file is pure ASCII on purpose - do NOT add non-ASCII here without
; saving as UTF-8 with BOM (write/edit tools strip BOM).
; Note: uninstall intentionally KEEPS user data in %ProgramData%\ClaudeGuard
; and %APPDATA%\ClaudeGuard.

#define MyAppName "ClaudeGuard"
#ifndef BackendReleaseDir
  #ifexist "target\release\claudeguard-daemon.exe"
    #define BackendReleaseDir "target\release"
  #else
    #define BackendReleaseDir "target-ws\release"
  #endif
#endif
#ifndef GuiReleaseDir
  #ifexist "target\release\claudeguard-gui.exe"
    #define GuiReleaseDir "target\release"
  #else
    #define GuiReleaseDir "target-gui\release"
  #endif
#endif
#ifndef MyAppVersionStr
  #define RawDaemonVer GetVersionNumbersString(AddBackslash(BackendReleaseDir) + 'claudeguard-daemon.exe')
  #if Copy(RawDaemonVer, Len(RawDaemonVer) - 1, 2) == ".0"
    #define MyAppVersionStr Copy(RawDaemonVer, 1, Len(RawDaemonVer) - 2)
  #else
    #define MyAppVersionStr RawDaemonVer
  #endif
#endif
#define MyAppVersion MyAppVersionStr
#define MyAppPublisher "daha1216"
#define MyAppURL "https://github.com/daha1216/ClaudeGuard"
#define MyAppGuiExeName "claudeguard-gui.exe"
#define MyAppDaemonExeName "claudeguard-daemon.exe"
#define MyAppCliExeName "claudeguard-cli.exe"
#define MyServiceName "ClaudeGuardService"

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
UninstallDisplayIcon={app}\{#MyAppGuiExeName}
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
Name: "autostart"; Description: "{cm:AutoStartProgram,{#MyAppName}}"; GroupDescription: "{cm:AutoStartProgramGroupDescription}"; Flags: checkedonce

[Files]
Source: "{#BackendReleaseDir}\claudeguard-daemon.exe"; DestDir: "{app}"; DestName: "{#MyAppDaemonExeName}"; Flags: ignoreversion
Source: "{#BackendReleaseDir}\claudeguard-cli.exe"; DestDir: "{app}"; DestName: "{#MyAppCliExeName}"; Flags: ignoreversion
Source: "{#GuiReleaseDir}\claudeguard-gui.exe"; DestDir: "{app}"; DestName: "{#MyAppGuiExeName}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppGuiExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppGuiExeName}"; Tasks: desktopicon

[Registry]
; Register normal-privilege tray GUI autostart at user login (runs with user token, no UAC prompt).
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ClaudeGuardGui"; ValueData: """{app}\{#MyAppGuiExeName}"" --tray"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Register and start ClaudeGuardService (LocalSystem, auto-start at boot with 0 UAC prompts).
Filename: "{app}\{#MyAppDaemonExeName}"; Parameters: "--install-service --start"; StatusMsg: "Registering and starting {#MyServiceName}..."; Flags: runhidden waituntilterminated
; Launch normal-privilege GPUI desktop client under the original logged-in user token.
Filename: "{app}\{#MyAppGuiExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent shellexec runasoriginaluser
; Restore normal-privilege tray client during silent upgrades when autostart is enabled.
Filename: "{app}\{#MyAppGuiExeName}"; Parameters: "--tray"; Tasks: autostart; Check: WizardSilent; Flags: nowait shellexec runasoriginaluser

[Code]
const
  MOVEFILE_DELAY_UNTIL_REBOOT = $4;

var
  ExecResultCode: Integer;
  RestoreResultCode: Integer;

function MoveFileExW(lpExistingFileName: String; lpNewFileName: THandle; dwFlags: Cardinal): BOOL;
  external 'MoveFileExW@kernel32.dll stdcall';

procedure CleanupStagingPattern(const StagingDir, Pattern: String);
var
  FindRec: TFindRec;
  FilePath: String;
begin
  if FindFirst(StagingDir + '\' + Pattern, FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
        begin
          FilePath := StagingDir + '\' + FindRec.Name;
          if not DeleteFile(FilePath) then
            MoveFileExW(FilePath, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

procedure CleanupStagingWaiters();
var
  StagingDir: String;
begin
  StagingDir := ExpandConstant('{commonappdata}\ClaudeGuard\staging');
  if DirExists(StagingDir) then
  begin
    CleanupStagingPattern(StagingDir, 'cg-v3-waiter-*.exe');
    CleanupStagingPattern(StagingDir, 'ClaudeGuard-*-setup*.exe');
    if not RemoveDir(StagingDir) then
      MoveFileExW(StagingDir, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
  end;
end;

procedure WaitProcessGone(const ImageName: String);
var
  Idx: Integer;
begin
  for Idx := 1 to 8 do
  begin
    Exec(ExpandConstant('{cmd}'), '/C tasklist /FI "IMAGENAME eq ' + ImageName + '" 2>nul | find /I "' + ImageName + '" >nul', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    if ExecResultCode <> 0 then
      break;
    Sleep(250);
  end;
end;

procedure StopLegacyAndCurrentProcesses();
var
  WaitIdx: Integer;
  ScStopLaunched: Boolean;
begin
  // Stop Windows Service gracefully first so WAL / Flow B cleanup (up to 15s wait hint) runs before upgrade.
  // Skip the 64x250ms poll loop immediately when service is absent (1060) or already stopped (1062).
  ScStopLaunched := Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  if ScStopLaunched and (ExecResultCode <> 1060) and (ExecResultCode <> 1062) then
  begin
    for WaitIdx := 1 to 64 do
    begin
      Exec(ExpandConstant('{cmd}'), '/C sc query {#MyServiceName} | findstr /C:"STOPPED" >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
      if ExecResultCode = 0 then
        break;
      Sleep(250);
    end;
  end;

  // Stop legacy v3 single-exe process and any running v4/v5 binaries before file replacement.
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM ClaudeGuard.exe >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppGuiExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppDaemonExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppCliExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  WaitProcessGone('{#MyAppGuiExeName}');
  WaitProcessGone('{#MyAppDaemonExeName}');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopLegacyAndCurrentProcesses();
  // Clean up legacy v3 HKCU autostart key so v3->v5 upgrade does not double-launch missing v3 exe.
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuard');
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not WizardIsTaskSelected('autostart') then
      RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuardGui');
    CleanupStagingWaiters();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  CliPath: String;
  DaemonPath: String;
  RestoreOk: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Close normal-privilege GUI first so it cannot re-trigger IPC calls while restoring.
    Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppGuiExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM ClaudeGuard.exe >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    WaitProcessGone('{#MyAppGuiExeName}');

    // R06: Restore all network/firewall/NIC/environment modifications BEFORE deleting binaries or service.
    // claudeguard-cli --restore contacts the live daemon via Named Pipe, or runs offline WAL recovery if stopped.
    CliPath := ExpandConstant('{app}\{#MyAppCliExeName}');
    RestoreOk := False;
    if FileExists(CliPath) then
    begin
      if Exec(CliPath, '--restore', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, RestoreResultCode) then
        RestoreOk := (RestoreResultCode = 0);
    end;

    if not RestoreOk then
    begin
      if SuppressibleMsgBox('Failed to verify that ClaudeGuard network and firewall isolation rules were restored.' + #13#10 + #13#10 +
                'Continuing uninstall could leave firewall block rules active and block AI apps.' + #13#10 +
                'Recommended: cancel uninstall and run manually:' + #13#10 + '    ' + CliPath + ' --restore' + #13#10 + #13#10 +
                'Continue uninstall anyway?',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDNO then
        Abort;
    end;

    // Unwire Claude Code Pre-Prompt hooks, PowerShell $PROFILE wrappers, and WSL2 gate shims before removing binaries.
    if FileExists(CliPath) then
      Exec(CliPath, '--unhook-all', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExecResultCode);

    // Stop and unregister ClaudeGuardService via daemon helper (with sc.exe fallback).
    DaemonPath := ExpandConstant('{app}\{#MyAppDaemonExeName}');
    if FileExists(DaemonPath) then
      Exec(DaemonPath, '--uninstall-service', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppDaemonExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    WaitProcessGone('{#MyAppDaemonExeName}');

    // Run a final post-service-stop offline --restore sweep so no persistent boot/WFP/firewall rules survive.
    if FileExists(CliPath) then
    begin
      Exec(CliPath, '--restore', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
      Exec(CliPath, '--unhook-all', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    end;

    // Clean autostart & legacy v1/v3 registry keys while preserving %ProgramData%\ClaudeGuard & %APPDATA%\ClaudeGuard.
    RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuardGui');
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuard');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeGuard');
  end;
end;
