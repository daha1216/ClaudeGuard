; ClaudeGuard v4 Inno Setup script
; Build: ISCC.exe claude-guard.iss  (from repo root D:\ClaudeGuard-v4)
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
  #define MyAppVersionStr GetVersionNumbersString(AddBackslash(BackendReleaseDir) + 'claudeguard-daemon.exe')
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
var
  ExecResultCode: Integer;
  RestoreResultCode: Integer;

procedure CleanupStagingWaiters();
var
  StagingDir: String;
  FindRec: TFindRec;
begin
  StagingDir := ExpandConstant('{commonappdata}\ClaudeGuard\staging');
  if DirExists(StagingDir) then
  begin
    if FindFirst(StagingDir + '\cg-v3-waiter-*.exe', FindRec) then
    begin
      try
        repeat
          if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
            DeleteFile(StagingDir + '\' + FindRec.Name);
        until not FindNext(FindRec);
      finally
        FindClose(FindRec);
      end;
    end;
    RemoveDir(StagingDir);
  end;
end;

procedure StopLegacyAndCurrentProcesses();
var
  WaitIdx: Integer;
begin
  // Stop Windows Service gracefully first so WAL / Flow B cleanup (up to 15s wait hint) runs before upgrade.
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  for WaitIdx := 1 to 64 do
  begin
    Exec(ExpandConstant('{cmd}'), '/C sc query {#MyServiceName} | findstr /C:"STOPPED" >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    if ExecResultCode = 0 then
      break;
    Sleep(250);
  end;

  // Stop legacy v3 single-exe process and any running v4 binaries before file replacement.
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM ClaudeGuard.exe >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppGuiExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppDaemonExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppCliExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopLegacyAndCurrentProcesses();
  // Clean up legacy v3 HKCU autostart key so v3->v4 upgrade does not double-launch missing v3 exe.
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuard');
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
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

    // Stop and unregister ClaudeGuardService via daemon helper (with sc.exe fallback).
    DaemonPath := ExpandConstant('{app}\{#MyAppDaemonExeName}');
    if FileExists(DaemonPath) then
      Exec(DaemonPath, '--uninstall-service', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);
    Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#MyAppDaemonExeName} >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ExecResultCode);

    // Clean autostart & legacy v1/v3 registry keys while preserving %ProgramData%\ClaudeGuard & %APPDATA%\ClaudeGuard.
    RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuardGui');
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ClaudeGuard');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeGuard');
  end;
end;
