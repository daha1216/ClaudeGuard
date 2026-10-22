#!/usr/bin/env python3
"""Native smoke lifecycle acceptance using exact PID, AppKit and isolated settings.

Never runs normal guard monitoring, changes login items, or addresses an app by
bundle identifier. Refuses to run if this ClaudeGuard bundle is already running.
Requires macOS GUI session and Command Line Tools; no Accessibility permission.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

SWIFT = r'''
import AppKit
import CoreGraphics
import Foundation
let pid = pid_t(CommandLine.arguments[1])!
let expected = CommandLine.arguments[2]
let action = CommandLine.arguments[3]
guard let app = NSRunningApplication(processIdentifier: pid),
      app.executableURL?.path == expected else {
    print("{\"running\":false}")
    exit(action == "status" ? 0 : 1)
}
var accepted = true
if action == "terminate" { accepted = app.terminate() }
let windows = CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID) as? [[String: Any]] ?? []
let visible = windows.filter { entry in
    guard let owner = entry[kCGWindowOwnerPID as String] as? Int,
          let layer = entry[kCGWindowLayer as String] as? Int,
          let on = entry[kCGWindowIsOnscreen as String] as? Bool,
          let bounds = entry[kCGWindowBounds as String] as? [String: Any],
          let width = bounds["Width"] as? Double,
          let height = bounds["Height"] as? Double else { return false }
    return owner == Int(pid) && layer == 0 && on && width >= 400 && height >= 300
}.count
let value: [String: Any] = ["running": true, "hidden": app.isHidden, "active": app.isActive, "visibleWindows": visible, "accepted": accepted]
let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
print(String(data: data, encoding: .utf8)!)
'''


def processes(binary):
    output = subprocess.check_output(['/bin/ps', '-axo', 'pid=,comm='], text=True)
    found = []
    for line in output.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[1] == str(binary):
            found.append(int(fields[0]))
    return found


def wait_for(operation, predicate, label, timeout=15):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = operation()
        if predicate(last):
            return last
        time.sleep(0.2)
    raise AssertionError((label, last))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app', type=Path)
    args = parser.parse_args()
    app = args.app.resolve(strict=True)
    binary = app / 'Contents/MacOS/claude-guard'
    assert binary.is_file() and app.suffix == '.app'
    assert not processes(binary), 'Refusing to interact with a pre-existing instance'
    with tempfile.TemporaryDirectory(prefix='cg-lifecycle-') as temporary:
        root = Path(temporary)
        profile = root / 'profile'
        profile.mkdir()
        config = dict(version=3, first_run=False, kill_on_fail=False, guarded_agents=[],
                      quarantine_on_fail=False, cut_network=False, sweep_on_exit=False,
                      close_to_tray=True, auto_start_with_system=False, auto_upd_check=False,
                      notify=dict(enabled=False))
        (profile / 'config.json').write_text(json.dumps(config))
        (profile / 'feishu.json').write_text(json.dumps(dict(enabled=False)))
        for product in ['claude', 'codex']:
            (profile / (product + '-update.json')).write_text(json.dumps(dict(status=dict(enabled=False))))
        source = root / 'control.swift'
        source.write_text(SWIFT)
        control = root / 'control'
        subprocess.run(['/usr/bin/swiftc', str(source), '-o', str(control)], check=True, capture_output=True, text=True)
        env = dict(os.environ, CG_DATA_DIR=str(profile), CG_SMOKE_STATE='pass')
        pid = None
        evidence = {}

        def native(action='status'):
            return json.loads(subprocess.check_output([str(control), str(pid), str(binary), action], text=True))

        def secondary(flag):
            # Rosetta's first cross-architecture LaunchServices handoff can exceed
            # the native startup window even after the primary app is running.
            result = subprocess.run([str(binary), flag], env=env, capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, (flag, result.stderr)
            assert processes(binary) == [pid], (flag, 'duplicate instance remained')

        try:
            subprocess.run(['/usr/bin/open', '-n', '-g', '-a', str(app), '--env', 'CG_DATA_DIR=' + str(profile),
                            '--env', 'CG_SMOKE_STATE=pass', '--args', '--tray'], check=True)
            matches = wait_for(lambda: processes(binary), lambda p: len(p) == 1, 'isolated process created')
            pid = matches[0]
            evidence['trayStartup'] = wait_for(native, lambda s: s['running'] and s['visibleWindows'] == 0, 'tray startup stays hidden')
            secondary('--tray')
            time.sleep(0.6)
            evidence['trayHandoff'] = native()
            assert evidence['trayHandoff']['visibleWindows'] == 0
            assert evidence['trayHandoff']['active'] == evidence['trayStartup']['active'], 'tray handoff unexpectedly activated the app'
            subprocess.run(['/usr/bin/open', '-g', '-a', str(app)], check=True)
            # Reopen dispatch is queued; allow it to settle before checking that a
            # background login-style open leaves the existing window hidden.
            time.sleep(0.8)
            evidence['backgroundReopen'] = native()
            assert evidence['backgroundReopen']['visibleWindows'] == 0
            assert evidence['backgroundReopen']['active'] is False
            assert processes(binary) == [pid]
            subprocess.run(['/usr/bin/open', '-a', str(app)], check=True)
            evidence['foregroundReopen'] = wait_for(native, lambda s: s['visibleWindows'] == 1 and s['active'], 'Finder/Dock-style reopen restores and activates main window')
            assert processes(binary) == [pid]
            secondary('--settings')
            evidence['settingsHandoff'] = wait_for(native, lambda s: s['visibleWindows'] == 1, 'settings handoff shows existing window')
            # set_focus may be queued after show; observe its eventual native state.
            focus_deadline = time.monotonic() + 3
            while time.monotonic() < focus_deadline:
                evidence['settingsFocusAfterQueue'] = native()
                if evidence['settingsFocusAfterQueue']['active']:
                    break
                time.sleep(0.2)
            assert evidence['settingsFocusAfterQueue']['active'], 'settings handoff lost native foreground activation'
            secondary('--settings')
            evidence['repeatedSettingsHandoff'] = wait_for(native, lambda s: s['visibleWindows'] == 1, 'repeated handoff keeps single native window')
            assert native('terminate')['accepted'], 'normal AppKit Quit was rejected'
            wait_for(lambda: processes(binary), lambda p: not p, 'normal native Quit exits')
            evidence['normalQuit'] = True
            assert not (profile / 'netcut.json').exists()
            assert not (profile / 'claude-macos-update-journal.json').exists()
            assert not (profile / 'codex-macos-update-journal.json').exists()
            persisted = json.loads((profile / 'config.json').read_text())
            assert persisted['kill_on_fail'] is False and persisted['guarded_agents'] == []
            assert persisted['auto_start_with_system'] is False and persisted['auto_upd_check'] is False
            assert json.loads((profile / 'feishu.json').read_text())['enabled'] is False
            evidence['isolatedConfigPreserved'] = True
            evidence['noNetworkState'] = True
            print(json.dumps(dict(passed=True, evidence=evidence, boundaries=['CG_SMOKE_STATE skips monitoring and update workers', 'settings handoff checks native visibility, not DOM expansion', 'red close button, hide-after-show and actual logout/login not exercised']), ensure_ascii=False, indent=2))
        finally:
            if pid is not None and pid in processes(binary):
                # Only terminate the exact process this test created, using normal Quit.
                native('terminate')
                wait_for(lambda: processes(binary), lambda p: not p, 'test process cleanup')


if __name__ == '__main__':
    main()
