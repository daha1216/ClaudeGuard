#!/usr/bin/env python3
"""Isolated CLI acceptance: read-only statuses and idempotent process-mode recovery.

No GUI, guard workers, network probes, Keychain access, real credentials, or messages.
Use a packaged binary for --notification-status; that query never requests permission.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--notification-status', action='store_true')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='cg-acceptance-') as temporary:
        directory = Path(temporary) / 'profile'
        directory.mkdir()
        env = dict(os.environ, CG_DATA_DIR=str(directory))
        secret_markers = ['SYNTHETIC-WEBHOOK-DO-NOT-DECRYPT', 'SYNTHETIC-SECRET-DO-NOT-DECRYPT', 'SYNTHETIC-QUEUE-BODY']
        fixtures = {
            'config.json': dict(first_run=False, kill_on_fail=False, guarded_agents=[]),
            'feishu.json': dict(enabled=True, webhook=secret_markers[0], secret=secret_markers[1], queue=[dict(id=1, text=secret_markers[2], attempts=0, next=0)]),
            # A stale record must never cause Mac recovery to touch real networking.
            'netcut.json': dict(mode='nics', disabled=['synthetic-never-use']),
        }
        for name, data in fixtures.items():
            (directory / name).write_text(json.dumps(data))
        before = {p.name: p.read_bytes() for p in directory.iterdir()}

        def run(flag):
            result = subprocess.run([str(binary), flag], env=env, capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, (flag, result.returncode, result.stderr)
            assert not any(marker in result.stdout + result.stderr for marker in secret_markers), flag
            return result.stdout

        assert run('--version').startswith('ClaudeGuard ')
        feishu = json.loads(run('--feishu-status'))
        assert feishu['enabled'] and feishu['hasWebhook'] and feishu['hasSecret']
        assert feishu['queued'] == 1
        for flag in ['--claude-update-status', '--codex-update-status']:
            assert json.loads(run(flag))['phase'] != 'unsupported'
        first = json.loads(run('--restore'))
        assert first['networkOk'] is True
        assert json.loads(run('--restore')) == first
        if args.notification_status:
            status = json.loads(run('--notification-status'))
            assert status['ok'] is True
            assert status['permission'] in ['granted', 'denied', 'provisional', 'not_determined', 'unknown']
        after = {p.name: p.read_bytes() for p in directory.iterdir()}
        assert after == before, 'read-only status/recovery changed fixture files'
    print('PASS: isolated status privacy, queued-message preservation, repeated recovery, and fixture immutability' + ('; native notification status queried without permission request' if args.notification_status else ''))


if __name__ == '__main__':
    main()
