#!/usr/bin/env python3
"""End-to-end CLI probes against a loopback proxy fixture; never uses user settings."""
import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    received = []
    reply = {'status': 200, 'body': 'ip=203.0.113.7\nloc=US\n'}

    class Proxy(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.path)
            self.send_response(reply['status'])
            self.end_headers()
            self.wfile.write(reply['body'].encode())

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='cg-cli-') as temp:
            directory = Path(temp)
            env = dict(os.environ, CG_DATA_DIR=temp)
            targets = [dict(id=i, name=i, builtin=True, enabled=False, anchor_url='https://example.com/', anchor_kind='trace', expect_ips=[], expect_regions=[]) for i in ['local', 'claude', 'codex', 'antigravity']]
            target = dict(id='fixture', name='fixture', builtin=False, enabled=True,
                          anchor_url='http://anchor.invalid/cdn-cgi/trace', anchor_kind='trace',
                          expect_ips=['203.0.113.7'], expect_regions=[], timeout_secs=3, bind_agent=None)
            config = dict(version=3, proxy_host='127.0.0.1', proxy_port=server.server_port,
                          targets=targets + [target], guarded_agents=[], kill_on_fail=False,
                          quarantine_on_fail=False, cut_network=False, first_run=False)

            def check(expected, code):
                (directory / 'config.json').write_text(json.dumps(config))
                result = subprocess.run([str(binary), '--check'], env=env, capture_output=True, text=True, timeout=15)
                assert result.returncode == code, (result.stderr, result.stdout)
                payload = json.loads(result.stdout)
                assert len(payload['targets']) == 1, payload
                assert payload['targets'][0]['verdict'] == expected, payload
                assert payload['passed'] == (code == 0), payload
                assert not (directory / 'netcut.json').exists()

            check('pass', 0)
            reply['body'] = 'ip=198.51.100.8\nloc=GB\n'
            check('fail', 2)
            target['expect_regions'] = ['GB']
            check('pass', 0)  # Upstream OR semantics: region match is sufficient.
            reply['body'] = '<html>no exit information</html>'
            check('unverified', 2)
            target['anchor_kind'] = 'reachability'
            reply['status'] = 403
            check('pass', 0)  # Upstream: any HTTP response means reachable.
            assert received == [target['anchor_url']] * 5, received
            # The target host has no DNS entry: these successes prove explicit proxy use.
            config['proxy_port'] = 0  # migration changes it; replace with a closed loopback port
            import socket
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                config['proxy_port'] = sock.getsockname()[1]
            target['anchor_kind'] = 'trace'
            check('unverified', 2)
            assert len(received) == 5
            for flag in ['--claude-update-status', '--codex-update-status']:
                result = subprocess.run([str(binary), flag], env=env, capture_output=True, text=True, check=True)
                assert json.loads(result.stdout)['phase'] != 'unsupported'
            print('PASS: 6 isolated CLI probe cases; proxy-only routing; 2 native updater status checks')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    main()
