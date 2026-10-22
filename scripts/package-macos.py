#!/usr/bin/env python3
"""Build a locally ad-hoc signed macOS preview. Never installs or launches it."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--target', choices=['aarch64-apple-darwin', 'x86_64-apple-darwin'])
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise SystemExit('macOS is required')
    root = Path(__file__).resolve().parent.parent
    cargo = os.environ.get('CARGO') or shutil.which('cargo') or str(Path.home() / '.cargo/bin/cargo')
    metadata = json.loads(subprocess.check_output([cargo, 'metadata', '--no-deps', '--format-version', '1', '--locked'], cwd=root))
    package = next(p for p in metadata['packages'] if Path(p['manifest_path']).resolve() == root / 'Cargo.toml')
    command = [cargo, 'build', '--locked'] + ([] if args.debug else ['--release'])
    if args.target:
        command += ['--target', args.target]
    subprocess.run(command, cwd=root, check=True)
    config = json.loads((root / 'tauri.conf.json').read_text())
    dist = args.output_dir or (root / 'dist' / args.target if args.target else root / 'dist')
    dist.mkdir(parents=True, exist_ok=True)
    app = dist / 'ClaudeGuard.app'
    # Build in a new directory before replacing our own generated output.
    with tempfile.TemporaryDirectory(prefix='macos-package-', dir=dist) as temp:
        staged = Path(temp) / 'ClaudeGuard.app'
        macos = staged / 'Contents/MacOS'
        resources = staged / 'Contents/Resources'
        macos.mkdir(parents=True)
        resources.mkdir()
        target_dir = Path(metadata['target_directory'])
        if args.target:
            target_dir /= args.target
        binary = target_dir / ('debug' if args.debug else 'release') / 'claude-guard'
        architectures = subprocess.check_output(['/usr/bin/lipo', '-archs', str(binary)], text=True).split()
        if len(architectures) != 1 or architectures[0] not in ['arm64', 'x86_64']:
            raise SystemExit('Expected a single supported macOS architecture; package each target separately')
        architecture = architectures[0]
        shutil.copy2(binary, macos / 'claude-guard')
        iconset = Path(temp) / 'AppIcon.iconset'
        iconset.mkdir()
        for size in [16, 32, 128, 256, 512]:
            for scale in [1, 2]:
                name = f'icon_{size}x{size}' + ('@2x' if scale == 2 else '') + '.png'
                subprocess.run(['/usr/bin/sips', '-z', str(size * scale), str(size * scale), str(root / 'assets/macos-icon.png'), '--out', str(iconset / name)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['/usr/bin/iconutil', '-c', 'icns', str(iconset), '-o', str(resources / 'AppIcon.icns')], check=True)
        frameworks = staged / 'Contents/Frameworks'
        frameworks.mkdir()
        notification_library = frameworks / 'CGNotifications.dylib'
        subprocess.run(['/usr/bin/xcrun', 'swiftc', '-swift-version', '5', '-O', '-emit-library',
                        '-target', f'{architecture}-apple-macos12.0',
                        '-o', str(notification_library), str(root / 'native/Notifications.swift'),
                        '-framework', 'UserNotifications'], check=True)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(notification_library)], check=True)
        info = dict(CFBundleName=config['productName'], CFBundleDisplayName=config['productName'],
                    CFBundleIdentifier=config['identifier'], CFBundleExecutable='claude-guard',
                    CFBundlePackageType='APPL', CFBundleShortVersionString=package['version'],
                    CFBundleVersion=package['version'], CFBundleIconFile='AppIcon',
                    LSMinimumSystemVersion='12.0', NSHighResolutionCapable=True)
        (staged / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(staged)], check=True)
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(staged)], check=True)
        if app.exists():
            shutil.rmtree(app)
        shutil.move(staged, app)
    print(f'Local preview (ad-hoc signed, not notarized): {app}')


if __name__ == '__main__':
    main()
