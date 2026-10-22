#!/usr/bin/env python3
"""Create authenticated Mac self-update assets. Never generates signing keys.

Requires an existing Minisign installation and maintainer-controlled private key.
The public key must also be compiled into the application with
CG_MACOS_UPDATE_PUBLIC_KEY (the base64 line, not the public-key file path).
Produces a full .zip, signed .zip.json, and .zip.json.minisig; publishes nothing.
"""
import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    parser.add_argument("--secret-key", type=pathlib.Path, required=True)
    parser.add_argument("--public-key", type=pathlib.Path, required=True)
    args = parser.parse_args()
    minisign = shutil.which("minisign")
    if minisign is None:
        parser.error("minisign is required; no unsigned update assets will be produced")
    if not args.secret_key.is_file() or not args.public_key.is_file():
        parser.error("existing maintainer private and public key files are required")
    app = args.app.resolve(strict=True)
    if app.suffix != ".app":
        parser.error("a complete .app bundle is required")
    with (app / "Contents/Info.plist").open("rb") as stream:
        info = plistlib.load(stream)
    version = info["CFBundleShortVersionString"]
    if info.get("CFBundleIdentifier") != "com.daha.claudeguard" or not re.fullmatch(r"\d+(?:\.\d+){1,3}", version):
        parser.error("invalid application identity or release version")
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    binary = app / "Contents/MacOS" / info["CFBundleExecutable"]
    arches = subprocess.check_output(["/usr/bin/lipo", "-archs", str(binary)], text=True).split()
    if args.architecture not in arches:
        parser.error("application does not contain the requested architecture")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    name = f"ClaudeGuard-v{version}-macos-{args.architecture}.zip"
    targets = [args.output_dir / (name + suffix) for suffix in ("", ".json", ".json.minisig")]
    if any(path.exists() for path in targets):
        parser.error("an output asset already exists; refusing to overwrite")
    with tempfile.TemporaryDirectory(prefix="claudeguard-release-") as temporary:
        directory = pathlib.Path(temporary)
        archive = directory / name
        subprocess.run(["/usr/bin/ditto", "-c", "-k", "--keepParent", str(app), str(archive)], check=True)
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        size = archive.stat().st_size
        if not 0 < size <= 1024 ** 3:
            parser.error("archive exceeds updater size limits")
        manifest = directory / (name + ".json")
        manifest.write_text(json.dumps({
            "version": version,
            "architecture": args.architecture,
            "url": f"https://github.com/daha1216/ClaudeGuard/releases/download/v{version}/{name}",
            "size": size,
            "sha256": digest.hexdigest(),
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        signature = directory / (name + ".json.minisig")
        subprocess.run([minisign, "-S", "-s", str(args.secret_key.resolve()), "-m", str(manifest), "-x", str(signature)], check=True)
        subprocess.run([minisign, "-V", "-p", str(args.public_key.resolve()), "-m", str(manifest), "-x", str(signature)], check=True)
        for source, target in zip((archive, manifest, signature), targets):
            # Exclusive create: a failed or competing packaging run cannot replace assets.
            with source.open("rb") as reader, target.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
    print("Created verified Mac update ZIP, manifest, and signature. Nothing was uploaded.")


if __name__ == "__main__":
    main()
