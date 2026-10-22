#!/usr/bin/env python3
"""Offline packaging acceptance with disposable test-only keys and signed app.

The temporary CLI uses the real Minisign crate, not a successful-signature mock.
No test key or generated package is written to the repository or published.
"""
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CARGO = pathlib.Path.home() / ".cargo/bin/cargo"
ARCH = "arm64" if platform.machine() == "arm64" else "x86_64"
SIGNER = r'''
use minisign::{KeyPair,PublicKeyBox,SecretKeyBox,SignatureBox};
use std::{fs,io::Cursor,path::PathBuf};
fn main() {
    let args:Vec<String>=std::env::args().collect();
    if args[1]=="--test-keypair" {
        let dir=PathBuf::from(&args[2]);
        let pair=KeyPair::generate_unencrypted_keypair().unwrap();
        fs::write(dir.join("test.pub"),pair.pk.to_box().unwrap().to_string()).unwrap();
        fs::write(dir.join("test.key"),pair.sk.to_box(Some("DISPOSABLE TEST KEY")).unwrap().to_string()).unwrap();
        return;
    }
    let arg=|flag:&str|args[args.iter().position(|s|s==flag).unwrap()+1].clone();
    let bytes=fs::read(arg("-m")).unwrap();
    if args[1]=="-S" {
        let sk=SecretKeyBox::from_string(&fs::read_to_string(arg("-s")).unwrap()).unwrap().into_unencrypted_secret_key().unwrap();
        let sig=minisign::sign(None,&sk,Cursor::new(bytes),Some("ephemeral packaging acceptance"),None).unwrap();
        fs::write(arg("-x"),sig.into_string()).unwrap();
    } else {
        let pk=PublicKeyBox::from_string(&fs::read_to_string(arg("-p")).unwrap()).unwrap().into_public_key().unwrap();
        let sig=SignatureBox::from_string(&fs::read_to_string(arg("-x")).unwrap()).unwrap();
        minisign::verify(&pk,&sig,Cursor::new(bytes),true,false,false).unwrap();
    }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="cg-self-update-packaging-test-") as temporary:
        directory = pathlib.Path(temporary)
        (directory / "src").mkdir()
        (directory / "Cargo.toml").write_text('[package]\nname="minisign"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nminisign="=0.10.0"\n', encoding="utf-8")
        (directory / "src/main.rs").write_text(SIGNER, encoding="utf-8")
        subprocess.run([str(CARGO), "build", "--offline", "--quiet", "--manifest-path", str(directory / "Cargo.toml")], check=True)
        signer = directory / "target/debug/minisign"
        subprocess.run([str(signer), "--test-keypair", str(directory)], check=True)
        app = directory / "ClaudeGuard.app"
        (app / "Contents/MacOS").mkdir(parents=True)
        subprocess.run(["/usr/bin/clang", "-x", "c", "-", "-arch", ARCH, "-o", str(app / "Contents/MacOS/test")], input=b"int main(void){return 0;}\n", check=True)
        with (app / "Contents/Info.plist").open("wb") as stream:
            plistlib.dump({"CFBundleIdentifier": "com.daha.claudeguard", "CFBundleShortVersionString": "999.0.0", "CFBundleVersion": "999.0.0", "CFBundleExecutable": "test"}, stream)
        subprocess.run(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", "--timestamp=none", str(app)], check=True, capture_output=True)
        env = dict(os.environ, PATH=str(signer.parent) + os.pathsep + os.environ.get("PATH", ""))
        out = directory / "assets"
        command = [shutil.which("python3"), str(ROOT / "scripts/package-self-update-macos.py"), "--app", str(app), "--output-dir", str(out), "--architecture", ARCH, "--secret-key", str(directory / "test.key"), "--public-key", str(directory / "test.pub")]
        subprocess.run(command, env=env, check=True)
        name = f"ClaudeGuard-v999.0.0-macos-{ARCH}.zip"
        archive = out / name
        manifest = out / (name + ".json")
        signature = out / (name + ".json.minisig")
        data = json.loads(manifest.read_text())
        assert data["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
        assert data["size"] == archive.stat().st_size
        subprocess.run([str(signer), "-V", "-p", str(directory / "test.pub"), "-m", str(manifest), "-x", str(signature)], check=True)
        result = subprocess.run(command, env=env, capture_output=True)
        assert result.returncode != 0, "existing release assets must never be overwritten"
        print("PASS: full ZIP/manifest/real Minisign signing and verification; overwrite rejected; disposable keys removed.")


if __name__ == "__main__":
    main()
