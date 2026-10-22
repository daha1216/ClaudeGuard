//! Explicit acceptance tests of the exact helper embedded in production updates.
use super::*;
use std::process::{Child, ExitStatus};
use std::time::Instant;

struct Parent(Child);
impl Parent {
    fn new() -> Self {
        Self(Command::new("/bin/sleep").arg("30").spawn().unwrap())
    }
    fn identity(&self) -> (u32, String) {
        let pid = self.0.id();
        (pid, process_birth(pid).unwrap())
    }
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for Parent {
    fn drop(&mut self) {
        self.stop();
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    bundle: PathBuf,
    marker: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("cg-relaunch-test-")
            .tempdir()
            .unwrap();
        // Spaces, quotes and command substitution remain literal application path.
        let bundle = directory
            .path()
            .join("Relaunch $(echo harmless) 'quote'.app");
        let marker = directory.path().join("launches.txt");
        std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        let source = format!(
            "#include <fcntl.h>\n#include <unistd.h>\nint main(void){{int fd=open({},O_WRONLY|O_CREAT|O_APPEND,0600);if(fd<0)return 2;write(fd,\"launch\\n\",7);close(fd);return 0;}}\n",
            serde_json::to_string(marker.to_str().unwrap()).unwrap()
        );
        let mut compiler = Command::new("/usr/bin/clang")
            .args(["-x", "c", "-", "-arch", architecture(), "-o"])
            .arg(bundle.join("Contents/MacOS/fixture"))
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(source.as_bytes())
            .unwrap();
        assert!(compiler.wait().unwrap().success());
        let mut info = plist::Dictionary::new();
        info.insert(
            "CFBundleIdentifier".into(),
            format!(
                "local.claudeguard.relaunch.{}",
                directory.path().file_name().unwrap().to_string_lossy()
            )
            .into(),
        );
        for (key, value) in [
            ("CFBundleExecutable", "fixture"),
            ("CFBundleShortVersionString", "1.0.0"),
            ("CFBundleVersion", "1.0.0"),
            ("CFBundlePackageType", "APPL"),
            ("CFBundleName", "ClaudeGuard isolated relaunch fixture"),
        ] {
            info.insert(key.into(), value.into());
        }
        info.insert("LSBackgroundOnly".into(), true.into());
        plist::Value::Dictionary(info)
            .to_file_xml(bundle.join("Contents/Info.plist"))
            .unwrap();
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--deep", "--sign", "-", "--timestamp=none"])
            .arg(&bundle)
            .output()
            .unwrap();
        assert!(
            sign.status.success(),
            "{}",
            String::from_utf8_lossy(&sign.stderr)
        );
        Self {
            _directory: directory,
            bundle,
            marker,
        }
    }
    fn launches(&self) -> usize {
        std::fs::read_to_string(&self.marker)
            .unwrap_or_default()
            .lines()
            .count()
    }
    fn wait_for_launch(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.launches() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            self.launches(),
            1,
            "LaunchServices did not execute the synthetic app exactly once"
        );
    }
}
fn wait_helper(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("owned test relaunch helper did not exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
#[test]
#[ignore = "explicit acceptance: launches a disposable ad-hoc app through real LaunchServices"]
fn real_relaunch_waits_for_exact_parent_exit_and_launches_once() {
    let fixture = Fixture::new();
    let mut parent = Parent::new();
    let (pid, birth) = parent.identity();
    let mut helper = spawn_relaunch(&fixture.bundle, pid, &birth).unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        fixture.launches(),
        0,
        "must not launch while exact parent is alive"
    );
    assert!(helper.try_wait().unwrap().is_none());
    parent.stop();
    assert!(wait_helper(&mut helper).success());
    fixture.wait_for_launch();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(fixture.launches(), 1);
    println!("PASS: exact parent alive -> no launch; parent exit -> real LaunchServices executes fixture once; metacharacter path preserved");
}
#[test]
#[ignore = "explicit acceptance: launches a disposable ad-hoc app through real LaunchServices"]
fn real_relaunch_recycled_identity_does_not_wait_or_signal_unrelated_process() {
    let fixture = Fixture::new();
    let mut parent = Parent::new();
    let (pid, _) = parent.identity();
    let started = Instant::now();
    let mut helper = spawn_relaunch(&fixture.bundle, pid, "Thu Jan  1 00:00:00 1970").unwrap();
    assert!(wait_helper(&mut helper).success());
    assert!(started.elapsed() < Duration::from_secs(10));
    fixture.wait_for_launch();
    assert!(
        parent.0.try_wait().unwrap().is_none(),
        "mismatched live process must not be killed"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(fixture.launches(), 1);
    println!("PASS: mismatched birth time -> prompt single launch; unrelated synthetic parent remains alive");
}
#[test]
#[ignore = "explicit acceptance: verifies a real shell timeout without launching applications"]
fn real_relaunch_times_out_without_launching_or_signalling_parent() {
    let fixture = Fixture::new();
    let mut parent = Parent::new();
    let (pid, birth) = parent.identity();
    let started = Instant::now();
    let mut helper = spawn_relaunch_with_timeout(&fixture.bundle, pid, &birth, 2).unwrap();
    let status = wait_helper(&mut helper);
    assert_eq!(status.code(), Some(75));
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(fixture.launches(), 0);
    assert!(parent.0.try_wait().unwrap().is_none());
    println!("PASS: exact live parent -> helper exits 75 after bounded timeout; no launch and parent remains alive");
}
#[test]
fn relaunch_rejects_empty_identity_and_invalid_wait_without_spawning() {
    assert!(spawn_relaunch_with_timeout(Path::new("/nonexistent.app"), 0, "", 2).is_err());
    assert!(spawn_relaunch_with_timeout(Path::new("/nonexistent.app"), 42, "x\ny", 2).is_err());
    assert!(spawn_relaunch_with_timeout(Path::new("/nonexistent.app"), 42, "x", 0).is_err());
}
