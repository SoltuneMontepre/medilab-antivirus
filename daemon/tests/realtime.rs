//! End-to-end: `avd run` watching a temp dir detects a dropped file, debounces rewrites, and (Linux) blocks its exec.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Kills the daemon on every exit path, including a failed assert.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits up to `timeout` for a line matching `want`; every line seen is also echoed for debugging.
fn wait_for(lines: &Receiver<String>, timeout: Duration, want: impl Fn(&str) -> bool) -> Option<String> {
    let deadline = Instant::now() + timeout;
    while let Ok(line) = lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        if want(&line) {
            return Some(line);
        }
    }
    None
}

#[test]
#[ignore = "needs admin (Windows USN) or root (Linux fanotify)"]
fn realtime_detects_debounces_and_blocks() {
    use sha2::{Digest, Sha256};
    let dir = std::env::temp_dir().join(format!("avd-realtime-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("watched")).unwrap();
    let watched = dir.join("watched");

    // A harmless script put on a private hash list, so a detection exists without EICAR on disk.
    let marked: &[u8] = b"#!/bin/sh\necho avd-test-marked\n";
    let hex: String = Sha256::digest(marked).iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("hashes.txt"), format!("{hex} Test-Marked\n")).unwrap();
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../signatures/rules");
    let config = dir.join("antivirus.toml");
    let toml = format!(
        "hash_list = 'hashes.txt'\nrules_dir = '{}'\ndata_dir = 'data'\n[watch]\npaths = ['{}']\ndebounce_ms = 1000\n",
        rules.display(),
        watched.display()
    );
    std::fs::write(&config, toml).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_avd"))
        .arg("run")
        .arg("-c")
        .arg(&config)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let daemon = Daemon(child);
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("avd: {line}");
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    assert!(
        wait_for(&lines, Duration::from_secs(30), |l| l.contains("watching")).is_some(),
        "avd never started watching"
    );

    // Let the sensor's startup rescan of the (empty) dir finish, so the detection below comes from the write event.
    std::thread::sleep(Duration::from_secs(1));
    let target = watched.join("marked.sh");
    let detected = |l: &str| l.contains("detection\t") && l.contains("marked.sh") && l.contains("Test-Marked");
    std::fs::write(&target, marked).unwrap();
    assert!(wait_for(&lines, Duration::from_secs(10), detected).is_some(), "dropped file not detected");

    // 100 rewrites in a burst settle into one scan, so one more detection.
    for _ in 0..100 {
        std::fs::write(&target, marked).unwrap();
    }
    assert!(wait_for(&lines, Duration::from_secs(10), detected).is_some(), "rewritten file not detected");
    let extra = wait_for(&lines, Duration::from_secs(3), detected);
    assert!(extra.is_none(), "rewrites were not debounced: {extra:?}");

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = Command::new(&target).status().expect_err("exec of a detected file must be denied");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }

    drop(daemon);
    let _ = std::fs::remove_dir_all(&dir);
}
