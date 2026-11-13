//! End-to-end: `avd scan` on a real EICAR file on disk.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Writes EICAR to `dir/eicar.com`. The bytes are stored XOR 0x55 and decoded at runtime,
/// so the literal never appears in source or in the test binary (Defender would quarantine either).
fn write_eicar(dir: &Path) -> PathBuf {
    const X: [u8; 68] = [
        0x0d, 0x60, 0x1a, 0x74, 0x05, 0x70, 0x15, 0x14, 0x05, 0x0e, 0x61, 0x09, 0x05, 0x0f, 0x0d, 0x60, 0x61, 0x7d,
        0x05, 0x0b, 0x7c, 0x62, 0x16, 0x16, 0x7c, 0x62, 0x28, 0x71, 0x10, 0x1c, 0x16, 0x14, 0x07, 0x78, 0x06, 0x01,
        0x14, 0x1b, 0x11, 0x14, 0x07, 0x11, 0x78, 0x14, 0x1b, 0x01, 0x1c, 0x03, 0x1c, 0x07, 0x00, 0x06, 0x78, 0x01,
        0x10, 0x06, 0x01, 0x78, 0x13, 0x1c, 0x19, 0x10, 0x74, 0x71, 0x1d, 0x7e, 0x1d, 0x7f,
    ];
    // black_box: stop the optimizer from folding the decoded string into the binary.
    let bytes: Vec<u8> = std::hint::black_box(X).iter().map(|b| b ^ 0x55).collect();
    let path = dir.join("eicar.com");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Runs `avd scan <tree> -c <config>`; returns exit code, stdout, and the summary's `<label> N` values.
fn avd(tree: &Path, config: &Path) -> (Option<i32>, String, impl Fn(&str) -> u64) {
    let out = Command::new(env!("CARGO_BIN_EXE_avd")).arg("scan").arg(tree).arg("-c").arg(config).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let stat = move |label: &str| -> u64 {
        let tail = stderr.split(&format!("{label} ")).nth(1).unwrap_or_else(|| panic!("no `{label}` in {stderr}"));
        tail.split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
    };
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned(), stat)
}

/// M2: an unchanged tree is served from the verdict cache (detections included); a modified file is the only rescan.
#[test]
fn rescan_hits_cache_and_replays_detections() {
    use sha2::{Digest, Sha256};
    let dir = std::env::temp_dir().join(format!("avd-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..20 {
        std::fs::write(tree.join(format!("f{i}.txt")), format!("file {i}")).unwrap();
    }
    // A harmless file put on a private hash list, so a detection exists without EICAR on disk.
    let marked = b"harmless, but listed";
    std::fs::write(tree.join("marked.bin"), marked).unwrap();
    let hex: String = Sha256::digest(marked).iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("hashes.txt"), format!("{hex} Test-Marked\n")).unwrap();
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../signatures/rules");
    let config = dir.join("antivirus.toml");
    let toml = format!("hash_list = 'hashes.txt'\nrules_dir = '{}'\ndata_dir = 'data'\n", rules.display());
    std::fs::write(&config, toml).unwrap();

    let (code, _, s) = avd(&tree, &config);
    assert_eq!((code, s("scanned"), s("cache hits")), (Some(1), 21, 0));
    let (code, stdout, s) = avd(&tree, &config);
    assert_eq!((code, s("scanned"), s("cache hits")), (Some(1), 0, 21));
    assert!(stdout.contains("marked.bin\thash\tTest-Marked"), "{stdout}");

    std::fs::write(tree.join("f0.txt"), "changed").unwrap();
    let (_, _, s) = avd(&tree, &config);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!((s("scanned"), s("cache hits")), (1, 20));
}

/// M4: a detected file is quarantined (one detection-log line per detection) and restored byte-identical.
#[test]
fn quarantine_then_restore_byte_identical() {
    use sha2::{Digest, Sha256};
    let dir = std::env::temp_dir().join(format!("avd-quarantine-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let marked = b"harmless, but listed";
    let file = tree.join("marked.bin");
    std::fs::write(&file, marked).unwrap();
    let hex: String = Sha256::digest(marked).iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("hashes.txt"), format!("{hex} Test-Marked\n")).unwrap();
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../signatures/rules");
    let config = dir.join("antivirus.toml");
    let toml = format!(
        "hash_list = 'hashes.txt'\nrules_dir = '{}'\ndata_dir = 'data'\n[actions]\nhash = 'quarantine'\n",
        rules.display()
    );
    std::fs::write(&config, toml).unwrap();
    let avd_cmd = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_avd")).args(args).arg("-c").arg(&config).output().unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
    };

    let (code, _, _) = avd(&tree, &config);
    assert_eq!(code, Some(1));
    assert!(!file.exists(), "detected file still in place");
    let log = std::fs::read_to_string(dir.join("data/detections.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.contains(r#""action":"quarantine","action_result":"quarantined""#), "{log}");

    let (code, list) = avd_cmd(&["quarantine", "list"]);
    assert_eq!(code, Some(0));
    let id = list.split('\t').next().unwrap().to_owned();
    assert_eq!(avd_cmd(&["restore", &id]).0, Some(0));
    let restored = std::fs::read(&file).unwrap();
    let (_, after) = avd_cmd(&["quarantine", "list"]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(restored, marked);
    assert_eq!(after, "");
}

#[test]
#[ignore = "needs a Defender exclusion for the fixture dir; CI runs it with --include-ignored"]
fn eicar_scan_exits_1_with_hash_and_yara() {
    let base = std::env::var_os("AVD_FIXTURE_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let dir = base.join(format!("avd-scan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_eicar(&dir);

    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../antivirus.toml");
    let out = Command::new(env!("CARGO_BIN_EXE_avd")).arg("scan").arg(&dir).arg("-c").arg(&config).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let engines: Vec<&str> = stdout.lines().filter_map(|l| l.split('\t').nth(1)).collect();
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}\nstderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(engines.contains(&"hash") && engines.contains(&"yara"), "{stdout}");
}
