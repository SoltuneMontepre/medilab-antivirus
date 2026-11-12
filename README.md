# antivirus

A personal antivirus for Windows and Linux, written in Rust. It runs alongside Defender, not instead of it.
Detection uses a SHA-256 hash list and YARA rules (via `yara-x`), and also looks inside archives (ZIP, TAR/GZ, 7z, ISO).

## Build and use

```sh
cargo build --release
target/release/avd scan <path> [-c antivirus.toml]
```

Each detection goes to stdout as one tab-separated line: `path  engine  name  file type`. Paths inside archives use `!`, for example `a.zip!docs/x.exe`.
A summary (counts and elapsed time) goes to stderr. All settings and their defaults are in [`antivirus.toml`](antivirus.toml).

Exit codes, the same as ClamAV: `0` clean, `1` detections found, `2` error.

## Real-time protection

`avd run [-c antivirus.toml]` watches the `[watch]` paths in the foreground (default `C:\Users` on Windows, `/home` and `/tmp` on Linux).
Each written file is scanned once its writes have been quiet for `debounce_ms`; most rescans of unchanged files are verdict-cache hits.
Two worker threads scan at background CPU and I/O priority. Logs are timestamped `LEVEL message` lines on stderr; a detection is one line:
`detection  path  engine  name  file type` (tab-separated, level `WARN`).

Changes made while avd is down are caught up at the next start: Windows replays the USN journal from the saved cursor; Linux rescans the watched paths.

### Run as a service

Windows, from an admin terminal (the service runs as LocalSystem, delayed auto-start, and restarts after 5 s / 30 s / 60 s on failure):

```powershell
target\release\avd install -c C:\path\to\antivirus.toml   # registers and starts the "avd" service; keep the exe and config where they are
target\release\avd uninstall                              # stops and removes it
```

The service logs to `avd.log` in the cache directory (`%ProgramData%\avd\cache\avd.log` by default); a log over 10 MB is moved to `avd.log.old` at start.

Linux (systemd, runs as root):

```sh
sudo install -m 755 target/release/avd /usr/local/bin/avd
sudo install -d /etc/avd && sudo cp -r antivirus.toml signatures /etc/avd/
sudo cp packaging/avd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now avd
journalctl -u avd -f
```

### Known limitations

- Windows: needs admin (reads the NTFS USN journal). Only NTFS volumes are watched; FAT/exFAT sticks and network shares are not.
  Detection happens after the write: a dropped file can run before its scan finishes. Nothing is blocked.
- Linux: needs `CAP_SYS_ADMIN` (fanotify). Executing a watched file waits for a cached verdict or a scan; a scan that takes longer than
  300 ms lets the exec through and the file is scanned afterwards. If avd dies, the kernel allows any pending exec.
- Detections are only logged for now; quarantine and other actions arrive in M4.

## Benchmark tree

`gen_tree` writes a deterministic tree of 10k files: nested dirs, sizes from 0 B to 4 MiB, and mixed PE/ELF/script/PDF/ZIP/OLE files, some of them real ZIPs:

```sh
cargo run --release -p daemon --example gen_tree -- <dir> [count]
target/release/avd scan <dir>
```

## Testing safely

- Never commit EICAR or any other malware sample. Tests build EICAR at runtime from XOR-encoded bytes. Unit tests only scan it in memory. The one integration test that writes it to disk (`daemon/tests/scan.rs`, using `write_eicar`) is `#[ignore]`d.
- To run that test on a machine with Defender, first exclude a fixture folder (from an admin PowerShell), then point the test at it:

  ```powershell
  Add-MpPreference -ExclusionPath C:\avd-fixtures
  $env:AVD_FIXTURE_DIR = "C:\avd-fixtures"; cargo test --workspace -- --include-ignored
  ```

  CI sets up the same exclusion on its Windows runner.
- The real-time test (`daemon/tests/realtime.rs`) drops a harmless file listed on a private hash list. It needs admin (Windows) or root (Linux):
  `cargo test -p daemon --test realtime -- --include-ignored`. The usual `--include-ignored` run skips it with `--skip realtime_`.
- Only handle real malware inside a VM with snapshots. Never handle it on your dev machine.
