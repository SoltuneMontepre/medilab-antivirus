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
`detection  path  engine  name  file type  action: result` (tab-separated).

Changes made while avd is down are caught up at the next start: Windows replays the USN journal from the saved cursor; Linux rescans the watched paths.

### Run as a service

Windows, from an admin terminal. Program Files is admin-only, so other programs can't edit the exe, config or rules
(avd warns at startup when they can). The service runs as LocalSystem, delayed auto-start, and restarts after 5 s / 30 s / 60 s on failure:

```powershell
$d = "$env:ProgramFiles\avd"; mkdir $d -Force
copy target\release\avd.exe, antivirus.toml $d; copy -Recurse -Force signatures $d
& "$d\avd.exe" install -c "$d\antivirus.toml"   # registers and starts the "avd" service
& "$d\avd.exe" uninstall                        # stops and removes it
```

The service logs to `avd.log` in the data directory (`%ProgramData%\avd\avd.log` by default); a log over 10 MB is moved to `avd.log.old` at start.

Linux (systemd, runs as root, restarts 5 s after a failure):

```sh
sudo install -m 755 target/release/avd /usr/local/bin/avd
sudo install -d /etc/avd && sudo cp -r antivirus.toml signatures /etc/avd/
sudo cp packaging/avd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now avd
journalctl -u avd -f
```

## Response

What happens to a detected file is set per engine in `[actions]`: `alert` (default), `quarantine`, `suspend` or `kill`, each
including the ones before it. It applies to `avd scan` and to real-time protection. Keep `alert` until the detection log has
shown no false positives for an engine during normal use; [docs/false-positives.md](docs/false-positives.md) is the procedure and record.

- **Detection log**: one JSON line per detection in `<data dir>/detections.jsonl` (time, path, sha256, file type, engine, rule,
  pid, action, action result, quarantine id); rotated at 10 MB, 5 old files kept. `avd detections [--since 24h]` prints recent ones.
- **Quarantine**: the file is copied, XOR-neutered, to `<data dir>/quarantine/<id>.bin` with an `<id>.json` sidecar (original
  path, sha256, size, time, detections, permissions). Both are fsynced before the original is deleted, so a failure leaves the
  original in place. A file another process holds open (Windows) is deleted at the next reboot.
  `avd quarantine list` shows entries; `avd restore <id> [--to <path>] [--force] [--allow]` writes the file back after checking
  its hash. `--allow` adds the hash to `<data dir>/allowed.txt`, so a false positive is not detected again (picked up live by the service).
  `avd allow <file>` does the same for a file that was left in place (alert mode).
- **Processes**: `suspend` / `kill` act on the process that wrote the file. Only Linux knows it today (fanotify);
  elsewhere these fall back to quarantine. pid 0/1/4, kernel threads, critical Windows processes and avd itself are refused.
  `avd process resume|kill <pid>` decides about a suspended one.
- **Notifications**: real-time detections pop up on every logged-in user's desktop (Windows: a message box from the service;
  Linux: `notify-send` in each graphical session, run as that user, never through a shell). At most one per 10 s; the
  rest roll up into "…and N more". `notify = false` turns them off.

The data directory is `%ProgramData%\avd` / `/var/lib/avd` (or `data_dir` in the config). The service restricts it to
SYSTEM and Administrators (Windows) or mode 0700 (Linux). Commands run by a non-admin user fall back to their own
`%LOCALAPPDATA%\avd` / `~/.local/share/avd`.

### Self-protection

At startup the service:

- warns (log and notification) if non-admin users can modify the config, the hash list or the rules, or their directories
- logs what changed in the config since the last start, and notifies when protection got weaker: new exclusions, fewer watched
  paths, weaker actions, new trusted publishers, notifications off
- notifies if the previous run stopped without a clean shutdown (a heartbeat file is updated every minute)

None of this stops malware running as admin or root: it can still stop avd or edit its files. It makes that noticed.

### Known limitations

- Windows: needs admin (reads the NTFS USN journal). Only NTFS volumes are watched; FAT/exFAT sticks and network shares are not.
  Detection happens after the write: a dropped file can run before its scan finishes. Nothing is blocked.
  USN records carry no process, so `suspend` / `kill` can't find the writer yet (ETW in M5).
- Linux: needs `CAP_SYS_ADMIN` (fanotify). Executing a watched file waits for a cached verdict or a scan; a scan that takes longer than
  300 ms lets the exec through and the file is scanned afterwards. If avd dies, the kernel allows any pending exec.

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
