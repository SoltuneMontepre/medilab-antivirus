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
- Only handle real malware inside a VM with snapshots. Never handle it on your dev machine.
