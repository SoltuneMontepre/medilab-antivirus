//! Platform-independent logic: scan pipeline, detection engines, cache, rules, config, updates.
//! All detection decisions live here so Windows and Linux behave identically.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// Contents of `antivirus.toml`. Every key has a default, so a missing file or key is fine.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub max_file_size: u64,
    pub hash_list: PathBuf,
    pub rules_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: 64 * 1024 * 1024,
            hash_list: "signatures/hashes.txt".into(),
            rules_dir: "signatures/rules".into(),
        }
    }
}

impl Config {
    /// Missing file → defaults. Unreadable or malformed file → error naming the file (toml adds line and column).
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Pe,
    Elf,
    Script,
    Pdf,
    /// Also docx/xlsx/jar/apk.
    Zip,
    /// Legacy Office.
    Ole,
    Unknown,
}

pub fn file_type(data: &[u8]) -> FileType {
    match data {
        [b'M', b'Z', ..] => FileType::Pe,
        [0x7f, b'E', b'L', b'F', ..] => FileType::Elf,
        [b'#', b'!', ..] => FileType::Script,
        [b'%', b'P', b'D', b'F', ..] => FileType::Pdf,
        [b'P', b'K', 0x03, 0x04, ..] => FileType::Zip,
        [0xD0, 0xCF, 0x11, 0xE0, ..] => FileType::Ole,
        _ => FileType::Unknown,
    }
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub engine: &'static str,
    pub name: String,
    pub file_type: FileType,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub scanned: u64,
    /// Over `max_file_size`.
    pub skipped: u64,
    /// Walk or read failures; each is logged with its path.
    pub errors: u64,
    pub detections: u64,
}

pub struct Engine {
    max_file_size: u64,
}

impl Engine {
    pub fn load(config: &Config) -> Result<Self, String> {
        Ok(Self { max_file_size: config.max_file_size })
    }

    /// Scans a file or a directory tree. Per-file problems are logged and counted, never fatal.
    pub fn scan(&self, root: &Path, mut on_detection: impl FnMut(Detection)) -> Stats {
        let mut stats = Stats::default();
        // ponytail: single-threaded; the M3 work queue adds workers.
        // follow_links(false) is walkdir's default, spelled out because it is what prevents
        // symlink loops and escaping the scan root.
        for entry in WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    log::warn!("{e}"); // walkdir's message includes the path
                    stats.errors += 1;
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let data = match self.read(path) {
                Ok(Some(data)) => data,
                Ok(None) => {
                    stats.skipped += 1;
                    continue;
                }
                Err(e) => {
                    log::warn!("{}: {e}", path.display());
                    stats.errors += 1;
                    continue;
                }
            };
            stats.scanned += 1;
            let sha256: [u8; 32] = Sha256::digest(&data).into();
            let file_type = file_type(&data);
            for (engine, name) in self.check(&data, &sha256) {
                stats.detections += 1;
                on_detection(Detection { path: path.to_path_buf(), sha256, engine, name, file_type });
            }
        }
        stats
    }

    /// `Ok(None)` means the file is over the size limit.
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len > self.max_file_size {
            return Ok(None);
        }
        let mut data = Vec::with_capacity(len as usize);
        // take(): a file that grows between the size check and the read still stops at the limit.
        file.take(self.max_file_size).read_to_end(&mut data)?;
        Ok(Some(data))
    }

    /// Returns `(engine, rule name)` matches. The hash and YARA engines plug in here (#6).
    fn check(&self, _data: &[u8], _sha256: &[u8; 32]) -> Vec<(&'static str, String)> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_magics() {
        assert_eq!(file_type(b"MZ\x90\x00"), FileType::Pe);
        assert_eq!(file_type(b"\x7fELF\x02\x01"), FileType::Elf);
        assert_eq!(file_type(b"#!/bin/sh\n"), FileType::Script);
        assert_eq!(file_type(b"%PDF-1.7"), FileType::Pdf);
        assert_eq!(file_type(b"PK\x03\x04\x14\x00"), FileType::Zip);
        assert_eq!(file_type(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"), FileType::Ole);
        assert_eq!(file_type(b"hello"), FileType::Unknown);
        assert_eq!(file_type(b"M"), FileType::Unknown);
        assert_eq!(file_type(b""), FileType::Unknown);
    }

    #[test]
    fn scan_survives_bad_entries() {
        let dir = std::env::temp_dir().join(format!("av-core-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("ok.bin"), b"MZ").unwrap();
        std::fs::write(dir.join("big.bin"), [0u8; 11]).unwrap();
        // Symlinks need admin on Windows and permission bits are Unix-only; CI covers these on Linux.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            symlink(&dir, dir.join("sub/loop")).unwrap();
            let locked = dir.join("locked.bin");
            std::fs::write(&locked, b"x").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        }

        let engine = Engine::load(&Config { max_file_size: 10, ..Config::default() }).unwrap();
        let stats = engine.scan(&dir, |_| {});
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(stats.skipped, 1);
        // locked.bin is an error, unless running as root, which reads it anyway.
        let expected = if cfg!(unix) { 2 } else { 1 };
        assert_eq!(stats.scanned + stats.errors, expected);
    }
}
