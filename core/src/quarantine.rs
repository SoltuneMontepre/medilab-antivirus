//! Quarantine: a detected file becomes `<id>.bin` (XOR-neutered, so it can't run and other AVs don't re-detect it)
//! plus `<id>.json` (where it came from and why) in the quarantine directory. Restore reverses it.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Detection, Platform};

const KEY: &[u8] = b"avd quarantine: neutered, do not run";

/// The `<id>.json` sidecar.
#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub time: String,
    /// `engine:rule` per detection.
    pub detections: Vec<String>,
    /// Unix permission bits.
    pub mode: Option<u32>,
    pub readonly: bool,
}

pub struct Quarantined {
    pub id: String,
    /// The original was held open (Windows) and gets deleted at the next reboot instead of now.
    pub at_reboot: bool,
}

/// Copies `file` into `dir`, then deletes it. Order matters so nothing is lost: neutered copy and sidecar are
/// written and fsynced first; any failure up to the delete leaves the original as it was and removes the copy.
pub fn quarantine(
    dir: &Path,
    file: &Path,
    detections: &[Detection],
    platform: Option<&dyn Platform>,
) -> io::Result<Quarantined> {
    let mut data = fs::read(file)?;
    let meta = fs::metadata(file)?;
    let sha256 = hex(&Sha256::digest(&data));
    let now = chrono::Local::now();
    let id = format!("{}-{}", now.format("%Y%m%d-%H%M%S%3f"), &sha256[..8]);
    #[cfg(unix)]
    let mode = Some(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
    #[cfg(not(unix))]
    let mode = None;
    let entry = Entry {
        id: id.clone(),
        path: file.to_owned(),
        sha256,
        size: data.len() as u64,
        time: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, false),
        detections: detections.iter().map(|d| format!("{}:{}", d.engine, d.name)).collect(),
        mode,
        readonly: meta.permissions().readonly(),
    };
    xor(&mut data);

    fs::create_dir_all(dir)?;
    let (bin, json) = (dir.join(format!("{id}.bin")), dir.join(format!("{id}.json")));
    let cleanup = || {
        let _ = fs::remove_file(&bin);
        let _ = fs::remove_file(&json);
    };
    let written = write_new(&bin, &data)
        .and_then(|()| write_new(&json, &serde_json::to_vec_pretty(&entry)?))
        .and_then(|()| sync_dir(dir));
    if let Err(e) = written {
        cleanup();
        return Err(e);
    }

    // Windows refuses to delete a read-only file. (The lint is about Unix, where this would mean world-writable.)
    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    if entry.readonly {
        let mut writable = meta.permissions();
        writable.set_readonly(false);
        let _ = fs::set_permissions(file, writable);
    }
    match fs::remove_file(file) {
        Ok(()) => Ok(Quarantined { id, at_reboot: false }),
        // ERROR_SHARING_VIOLATION: a running process holds it open.
        Err(e)
            if cfg!(windows)
                && e.raw_os_error() == Some(32)
                && platform.is_some_and(|p| p.delete_on_reboot(file).is_ok()) =>
        {
            Ok(Quarantined { id, at_reboot: true })
        }
        Err(e) => {
            let _ = fs::set_permissions(file, meta.permissions());
            cleanup();
            Err(io::Error::new(e.kind(), format!("cannot delete the original: {e}")))
        }
    }
}

/// All entries, oldest first. A missing directory is an empty quarantine; unreadable sidecars are logged and skipped.
pub fn list(dir: &Path) -> io::Result<Vec<Entry>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for path in entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")) {
        match fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        {
            Ok(entry) => out.push(entry),
            Err(e) => log::warn!("{}: {e}", path.display()),
        }
    }
    out.sort_by(|a: &Entry, b| a.id.cmp(&b.id));
    Ok(out)
}

/// The sidecar of `id`. `id` comes from the command line, so it may only name a file inside `dir`.
pub fn entry(dir: &Path, id: &str) -> io::Result<Entry> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad quarantine id `{id}`")));
    }
    let json = fs::read(dir.join(format!("{id}.json")))
        .map_err(|e| io::Error::new(e.kind(), format!("quarantine entry {id}: {e}")))?;
    Ok(serde_json::from_slice(&json)?)
}

/// Decodes `entry`, checks its hash, writes it to `to` (default: where it came from) and removes it from the
/// quarantine. An existing file is only replaced with `force`. Returns where it was written.
pub fn restore(dir: &Path, entry: &Entry, to: Option<&Path>, force: bool) -> io::Result<PathBuf> {
    let bin = dir.join(format!("{}.bin", entry.id));
    let mut data = fs::read(&bin)?;
    xor(&mut data);
    if hex(&Sha256::digest(&data)) != entry.sha256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "quarantined copy does not match its recorded sha256"));
    }
    let target = to.unwrap_or(&entry.path);
    if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut out = options.open(target).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => {
            io::Error::new(e.kind(), format!("{} exists; --force replaces it", target.display()))
        }
        _ => io::Error::new(e.kind(), format!("{}: {e}", target.display())),
    })?;
    out.write_all(&data)?;
    out.sync_all()?;
    drop(out);
    let mut permissions = fs::metadata(target)?.permissions();
    #[cfg(unix)]
    if let Some(mode) = entry.mode {
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, mode);
    }
    if entry.readonly {
        permissions.set_readonly(true);
    }
    fs::set_permissions(target, permissions)?;
    fs::remove_file(&bin)?;
    fs::remove_file(dir.join(format!("{}.json", entry.id)))?;
    Ok(target.to_owned())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn xor(data: &mut [u8]) {
    data.iter_mut().zip(KEY.iter().cycle()).for_each(|(b, k)| *b ^= k);
}

fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

/// Makes the new directory entries durable (Unix; NTFS journals metadata itself).
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    let _ = dir;
    Ok(())
}
