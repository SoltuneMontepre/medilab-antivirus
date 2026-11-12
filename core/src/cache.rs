//! Verdict cache: file identity -> last verdict, persisted to disk, invalidated by content or signature changes.
//!
//! File format (all integers little-endian):
//! ```text
//! header: magic "AVVC" | version u32 | ruleset [u8; 32] | count u64
//! entry:  volume u64 | file u128 | size u64 | marker u128 | n u32 | n × detection
//! detection: inner str | engine str | name str | file_type u8 | sha256 [u8; 32]
//! str: len u32 | UTF-8 bytes
//! ```
//! Entries are written least-recently-used first, so LRU order survives a restart.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::{FileKey, FileType};

/// Suggested `cap`. A clean file (the common case) costs ~150 bytes in memory: 32-byte key + 64-byte entry
/// in the map plus hash table slack; each detection adds ~150 more. 200k files ≈ 30 MB of the ~100 MB budget,
/// and ~10 MB on disk (52 bytes per clean entry).
pub const DEFAULT_CAP: usize = 200_000;

const MAGIC: &[u8; 4] = b"AVVC";
const VERSION: u32 = 1;
/// Bigger than any cache we write (≈1M clean entries); refuse to read more than this.
const MAX_FILE_BYTES: u64 = 64 << 20;

/// One detection remembered for a file. `inner` is "" for the file itself, or the archive suffix
/// like "!in.zip!a.exe" (stored relative so a renamed file — same identity — still reports its new path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    pub inner: String,
    pub engine: String,
    pub name: String,
    pub file_type: FileType,
    pub sha256: [u8; 32],
}

/// (volume, file): one entry per file identity.
type Id = (u64, u128);

struct Entry {
    size: u64,
    marker: u128,
    /// Last use; higher is newer.
    tick: u64,
    detections: Vec<Cached>,
}

pub struct Cache {
    path: PathBuf,
    ruleset: [u8; 32],
    cap: usize,
    map: HashMap<Id, Entry>,
    tick: u64,
    /// Only puts and drops set this; a hit-only scan does not rewrite the file (its LRU touches are lost on restart).
    dirty: bool,
}

impl Cache {
    /// Never fails. Missing file → empty. Corrupt / other format version / different `ruleset` → empty + log::warn
    /// (a ruleset change therefore turns every old entry into a miss). `cap` = max entries kept (LRU).
    pub fn load(path: &Path, ruleset: [u8; 32], cap: usize) -> Cache {
        let mut cache = Cache { path: path.to_owned(), ruleset, cap, map: HashMap::new(), tick: 0, dirty: false };
        let mut data = Vec::new();
        match File::open(path).and_then(|f| f.take(MAX_FILE_BYTES + 1).read_to_end(&mut data)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return cache,
            Err(e) => {
                log::warn!("{}: {e}; starting with an empty verdict cache", path.display());
                return cache;
            }
            Ok(_) => {}
        }
        if data.len() as u64 > MAX_FILE_BYTES {
            log::warn!("{}: larger than {MAX_FILE_BYTES} bytes; starting with an empty verdict cache", path.display());
            return cache;
        }
        match parse(&data, &ruleset) {
            Ok((map, tick)) => {
                cache.map = map;
                cache.tick = tick;
                cache.evict(); // the file may have been written with a bigger cap
            }
            Err(why) => log::warn!("{}: {why}; starting with an empty verdict cache", path.display()),
        }
        cache
    }

    /// Hit only when an entry exists for (key.volume, key.file) AND its size and marker equal `key`'s. A mismatching entry is a miss (and is dropped).
    pub fn get(&mut self, key: &FileKey) -> Option<&[Cached]> {
        let id = (key.volume, key.file);
        let entry = self.map.get(&id)?;
        if entry.size != key.size || entry.marker != key.marker {
            self.map.remove(&id);
            self.dirty = true;
            return None;
        }
        self.tick += 1;
        let entry = self.map.get_mut(&id)?;
        entry.tick = self.tick;
        Some(&entry.detections)
    }

    /// Insert/replace; evicts least-recently-used entries when over `cap`.
    pub fn put(&mut self, key: FileKey, detections: Vec<Cached>) {
        self.tick += 1;
        let entry = Entry { size: key.size, marker: key.marker, tick: self.tick, detections };
        self.map.insert((key.volume, key.file), entry);
        self.dirty = true;
        self.evict();
    }

    /// Atomic: write `<path>.tmp` then rename over `path`; creates parent dirs. No-op if nothing changed since load/save.
    pub fn save(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let mut entries: Vec<_> = self.map.iter().collect();
        entries.sort_unstable_by_key(|(_, e)| e.tick);
        let mut out = Vec::new();
        out.extend(MAGIC);
        out.extend(VERSION.to_le_bytes());
        out.extend(self.ruleset);
        out.extend((entries.len() as u64).to_le_bytes());
        for ((volume, file), e) in entries {
            out.extend(volume.to_le_bytes());
            out.extend(file.to_le_bytes());
            out.extend(e.size.to_le_bytes());
            out.extend(e.marker.to_le_bytes());
            out.extend((e.detections.len() as u32).to_le_bytes());
            for d in &e.detections {
                for s in [&d.inner, &d.engine, &d.name] {
                    out.extend((s.len() as u32).to_le_bytes());
                    out.extend(s.as_bytes());
                }
                out.push(type_to_u8(d.file_type));
                out.extend(d.sha256);
            }
        }
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }

    /// When over `cap`, drops the oldest entries down to 90% of `cap`.
    // ponytail: O(n) scan + select per eviction, amortized over cap/10 puts; a linked LRU if that ever shows in profiles.
    fn evict(&mut self) {
        if self.map.len() <= self.cap {
            return;
        }
        let n = self.map.len() - self.cap + self.cap / 10;
        let mut ticks: Vec<u64> = self.map.values().map(|e| e.tick).collect();
        let cutoff = *ticks.select_nth_unstable(n - 1).1;
        self.map.retain(|_, e| e.tick > cutoff);
    }
}

/// Returns the entries and the newest tick. Every length is checked against the bytes left,
/// so nothing allocates more than the file holds.
fn parse(data: &[u8], ruleset: &[u8; 32]) -> Result<(HashMap<Id, Entry>, u64), String> {
    let mut r = Reader(data);
    let corrupt = || "corrupt verdict cache".to_owned();
    if r.bytes::<4>().as_ref() != Some(MAGIC) {
        return Err("not a verdict cache".into());
    }
    let version = u32::from_le_bytes(r.bytes().ok_or_else(corrupt)?);
    if version != VERSION {
        return Err(format!("verdict cache format {version}, expected {VERSION}"));
    }
    if r.bytes::<32>().ok_or_else(corrupt)? != *ruleset {
        return Err("signatures changed since the verdict cache was written".into());
    }
    let count = u64::from_le_bytes(r.bytes().ok_or_else(corrupt)?);
    let mut map = HashMap::new();
    // Each entry consumes at least 52 bytes or fails, so a huge `count` just runs out of data.
    for tick in 1..=count {
        let (id, entry) = r.entry(tick).ok_or_else(corrupt)?;
        map.insert(id, entry);
    }
    if !r.0.is_empty() {
        return Err(corrupt());
    }
    Ok((map, count))
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    fn str(&mut self) -> Option<String> {
        let len = u32::from_le_bytes(self.bytes()?) as usize;
        let (s, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        String::from_utf8(s.to_vec()).ok()
    }

    fn entry(&mut self, tick: u64) -> Option<(Id, Entry)> {
        let volume = u64::from_le_bytes(self.bytes()?);
        let file = u128::from_le_bytes(self.bytes()?);
        let size = u64::from_le_bytes(self.bytes()?);
        let marker = u128::from_le_bytes(self.bytes()?);
        let n = u32::from_le_bytes(self.bytes()?);
        let mut detections = Vec::new();
        for _ in 0..n {
            // Struct fields are evaluated in the order written, which is the file order.
            detections.push(Cached {
                inner: self.str()?,
                engine: self.str()?,
                name: self.str()?,
                file_type: type_from_u8(self.bytes::<1>()?[0])?,
                sha256: self.bytes()?,
            });
        }
        Some(((volume, file), Entry { size, marker, tick, detections }))
    }
}

fn type_to_u8(t: FileType) -> u8 {
    match t {
        FileType::Pe => 0,
        FileType::Elf => 1,
        FileType::Script => 2,
        FileType::Pdf => 3,
        FileType::Zip => 4,
        FileType::Ole => 5,
        FileType::Unknown => 6,
    }
}

fn type_from_u8(b: u8) -> Option<FileType> {
    Some(match b {
        0 => FileType::Pe,
        1 => FileType::Elf,
        2 => FileType::Script,
        3 => FileType::Pdf,
        4 => FileType::Zip,
        5 => FileType::Ole,
        6 => FileType::Unknown,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: [u8; 32] = [9; 32];

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("av-cache-{}-{name}", std::process::id()))
    }

    fn key(file: u128, size: u64, marker: u128) -> FileKey {
        FileKey { volume: 7, file, size, marker }
    }

    fn det() -> Cached {
        let s = |s: &str| s.to_owned();
        Cached { inner: s("!in.zip!a.exe"), engine: s("yara"), name: s("X"), file_type: FileType::Pe, sha256: [1; 32] }
    }

    /// A saved cache with one detection entry and one clean entry.
    fn saved(path: &Path) {
        let mut c = Cache::load(path, RULES, 10);
        c.put(key(1, 100, 5), vec![det()]);
        c.put(key(2, 200, 6), vec![]);
        c.save().unwrap();
    }

    #[test]
    fn roundtrip_hits() {
        let path = temp("roundtrip");
        saved(&path);
        // No path in the key: a renamed file keeps its identity and still hits.
        let mut c = Cache::load(&path, RULES, 10);
        let _ = fs::remove_file(&path);
        assert_eq!(c.get(&key(1, 100, 5)), Some(&[det()][..]));
        assert_eq!(c.get(&key(2, 200, 6)), Some(&[][..]));
        assert_eq!(c.get(&key(3, 100, 5)), None);
    }

    #[test]
    fn changed_size_or_marker_misses() {
        let mut c = Cache::load(&temp("unused"), RULES, 10);
        c.put(key(1, 100, 5), vec![]);
        c.put(key(2, 100, 5), vec![]);
        assert_eq!(c.get(&key(1, 101, 5)), None);
        assert_eq!(c.get(&key(2, 100, 6)), None);
        assert_eq!(c.get(&key(1, 100, 5)), None, "stale entry is dropped");
    }

    #[test]
    fn other_ruleset_starts_empty() {
        let path = temp("ruleset");
        saved(&path);
        let mut c = Cache::load(&path, [8; 32], 10);
        let _ = fs::remove_file(&path);
        assert_eq!(c.get(&key(1, 100, 5)), None);
    }

    #[test]
    fn corrupt_file_starts_empty() {
        let path = temp("corrupt");
        saved(&path);
        let good = fs::read(&path).unwrap();
        let patched = |at: usize, bytes: &[u8]| {
            let mut v = good.clone();
            v[at..at + bytes.len()].copy_from_slice(bytes);
            v
        };
        let cases = [
            b"garbage bytes".to_vec(),
            good[..good.len() - 1].to_vec(),
            patched(4, &2u32.to_le_bytes()),       // format version
            patched(40, &u64::MAX.to_le_bytes()),  // entry count
            patched(100, &u32::MAX.to_le_bytes()), // first string length
        ];
        for bad in cases {
            fs::write(&path, bad).unwrap();
            assert!(Cache::load(&path, RULES, 10).map.is_empty());
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lru_evicts_oldest() {
        let mut c = Cache::load(&temp("unused"), RULES, 10);
        for i in 1..=10 {
            c.put(key(i, 0, 0), vec![]);
        }
        c.get(&key(1, 0, 0)).unwrap(); // 1 is now the newest
        c.put(key(11, 0, 0), vec![]); // over cap: drop to 9, i.e. the two oldest (2 and 3)
        assert_eq!(c.map.len(), 9);
        assert!(c.get(&key(2, 0, 0)).is_none() && c.get(&key(3, 0, 0)).is_none());
        assert!(c.get(&key(1, 0, 0)).is_some() && c.get(&key(11, 0, 0)).is_some());
    }
}
