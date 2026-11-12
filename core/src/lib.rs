//! Platform-independent logic: scan pipeline, detection engines, cache, rules, config, updates.
//! All detection decisions live here so Windows and Linux behave identically.

pub mod archive;
pub mod cache;
pub mod watch;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

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
    pub trust: TrustConfig,
    pub archives: archive::Limits,
    /// Where the verdict cache lives. None = per-OS default chosen by the daemon.
    pub cache_dir: Option<PathBuf>,
    pub watch: watch::WatchConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: 64 * 1024 * 1024,
            hash_list: "signatures/hashes.txt".into(),
            rules_dir: "signatures/rules".into(),
            trust: TrustConfig::default(),
            archives: archive::Limits::default(),
            cache_dir: None,
            watch: watch::WatchConfig::default(),
        }
    }
}

/// `[trust]`: which files may skip the engines.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TrustConfig {
    /// Off = scan everything (for debugging).
    pub enabled: bool,
    /// Windows: Authenticode signer subject names that count as trusted. Any other valid signature does not.
    pub publishers: Vec<String>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self { enabled: true, publishers: vec!["Microsoft Windows".into(), "Microsoft Corporation".into()] }
    }
}

/// Platform file identity plus a change marker, taken from the same open handle that is read.
/// Windows: volume serial + 128-bit file ID; Linux: st_dev + st_ino.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub volume: u64,
    pub file: u128,
    pub size: u64,
    /// Windows: last write + change time; Linux: mtime ns and ctime ns packed (mtime << 64 | ctime).
    pub marker: u128,
}

/// What the OS can tell core about a file. Implemented once per platform crate; shared by every scanning thread.
pub trait Platform: Send + Sync {
    fn file_key(&self, file: &File) -> io::Result<FileKey>;
    /// True only when the file is known-good (allowlisted signer, unmodified package file).
    /// `sha256` is the file's content digest, already computed by core.
    fn is_trusted(&self, path: &Path, file: &File, sha256: &[u8; 32]) -> bool;
    /// Optional fast path: keys for the regular files directly inside `dir`, by file name, from one directory
    /// read instead of one open per file (an open costs ~50 µs on Windows). Only used to look up the cache;
    /// on a miss the file is opened and re-keyed from the handle that is read. Must equal `file_key` for the
    /// same file, or every lookup just misses.
    fn dir_keys(&self, _dir: &Path) -> Option<HashMap<OsString, FileKey>> {
        None
    }
}

impl Config {
    /// Missing file → defaults. Relative signature paths resolve against the file's directory. Unreadable or malformed file → error naming the file (toml adds line and column).
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut config: Self = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        // join() keeps absolute paths as-is.
        if let Some(dir) = path.parent() {
            config.hash_list = dir.join(&config.hash_list);
            config.rules_dir = dir.join(&config.rules_dir);
            config.cache_dir = config.cache_dir.map(|c| dir.join(c));
        }
        Ok(config)
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
    /// Unchanged since the last scan; verdict reused from the cache.
    pub cache_hits: u64,
    /// Skipped the engines because `Platform::is_trusted` said so.
    pub trusted: u64,
    /// Files where an `[archives]` limit (depth, entries, bytes, ratio) stopped extraction.
    pub limit_hits: u64,
    /// Encrypted archive entries (7z: blocks) that could not be scanned.
    pub encrypted: u64,
    /// Containers we recognise but cannot open (RAR).
    pub unsupported: u64,
}

const YARA_TIMEOUT: Duration = Duration::from_secs(10);

/// Engine names a cached verdict may carry; anything else is treated as a miss.
const ENGINES: [&str; 2] = ["hash", "yara"];

/// Locks, ignoring poisoning (a worker panic must not wedge the cache).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Loaded signatures and the settings that go with them. Immutable once loaded.
struct Signatures {
    max_file_size: u64,
    archives: archive::Limits,
    trust_enabled: bool,
    /// SHA-256 → detection name.
    hashes: HashMap<[u8; 32], String>,
    rules: &'static yara_x::Rules,
    ruleset: [u8; 32],
}

/// Everything an engine needs except its YARA scanner (which is tied to one thread). Cheap to clone; clone it into
/// another thread and call `Engine::new` there.
#[derive(Clone)]
pub struct Shared {
    sigs: Arc<Signatures>,
    /// Set by the daemon. Without it nothing is cached or trusted: every file is read and scanned.
    pub platform: Option<Arc<dyn Platform>>,
    /// Needs `platform` (for file identity). Open it with `Cache::load(.., shared.ruleset(), ..)`.
    pub cache: Option<Arc<Mutex<cache::Cache>>>,
    /// Real-time mode: `Engine::scan` skips files this filter does not want.
    pub filter: Option<Arc<watch::Filter>>,
}

impl Shared {
    pub fn load(config: &Config) -> Result<Shared, String> {
        // Everything that can change a verdict for unchanged bytes: signatures, archive limits, code version.
        let mut ruleset = Sha256::new();
        ruleset.update(env!("CARGO_PKG_VERSION"));
        ruleset.update(format!("{:?}", config.archives));
        let hashes = load_hashes(&config.hash_list, &mut ruleset)?;
        // ponytail: Rules are leaked so every Scanner can be 'static; each reload leaks the old set.
        let rules: &'static yara_x::Rules = Box::leak(Box::new(compile_rules(&config.rules_dir, &mut ruleset)?));
        let sigs = Signatures {
            max_file_size: config.max_file_size,
            archives: config.archives,
            trust_enabled: config.trust.enabled,
            hashes,
            rules,
            ruleset: ruleset.finalize().into(),
        };
        Ok(Shared { sigs: Arc::new(sigs), platform: None, cache: None, filter: None })
    }

    /// Fingerprint of the loaded signatures and settings; the cache is dropped when it changes.
    pub fn ruleset(&self) -> [u8; 32] {
        self.sigs.ruleset
    }

    /// Cache-only verdict for an open file: Some(true) cached clean, Some(false) cached detection, None = miss / no
    /// cache. Never reads the file. (Used by Linux exec-permission checks on a latency-critical thread.)
    pub fn cached_clean(&self, file: &File) -> Option<bool> {
        let key = self.platform.as_ref()?.file_key(file).ok()?;
        self.cached(Path::new(""), &key).map(|d| d.is_empty())
    }

    /// Identity key for caching; None when there is no cache or the platform can't tell.
    fn file_key(&self, path: &Path, file: &File) -> Option<FileKey> {
        match (&self.platform, &self.cache) {
            (Some(platform), Some(_)) => platform
                .file_key(file)
                .map_err(|e| log::warn!("{}: file identity: {e}, not cached", path.display()))
                .ok(),
            _ => None,
        }
    }

    /// The cached verdict for `key` as detections at `path`; None on a miss.
    fn cached(&self, path: &Path, key: &FileKey) -> Option<Vec<Detection>> {
        let mut cache = lock(self.cache.as_ref()?);
        cache
            .get(key)?
            .iter()
            .map(|c| {
                Some(Detection {
                    path: format!("{}{}", path.display(), c.inner).into(),
                    sha256: c.sha256,
                    engine: ENGINES.into_iter().find(|e| *e == c.engine)?,
                    name: c.name.clone(),
                    file_type: c.file_type,
                })
            })
            .collect()
    }

    /// Reports the cached verdict for `key`, if there is one. The cache lock is released before `on_detection` runs.
    fn replay(&self, path: &Path, key: &FileKey, stats: &mut Stats, on_detection: &mut dyn FnMut(Detection)) -> bool {
        let Some(detections) = self.cached(path, key) else { return false };
        stats.cache_hits += 1;
        stats.detections += detections.len() as u64;
        detections.into_iter().for_each(on_detection);
        true
    }

    fn put(&self, key: Option<FileKey>, detections: Vec<cache::Cached>) {
        if let (Some(key), Some(cache)) = (key, &self.cache) {
            lock(cache).put(key, detections);
        }
    }
}

/// One scanning thread's engine: the shared signatures plus its own YARA scanner.
pub struct Engine {
    pub shared: Shared,
    yara: yara_x::Scanner<'static>,
}

impl Engine {
    pub fn new(shared: Shared) -> Engine {
        let mut yara = yara_x::Scanner::new(shared.sigs.rules);
        yara.set_timeout(YARA_TIMEOUT);
        Engine { shared, yara }
    }

    pub fn load(config: &Config) -> Result<Engine, String> {
        Ok(Engine::new(Shared::load(config)?))
    }

    /// Fingerprint of the loaded signatures and settings; the cache is dropped when it changes.
    pub fn ruleset(&self) -> [u8; 32] {
        self.shared.ruleset()
    }

    /// Scans a file or a directory tree. Per-file problems are logged and counted, never fatal.
    pub fn scan(&mut self, root: &Path, mut on_detection: impl FnMut(Detection)) -> Stats {
        let mut stats = Stats::default();
        // follow_links(false) is walkdir's default, spelled out because it is what prevents
        // symlink loops and escaping the scan root.
        // Files before subdirectories, so each directory's files come out together and its listing is read once.
        // ponytail: excluded directories are still walked (only their files are skipped); prune with filter_entry
        // if big excluded trees show up in rescans.
        let walk =
            WalkDir::new(root).follow_links(false).sort_by(|a, b| a.file_type().is_dir().cmp(&b.file_type().is_dir()));
        let mut listing: Option<(PathBuf, HashMap<OsString, FileKey>)> = None;
        for entry in walk {
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
            if self.shared.filter.as_ref().is_some_and(|f| !f.wants(path)) {
                continue;
            }
            // ponytail: an NTFS directory listing lags while another process holds the file open for writing
            // (and for changes made through another hard link), so such a file can hit its old verdict until the
            // handle closes. M3's USN journal sees writes as they happen and is the fix.
            let listed = match (&self.shared.platform, &self.shared.cache, path.parent(), entry.depth() > 0) {
                (Some(platform), Some(_), Some(dir), true) => {
                    if listing.as_ref().is_none_or(|(d, _)| d != dir) {
                        listing = Some((dir.to_path_buf(), platform.dir_keys(dir).unwrap_or_default()));
                    }
                    listing.as_ref().and_then(|(_, keys)| keys.get(entry.file_name()).copied())
                }
                _ => None,
            };
            if let Err(e) = self.scan_file(path, listed, &mut stats, &mut on_detection) {
                log::warn!("{}: {e}", path.display());
                stats.errors += 1;
            }
        }
        stats
    }

    /// Scans an already-open file from offset 0: size limit, cache, trust, engines, cache put — same as a walked
    /// file. Used for fanotify fds (no path race).
    pub fn scan_handle(&mut self, path: &Path, file: File, mut on_detection: impl FnMut(Detection)) -> Stats {
        let mut stats = Stats::default();
        if let Err(e) = self.scan_handle_inner(path, file, &mut stats, &mut on_detection) {
            log::warn!("{}: {e}", path.display());
            stats.errors += 1;
        }
        stats
    }

    fn scan_handle_inner(
        &mut self,
        path: &Path,
        mut file: File,
        stats: &mut Stats,
        on_detection: &mut dyn FnMut(Detection),
    ) -> io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        if file.metadata()?.len() > self.shared.sigs.max_file_size {
            stats.skipped += 1;
            return Ok(());
        }
        let key = self.shared.file_key(path, &file);
        if key.is_some_and(|key| self.shared.replay(path, &key, stats, on_detection)) {
            return Ok(());
        }
        self.scan_open(path, file, key, stats, on_detection)
    }

    /// One file: cache → size check → read → trust → engines → cache.
    /// `listed` is the key from the directory listing, if the platform has one; a hit then never opens the file.
    fn scan_file(
        &mut self,
        path: &Path,
        listed: Option<FileKey>,
        stats: &mut Stats,
        on_detection: &mut dyn FnMut(Detection),
    ) -> io::Result<()> {
        if listed.is_some_and(|key| self.shared.replay(path, &key, stats, on_detection)) {
            return Ok(());
        }
        let meta = open_metadata_only(path)?;
        if meta.metadata()?.len() > self.shared.sigs.max_file_size {
            stats.skipped += 1;
            return Ok(());
        }
        if listed.is_none()
            && self.shared.file_key(path, &meta).is_some_and(|key| self.shared.replay(path, &key, stats, on_detection))
        {
            return Ok(());
        }
        drop(meta);

        // The verdict is stored under the key of the handle that is read, taken before reading: a file swapped
        // or changed meanwhile has a different id or marker, so it misses next time instead of inheriting this verdict.
        let file = File::open(path)?;
        let key = self.shared.file_key(path, &file);
        self.scan_open(path, file, key, stats, on_detection)
    }

    /// The tail shared by walked files and open handles: read → trust → engines → cache. `key` was taken from `file`.
    fn scan_open(
        &mut self,
        path: &Path,
        mut file: File,
        key: Option<FileKey>,
        stats: &mut Stats,
        on_detection: &mut dyn FnMut(Detection),
    ) -> io::Result<()> {
        let mut data = Vec::new();
        // take(): a file that grows after the size check still stops at the limit.
        (&mut file).take(self.shared.sigs.max_file_size).read_to_end(&mut data)?;
        stats.scanned += 1;

        // ponytail: trust is only asked for executables; a signature check costs ~20 ms on Windows (more for
        // unsigned files), far more than scanning a small data file. Widen if FPs on signed non-PE files show up.
        let executable = matches!(file_type(&data), FileType::Pe | FileType::Elf | FileType::Script);
        if self.shared.sigs.trust_enabled && executable {
            let sha256: [u8; 32] = Sha256::digest(&data).into();
            if self.shared.platform.as_ref().is_some_and(|p| p.is_trusted(path, &file, &sha256)) {
                stats.trusted += 1;
                self.shared.put(key, Vec::new());
                return Ok(());
            }
        }

        let errors = stats.errors;
        let mut found = Vec::new();
        self.scan_data(path, &data, stats, &mut |d| {
            found.push(d.clone());
            on_detection(d);
        });
        // An incomplete scan (YARA error or timeout) is not cached, so the next scan retries it.
        if stats.errors == errors {
            let outer = path.display().to_string();
            let cached = found.into_iter().map(|d| cache::Cached {
                inner: d.path.display().to_string().strip_prefix(&outer).unwrap_or_default().to_owned(),
                engine: d.engine.to_owned(),
                name: d.name,
                file_type: d.file_type,
                sha256: d.sha256,
            });
            self.shared.put(key, cached.collect());
        }
        Ok(())
    }

    /// Scans one file's contents, including everything nested inside it.
    fn scan_data(&mut self, path: &Path, data: &[u8], stats: &mut Stats, on_detection: &mut dyn FnMut(Detection)) {
        let mut budget = archive::Budget::new(&self.shared.sigs.archives);
        self.scan_buffer(&path.display().to_string(), data, 0, &mut budget, stats, on_detection);
        stats.encrypted += budget.encrypted;
        stats.limit_hits += budget.limit_hit as u64;
    }

    /// Runs every engine on one buffer, then recurses into it if it is a container.
    /// Inner paths are `outer!entry`; one `budget` covers the whole outer file.
    fn scan_buffer(
        &mut self,
        path: &str,
        data: &[u8],
        depth: u32,
        budget: &mut archive::Budget,
        stats: &mut Stats,
        on_detection: &mut dyn FnMut(Detection),
    ) {
        let sha256: [u8; 32] = Sha256::digest(data).into();
        let file_type = file_type(data);
        let mut found: Vec<(&'static str, String)> = Vec::new();
        if let Some(name) = self.shared.sigs.hashes.get(&sha256) {
            found.push(("hash", name.clone()));
        }
        match self.yara.scan(data) {
            Ok(results) => found.extend(results.matching_rules().map(|r| ("yara", r.identifier().to_owned()))),
            Err(e) => {
                log::warn!("{path}: yara: {e}");
                stats.errors += 1;
            }
        }
        for (engine, name) in found {
            stats.detections += 1;
            on_detection(Detection { path: path.into(), sha256, engine, name, file_type });
        }

        // RAR: no maintained pure-Rust decoder, so it is counted, not opened.
        if data.starts_with(b"Rar!\x1a\x07") {
            stats.unsupported += 1;
            return;
        }
        if !archive::is_container(data) || budget.limit_hit {
            return;
        }
        if depth >= self.shared.sigs.archives.max_depth {
            log::warn!("{path}: nested deeper than {} levels, not opened", self.shared.sigs.archives.max_depth);
            budget.limit_hit = true;
            return;
        }
        let max = self.shared.sigs.max_file_size;
        // A bad or bomb-like archive is logged, not counted as an error: the outer file itself was scanned.
        let result = archive::for_each_entry(data, max, budget, &mut |name, bytes, budget| {
            self.scan_buffer(&format!("{path}!{name}"), bytes, depth + 1, budget, stats, on_detection)
        });
        if let Err(e) = result {
            log::warn!("{path}: {e}");
        }
    }
}

/// A handle good for metadata and file identity but not data. On Windows this asks for attribute access only,
/// which AV filters (Defender included) don't scan on open; that is most of the cost of a cache hit.
fn open_metadata_only(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x80;
        std::fs::OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).open(path)
    }
    #[cfg(not(windows))]
    File::open(path)
}

/// `<sha256 hex> <name>` per line; `#` comments and blank lines are skipped, malformed lines are logged and skipped.
/// The raw file also goes into `version`.
fn load_hashes(path: &Path, version: &mut Sha256) -> Result<HashMap<[u8; 32], String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    version.update(&text);
    let mut hashes = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = line
            .split_once(char::is_whitespace)
            .and_then(|(hex, name)| Some((parse_sha256(hex)?, name.trim())))
            .filter(|(_, name)| !name.is_empty());
        let Some((sha256, name)) = parsed else {
            log::warn!("{}:{}: expected `<sha256 hex> <name>`, line skipped", path.display(), i + 1);
            continue;
        };
        hashes.insert(sha256, name.to_owned());
    }
    Ok(hashes)
}

fn parse_sha256(hex: &str) -> Option<[u8; 32]> {
    // The digit check also rejects the `+` that from_str_radix would accept.
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Compiles every `*.yar` / `*.yara` file directly inside `dir`; their sources also go into `version`.
fn compile_rules(dir: &Path, version: &mut Sha256) -> Result<yara_x::Rules, String> {
    let err = |p: &Path, e: &dyn std::fmt::Display| format!("{}: {e}", p.display());
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| err(dir, &e))? {
        let path = entry.map_err(|e| err(dir, &e))?.path();
        if path.extension().is_some_and(|ext| ext == "yar" || ext == "yara") {
            paths.push(path);
        }
    }
    paths.sort(); // deterministic rule order
    let mut compiler = yara_x::Compiler::new();
    for path in &paths {
        let src = std::fs::read(path).map_err(|e| err(path, &e))?;
        version.update(&src);
        compiler.add_source(src.as_slice()).map_err(|e| err(path, &e))?;
    }
    Ok(compiler.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real signatures/ shipped with the repo.
    fn test_config() -> Config {
        Config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../antivirus.toml")).unwrap()
    }

    /// EICAR, XOR 0x55 so the literal never appears in source or in the test binary
    /// (Defender would quarantine either). Decoded only in memory, never written to disk.
    fn eicar() -> Vec<u8> {
        const X: [u8; 68] = [
            0x0d, 0x60, 0x1a, 0x74, 0x05, 0x70, 0x15, 0x14, 0x05, 0x0e, 0x61, 0x09, 0x05, 0x0f, 0x0d, 0x60, 0x61, 0x7d,
            0x05, 0x0b, 0x7c, 0x62, 0x16, 0x16, 0x7c, 0x62, 0x28, 0x71, 0x10, 0x1c, 0x16, 0x14, 0x07, 0x78, 0x06, 0x01,
            0x14, 0x1b, 0x11, 0x14, 0x07, 0x11, 0x78, 0x14, 0x1b, 0x01, 0x1c, 0x03, 0x1c, 0x07, 0x00, 0x06, 0x78, 0x01,
            0x10, 0x06, 0x01, 0x78, 0x13, 0x1c, 0x19, 0x10, 0x74, 0x71, 0x1d, 0x7e, 0x1d, 0x7f,
        ];
        // black_box: stop the optimizer from folding the decoded string into the binary.
        std::hint::black_box(X).iter().map(|b| b ^ 0x55).collect()
    }

    #[test]
    fn eicar_detected_by_hash_and_yara() {
        let mut engine = Engine::load(&test_config()).unwrap();
        let mut stats = Stats::default();
        let mut found = Vec::new();
        engine.scan_data(Path::new("mem"), &eicar(), &mut stats, &mut |d| found.push((d.engine, d.name)));
        found.sort();
        assert_eq!(found, [("hash", "EICAR-Test-File".to_owned()), ("yara", "EICAR_Test_File".to_owned())]);
        assert_eq!(stats, Stats { detections: 2, ..Stats::default() });
    }

    /// Scans an in-memory file; returns sorted `(path, engine)` detections and the stats.
    fn scan_mem(engine: &mut Engine, name: &str, data: &[u8]) -> (Vec<(String, &'static str)>, Stats) {
        let mut stats = Stats::default();
        let mut found = Vec::new();
        engine.scan_data(Path::new(name), data, &mut stats, &mut |d| {
            found.push((d.path.display().to_string(), d.engine))
        });
        found.sort();
        (found, stats)
    }

    fn zip_of(entries: &[(&str, &[u8])], options: zip::write::SimpleFileOptions) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in entries {
            w.start_file(*name, options).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn eicar_detected_in_containers() {
        use archive::tests::{make_7z, make_gz, make_iso, make_tar, make_zip};
        let e = eicar();
        let cases = [
            (make_zip("e.com", &e), "a!e.com"),
            (make_zip("b.zip", &make_zip("c.zip", &make_zip("e.com", &e))), "a!b.zip!c.zip!e.com"),
            (make_gz(None, &make_tar("x/e.com", &e)), "a!data!x/e.com"),
            (make_zip("in.tar.gz", &make_gz(None, &make_tar("x/e.com", &e))), "a!in.tar.gz!data!x/e.com"),
            (make_7z("s/e.com", &e), "a!s/e.com"),
            (make_iso(b"E.COM;1", &e), "a!SUB/E.COM"),
        ];
        let mut engine = Engine::load(&test_config()).unwrap();
        for (data, path) in cases {
            let (found, stats) = scan_mem(&mut engine, "a", &data);
            assert_eq!(found, [(path.to_owned(), "hash"), (path.to_owned(), "yara")]);
            assert_eq!((stats.errors, stats.limit_hits), (0, 0), "{path}");
        }
    }

    #[test]
    fn nested_zip_bomb_stops_at_first_limit() {
        // 42.zip-style, scaled down: 10 x 10 x 10 copies of a 2 MiB run of zeros, 2 GiB nominal.
        let opts = zip::write::SimpleFileOptions::default();
        let mut layer = zip_of(&[("zeros", &vec![0u8; 2 << 20])], opts);
        for _ in 0..3 {
            let names: Vec<String> = (0..10).map(|i| format!("{i}.zip")).collect();
            let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), layer.as_slice())).collect();
            layer = zip_of(&entries, opts);
        }
        let mut engine = Engine::load(&test_config()).unwrap();
        let start = std::time::Instant::now();
        let (_, stats) = scan_mem(&mut engine, "42.zip", &layer);
        assert!(start.elapsed() < Duration::from_secs(10), "{:?}", start.elapsed());
        assert_eq!((stats.limit_hits, stats.errors), (1, 0));

        // Nesting past max_depth is a limit hit too.
        let mut deep = b"plain".to_vec();
        for _ in 0..7 {
            deep = archive::tests::make_zip("n.zip", &deep);
        }
        assert_eq!(scan_mem(&mut engine, "deep.zip", &deep).1.limit_hits, 1);
    }

    /// Fifield-style overlapping ZIP: entry i's stored data covers every later local header plus one
    /// shared kernel, so n entries yield ~n * kernel bytes (quadratic) at ratio ~1:1.
    fn overlap_bomb(n: usize, kernel: &[u8]) -> Vec<u8> {
        fn le(v: &mut Vec<u8>, x: u64, bytes: usize) {
            v.extend_from_slice(&x.to_le_bytes()[..bytes]);
        }
        // Built back to front: each entry's CRC covers the headers after it.
        let mut tail = kernel.to_vec();
        let mut entries = Vec::new(); // (name, crc, size), last entry first
        for i in (0..n).rev() {
            let name = format!("{i:05}");
            let mut crc = flate2::Crc::new();
            crc.update(&tail);
            let (crc, size) = (crc.sum() as u64, tail.len() as u64);
            let mut h = vec![0x50, 0x4b, 3, 4];
            for (x, b) in [(20, 2), (0, 2), (0, 2), (0, 2), (0x21, 2), (crc, 4), (size, 4), (size, 4), (5, 2), (0, 2)] {
                le(&mut h, x, b);
            }
            h.extend_from_slice(name.as_bytes());
            tail.splice(0..0, h);
            entries.push((name, crc, size));
        }
        let header_len = 30 + 5;
        let mut cd = Vec::new();
        for (i, (name, crc, size)) in entries.iter().rev().enumerate() {
            cd.extend_from_slice(&[0x50, 0x4b, 1, 2]);
            let offset = (i * header_len) as u64;
            for (x, b) in [(20, 2), (20, 2), (0, 2), (0, 2), (0, 2), (0x21, 2), (*crc, 4), (*size, 4), (*size, 4)] {
                le(&mut cd, x, b);
            }
            for (x, b) in [(5, 2), (0, 2), (0, 2), (0, 2), (0, 2), (0, 4), (offset, 4)] {
                le(&mut cd, x, b);
            }
            cd.extend_from_slice(name.as_bytes());
        }
        let mut out = tail;
        let cd_offset = out.len() as u64;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&[0x50, 0x4b, 5, 6]);
        for (x, b) in [(0, 2), (0, 2), (n as u64, 2), (n as u64, 2), (cd.len() as u64, 4), (cd_offset, 4), (0, 2)] {
            le(&mut out, x, b);
        }
        out
    }

    #[test]
    fn overlapping_zip_bomb_hits_byte_budget() {
        // 1000 entries over a 16 KiB kernel: ~33 MiB out of ~85 KiB; a 4 MiB budget keeps the test fast.
        // Stored entries, so only the total-bytes cap (not the ratio) can stop it.
        let bomb = overlap_bomb(1000, &[0u8; 16 << 10]);
        let config =
            Config { archives: archive::Limits { max_total_bytes: 4 << 20, ..Default::default() }, ..test_config() };
        let mut engine = Engine::load(&config).unwrap();
        let start = std::time::Instant::now();
        let (_, stats) = scan_mem(&mut engine, "overlap.zip", &bomb);
        assert!(start.elapsed() < Duration::from_secs(10), "{:?}", start.elapsed());
        assert_eq!((stats.limit_hits, stats.errors), (1, 0));
    }

    #[test]
    fn encrypted_and_rar_counted_not_errors() {
        let aes = zip::write::SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "pw");
        let z = zip_of(&[("a.exe", b"MZ secret"), ("b.exe", b"MZ secret")], aes);
        let mut engine = Engine::load(&test_config()).unwrap();
        let (_, stats) = scan_mem(&mut engine, "locked.zip", &z);
        assert_eq!((stats.encrypted, stats.errors), (2, 0));

        let (_, stats) = scan_mem(&mut engine, "a.rar", b"Rar!\x1a\x07\x01\x00rest");
        assert_eq!((stats.unsupported, stats.errors), (1, 0));
    }

    #[test]
    fn bad_hash_line_is_skipped() {
        let path = std::env::temp_dir().join(format!("av-core-hashes-{}.txt", std::process::id()));
        let good = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR-Test-File";
        std::fs::write(&path, format!("# c\nnot-a-hash x\n{good}\nabcd\n")).unwrap();
        let hashes = load_hashes(&path, &mut Sha256::new());
        let _ = std::fs::remove_file(&path);
        assert_eq!(hashes.unwrap().len(), 1);
    }

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

        let mut engine = Engine::load(&Config { max_file_size: 10, ..test_config() }).unwrap();
        let stats = engine.scan(&dir, |_| {});
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(stats.skipped, 1);
        // locked.bin is an error, unless running as root, which reads it anyway.
        let expected = if cfg!(unix) { 2 } else { 1 };
        assert_eq!(stats.scanned + stats.errors, expected);
    }
}
