//! Real-time pipeline: sensors push changed paths, a debouncer waits for their writes to settle, and a small worker
//! pool scans them. Sensors never block: a full queue spills into a deduplicated "rescan later" set.

use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use globset::{Candidate, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use crate::{lock, Detection, Engine};

/// `[watch]`: what real-time protection watches.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WatchConfig {
    pub paths: Vec<PathBuf>,
    /// Globs. No defaults: malware drops into build dirs too.
    pub exclude: Vec<String>,
    /// A path is scanned once no event arrived for it for this long.
    pub debounce_ms: u64,
    pub workers: usize,
    /// Bounded queue length; also the debouncer's cap on tracked paths.
    pub queue: usize,
}

impl Default for WatchConfig {
    fn default() -> Self {
        let paths = if cfg!(windows) {
            vec!["C:\\Users".into()]
        } else if cfg!(target_os = "linux") {
            vec!["/home".into(), "/tmp".into()]
        } else {
            vec![]
        };
        Self { paths, exclude: vec![], debounce_ms: 500, workers: 2, queue: 10_000 }
    }
}

/// Which paths real-time protection cares about.
pub struct Filter {
    roots: Vec<PathBuf>,
    include: GlobSet,
    exclude: GlobSet,
}

impl Filter {
    /// `own_dirs`: the daemon's own dirs (cache, logs), always excluded. Errors on a bad glob, naming it.
    pub fn new(config: &WatchConfig, own_dirs: &[PathBuf]) -> Result<Filter, String> {
        // globset matches Windows paths with `/` separators and does not treat `\` as an escape there.
        let slashes = |s: &str| if cfg!(windows) { s.replace('\\', "/") } else { s.to_owned() };
        let glob = |pattern: String| {
            GlobBuilder::new(&pattern)
                .case_insensitive(cfg!(windows))
                .build()
                .map_err(|e| format!("[watch] glob `{pattern}`: {e}"))
        };
        // Everything below a directory; "/" and "C:\" become "/**" and "C:/**".
        let below = |dir: &Path| {
            let dir = slashes(&dir.to_string_lossy());
            glob(format!("{}/**", globset::escape(dir.trim_end_matches('/'))))
        };
        let build = |set: GlobSetBuilder| set.build().map_err(|e| format!("[watch] globs: {e}"));

        // Sensors report resolved paths (symlinks, junctions, 8.3 names gone), so roots are resolved too when they exist.
        let roots: Vec<PathBuf> = config.paths.iter().map(|root| resolve(root)).collect();
        let mut include = GlobSetBuilder::new();
        for root in &roots {
            include.add(below(root)?);
        }
        let mut exclude = GlobSetBuilder::new();
        for pattern in &config.exclude {
            exclude.add(glob(slashes(pattern))?);
        }
        for dir in own_dirs {
            exclude.add(below(&resolve(dir))?);
        }
        Ok(Filter { roots, include: build(include)?, exclude: build(exclude)? })
    }

    /// Under a watched root and not excluded.
    pub fn wants(&self, path: &Path) -> bool {
        let path = Candidate::new(path);
        self.include.is_match_candidate(&path) && !self.exclude.is_match_candidate(&path)
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }
}

/// Cap on the "rescan later" set; past it the set collapses into one full rescan of the roots.
const LATER_CAP: usize = 100_000;

struct State {
    /// Debouncing: path → (last event, pid of the last writer when the sensor knows it).
    pending: HashMap<PathBuf, (Instant, Option<u32>)>,
    /// Settled, waiting for a worker. At most `cap` long.
    queue: VecDeque<(PathBuf, Option<u32>)>,
    /// Settled while the queue was full. The writer pid is dropped here: by then it is likely stale.
    later: HashSet<PathBuf>,
    /// Workers currently scanning.
    busy: usize,
    stop: bool,
}

pub struct Pipeline {
    filter: Arc<Filter>,
    debounce: Duration,
    cap: usize,
    state: Mutex<State>,
    /// Wakes the debouncer.
    settle: Condvar,
    /// Wakes workers.
    work: Condvar,
}

impl Pipeline {
    /// Spawns the debouncer thread.
    pub fn new(config: &WatchConfig, filter: Arc<Filter>) -> Arc<Pipeline> {
        let state =
            State { pending: HashMap::new(), queue: VecDeque::new(), later: HashSet::new(), busy: 0, stop: false };
        let pipeline = Arc::new(Pipeline {
            filter,
            debounce: Duration::from_millis(config.debounce_ms),
            cap: config.queue.max(1),
            state: Mutex::new(state),
            settle: Condvar::new(),
            work: Condvar::new(),
        });
        let debouncer = pipeline.clone();
        std::thread::Builder::new()
            .name("debouncer".into())
            .spawn(move || debouncer.debounce())
            .expect("spawn debouncer thread");
        pipeline
    }

    /// Sensor entry point. Never blocks (only a short mutex). Drops paths the filter doesn't want.
    /// Directories are fine (a worker walks them). `pid`: the writing process, if the sensor knows it.
    pub fn push(&self, path: PathBuf, pid: Option<u32>) {
        if !self.filter.wants(&path) {
            return;
        }
        let mut s = lock(&self.state);
        if s.pending.len() >= self.cap && !s.pending.contains_key(&path) {
            // ponytail: the issue says flush the oldest pending path; queueing the newcomer undebounced is O(1)
            // and only loses debouncing under an event flood.
            self.enqueue(&mut s, path, pid);
            self.work.notify_one();
            return;
        }
        let was_empty = s.pending.is_empty();
        s.pending.insert(path, (Instant::now(), pid));
        // Otherwise the debouncer is already timed-waiting for an earlier deadline.
        if was_empty {
            self.settle.notify_one();
        }
    }

    /// Queue every watched root for a full walk (startup, lost events, journal reset). Never blocks.
    pub fn rescan(&self) {
        let mut s = lock(&self.state);
        for root in self.filter.roots() {
            self.enqueue(&mut s, root.clone(), None);
        }
        self.work.notify_all();
    }

    /// Nothing pending, queued, deferred, or being scanned.
    pub fn is_idle(&self) -> bool {
        let s = lock(&self.state);
        s.pending.is_empty() && s.queue.is_empty() && s.later.is_empty() && s.busy == 0
    }

    /// Worker loop: scans queued paths with `engine` until stop(). One call per worker thread, each with its own Engine.
    /// `on_file` gets each file's detections together, plus the writer's pid when known.
    pub fn work(&self, engine: &mut Engine, on_file: &(dyn Fn(&[Detection], Option<u32>) + Sync)) {
        loop {
            let (path, pid) = {
                let mut s = lock(&self.state);
                loop {
                    if s.stop {
                        return;
                    }
                    // ponytail: HashSet iter().next() rescans emptied buckets, O(n²/16) to drain a full `later`;
                    // fine at 100k, swap for an IndexSet if it shows in profiles.
                    let next = s.queue.pop_front().or_else(|| s.later.iter().next().map(|p| (p.clone(), None)));
                    if let Some((path, pid)) = next {
                        s.later.remove(&path);
                        s.busy += 1;
                        break (path, pid);
                    }
                    s = self.work.wait(s).unwrap_or_else(PoisonError::into_inner);
                }
            };
            // Temp files often vanish before their turn.
            if std::fs::symlink_metadata(&path).is_ok() {
                let scan = catch_unwind(AssertUnwindSafe(|| engine.scan_grouped(&path, |found| on_file(found, pid))));
                if scan.is_err() {
                    log::error!("{}: scan panicked; restarting this worker's engine", path.display());
                    *engine = Engine::new(engine.shared.clone());
                }
            }
            lock(&self.state).busy -= 1;
        }
    }

    pub fn stop(&self) {
        lock(&self.state).stop = true;
        self.settle.notify_all();
        self.work.notify_all();
    }

    /// Queue full → `later`; `later` full → forget it all and rescan the roots (correct and bounded).
    fn enqueue(&self, s: &mut State, path: PathBuf, pid: Option<u32>) {
        if s.queue.len() < self.cap {
            s.queue.push_back((path, pid));
        } else if s.later.len() < LATER_CAP || s.later.contains(&path) {
            s.later.insert(path);
        } else {
            log::warn!("real-time backlog over {LATER_CAP} paths; falling back to a full rescan");
            s.later.clear();
            s.later.extend(self.filter.roots().iter().cloned());
        }
    }

    /// Debouncer thread: moves paths quiet for `debounce` to the queue. Sleeps while nothing is pending.
    fn debounce(&self) {
        let mut s = lock(&self.state);
        while !s.stop {
            if s.pending.is_empty() {
                s = self.settle.wait(s).unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let now = Instant::now();
            let state = &mut *s;
            let ready: Vec<_> = state.pending.extract_if(|_, (t, _)| now.duration_since(*t) >= self.debounce).collect();
            if !ready.is_empty() {
                for (path, (_, pid)) in ready {
                    self.enqueue(state, path, pid);
                }
                self.work.notify_all();
            }
            // ponytail: each wake is O(pending); the debounce/4 floor bounds wakes under a flood at the cost of up
            // to 25% extra latency.
            let Some(oldest) = s.pending.values().map(|v| v.0).min() else { continue };
            let wait = (oldest + self.debounce).saturating_duration_since(now).max(self.debounce / 4);
            s = self.settle.wait_timeout(s, wait).unwrap_or_else(PoisonError::into_inner).0;
        }
    }
}

/// Canonical form without Windows' `\\?\` prefix; a missing path is kept as written.
fn resolve(path: &Path) -> PathBuf {
    let Ok(full) = std::fs::canonicalize(path) else { return path.to_owned() };
    match full.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(dos) if !dos.starts_with("UNC\\") => dos.into(),
        _ => full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("av-watch-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        resolve(&dir) // sensors report resolved paths (the Windows temp dir may be an 8.3 short name)
    }

    fn watching(dir: &Path, debounce_ms: u64, queue: usize) -> (WatchConfig, Arc<Filter>) {
        let config = WatchConfig { paths: vec![dir.to_owned()], debounce_ms, queue, ..WatchConfig::default() };
        let filter = Arc::new(Filter::new(&config, &[dir.join("own")]).unwrap());
        (config, filter)
    }

    #[test]
    fn burst_of_events_scans_once() {
        use sha2::{Digest, Sha256};
        let dir = temp("burst");
        // A harmless file put on a private hash list, so each scan of it is one detection.
        let marked = b"harmless, but listed";
        let file = dir.join("marked.bin");
        std::fs::write(&file, marked).unwrap();
        let hex: String = Sha256::digest(marked).iter().map(|b| format!("{b:02x}")).collect();
        let hashes = dir.join("own/hashes.txt");
        std::fs::create_dir_all(dir.join("own")).unwrap();
        std::fs::write(&hashes, format!("{hex} Test-Marked\n")).unwrap();
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../signatures/rules");
        let shared = crate::Shared::load(&Config { hash_list: hashes, rules_dir, ..Config::default() }).unwrap();

        let (config, filter) = watching(&dir, 50, 10);
        let pipeline = Pipeline::new(&config, filter);
        let scans = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                pipeline.work(&mut Engine::new(shared), &|_, _| {
                    scans.fetch_add(1, Ordering::SeqCst);
                })
            });
            for _ in 0..100 {
                pipeline.push(file.clone(), None);
                std::thread::sleep(Duration::from_millis(10)); // ~1 s of saves, each within the debounce window
            }
            pipeline.push(dir.join("own/hashes.txt"), None); // own dir: dropped
            let deadline = Instant::now() + Duration::from_secs(10);
            while !pipeline.is_idle() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            pipeline.stop();
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scans.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn full_queue_never_blocks_push() {
        let dir = temp("full");
        let (config, filter) = watching(&dir, 60_000, 1);
        let pipeline = Pipeline::new(&config, filter);
        for i in 0..100 {
            pipeline.push(dir.join(format!("f{i}")), None);
        }
        pipeline.push(dir.join("f99"), None); // already deferred: deduplicated
        pipeline.rescan();
        {
            let s = lock(&pipeline.state);
            // 1 debouncing, 1 queued, the rest (plus the root) deferred; no workers, and nothing blocked.
            assert_eq!((s.pending.len(), s.queue.len(), s.later.len()), (1, 1, 99));
        }
        assert!(!pipeline.is_idle());
        pipeline.stop();
        let _ = std::fs::remove_dir_all(&dir);

        // Roots and own dirs, with Windows' case-insensitivity and separators.
        let root =
            |p: &str| Filter::new(&WatchConfig { paths: vec![p.into()], ..WatchConfig::default() }, &[]).unwrap();
        if cfg!(windows) {
            assert!(root("C:\\").wants(Path::new("c:\\x\\y.exe")));
            assert!(root("C:\\Users\\").wants(Path::new("C:/USERS/a/b")));
            assert!(!root("C:\\Users").wants(Path::new("C:\\UsersX\\a")));
        } else {
            assert!(root("/").wants(Path::new("/x/y")));
            assert!(!root("/home").wants(Path::new("/homeX/a")));
        }
        assert!(!pipeline.filter.wants(&dir.join("own/cache.bin")));
    }
}
