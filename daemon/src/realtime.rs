//! `avd run`: sensors → watch pipeline → worker pool, with periodic checkpoints until told to stop.

use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use av_core::watch::{Filter, Pipeline};
use av_core::{Config, Detection, Engine};

const CHECKPOINT: Duration = Duration::from_secs(60);

fn report(d: Detection) {
    log::warn!("detection\t{}\t{}\t{}\t{:?}", d.path.display(), d.engine, d.name, d.file_type);
}

/// Runs until `stop` receives (or its sender is dropped). Startup errors are returned; later ones are logged.
pub fn run(config_path: &Path, stop: Receiver<()>) -> Result<(), String> {
    let config = Config::load(config_path)?;
    // Before any thread exists, so every worker inherits the low CPU and I/O priority.
    #[cfg(windows)]
    let lowered = sensors_windows::lower_priority();
    #[cfg(target_os = "linux")]
    let lowered = sensors_linux::lower_priority();
    #[cfg(any(windows, target_os = "linux"))]
    if let Err(e) = lowered {
        log::warn!("could not lower process priority: {e}");
    }

    let dir = crate::cache_dir(&config);
    let mut shared = crate::shared(&config, dir.as_deref())?;
    let filter = Arc::new(Filter::new(&config.watch, dir.as_slice())?);
    shared.filter = Some(filter.clone());
    let pipeline = Pipeline::new(&config.watch, filter.clone());
    for i in 0..config.watch.workers.max(1) {
        let (shared, pipeline) = (shared.clone(), pipeline.clone());
        thread::Builder::new()
            .name(format!("scan-{i}"))
            .spawn(move || pipeline.work(&mut Engine::new(shared), &report))
            .map_err(|e| format!("worker thread: {e}"))?;
    }
    let roots = filter.roots();

    #[cfg(windows)]
    let checkpoint_cursors = {
        use sensors_windows::usn;
        let file = dir.as_ref().map(|d| d.join("usn-cursors.txt"));
        let saved = file.as_deref().map(usn::load_cursors).unwrap_or_default();
        let cursors = usn::watch(roots, &saved, pipeline.clone()).map_err(|e| format!("USN journal: {e}"))?;
        let pipeline = pipeline.clone();
        move || {
            // Snapshot first: a reader moves its cursor only after pushing the paths before it, so an idle
            // pipeline after the snapshot means everything up to it was scanned.
            let snapshot: Vec<_> = cursors.iter().map(|c| av_core::lock(c).clone()).collect();
            if let (Some(file), true) = (&file, pipeline.is_idle()) {
                if let Err(e) = usn::save_cursors(file, &snapshot) {
                    log::warn!("USN cursors not saved: {e}");
                }
            }
        }
    };
    #[cfg(not(windows))]
    let checkpoint_cursors = || {};

    #[cfg(target_os = "linux")]
    {
        use sensors_linux::fanotify;
        fanotify::watch_writes(roots, pipeline.clone()).map_err(|e| format!("fanotify (writes): {e}"))?;
        let (quick_filter, quick_shared) = (filter.clone(), shared.clone());
        let quick = move |path: &Path, file: &std::fs::File| {
            if !quick_filter.wants(path) {
                return Some(true);
            }
            let clean = quick_shared.cached_clean(file);
            if clean == Some(false) {
                log::warn!("blocked exec of {} (cached detection)", path.display());
            }
            clean
        };
        let late = pipeline.clone();
        let jobs = fanotify::guard_exec(roots, Duration::from_millis(300), quick, move |p| late.push(p))
            .map_err(|e| format!("fanotify (exec): {e}"))?;
        let shared = shared.clone();
        thread::Builder::new()
            .name("exec".into())
            .spawn(move || {
                let mut engine = Engine::new(shared);
                for job in jobs {
                    // A dup of the event fd: the job keeps its own until answered.
                    let scan = || job.file.try_clone().map(|f| engine.scan_handle(&job.path, f, report));
                    // An error or a panic allows the exec (fail open, like the deadline) and keeps this thread alive.
                    let allow = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(scan)) {
                        Ok(Ok(stats)) => stats.detections == 0,
                        Ok(Err(e)) => {
                            log::warn!("exec check of {}: {e}; allowed", job.path.display());
                            true
                        }
                        Err(_) => {
                            log::error!("scan of {} panicked; exec allowed", job.path.display());
                            true
                        }
                    };
                    if !allow {
                        log::warn!("blocked exec of {}", job.path.display());
                    }
                    job.answer(allow);
                }
            })
            .map_err(|e| format!("exec thread: {e}"))?;
    }

    let shown: Vec<_> = roots.iter().map(|r| r.display().to_string()).collect();
    log::info!("watching {}", shown.join(", "));
    loop {
        let stopping = !matches!(stop.recv_timeout(CHECKPOINT), Err(RecvTimeoutError::Timeout));
        checkpoint_cursors();
        crate::save_cache(&shared);
        if stopping {
            break;
        }
    }
    // Sensor threads stay blocked in their reads; the process exits right after this returns.
    pipeline.stop();
    log::info!("stopped");
    Ok(())
}
