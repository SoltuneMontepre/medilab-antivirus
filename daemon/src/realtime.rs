//! `avd run`: sensors → watch pipeline → worker pool → responder, with periodic checkpoints until told to stop.

use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use av_core::response::Responder;
use av_core::watch::{Filter, Pipeline};
use av_core::Engine;

const CHECKPOINT: Duration = Duration::from_secs(60);

/// Runs until `stop` receives (or its sender is dropped). Startup errors are returned; later ones are logged.
pub fn run(config_path: &Path, stop: Receiver<()>) -> Result<(), String> {
    let config = crate::load(config_path, true)?;
    // Before any thread exists, so every worker inherits the low CPU and I/O priority.
    #[cfg(windows)]
    let lowered = sensors_windows::lower_priority();
    #[cfg(target_os = "linux")]
    let lowered = sensors_linux::lower_priority();
    #[cfg(any(windows, target_os = "linux"))]
    if let Err(e) = lowered {
        log::warn!("could not lower process priority: {e}");
    }

    let notifier = config.notify.then(crate::notify::start);
    let alert = |message: String| {
        log::warn!("{}", message.replace('\n', " "));
        if let Some(n) = &notifier {
            n.send(message);
        }
    };
    let dir = config.data_dir.clone();
    if let Some(dir) = &dir {
        crate::protect::startup(&config, config_path, dir, &alert);
    }

    let mut shared = crate::shared(&config)?;
    let notify = notifier.clone().map(|n| Box::new(move |m| n.send(m)) as Box<dyn Fn(String) + Send + Sync>);
    let responder = Arc::new(Responder::new(&config, shared.platform.clone(), notify));
    let filter = Arc::new(Filter::new(&config.watch, dir.as_slice())?);
    shared.filter = Some(filter.clone());
    let pipeline = Pipeline::new(&config.watch, filter.clone());
    for i in 0..config.watch.workers.max(1) {
        let (shared, pipeline, responder) = (shared.clone(), pipeline.clone(), responder.clone());
        thread::Builder::new()
            .name(format!("scan-{i}"))
            .spawn(move || pipeline.work(&mut Engine::new(shared), &|found, pid| responder.respond(found, pid)))
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
        let jobs = fanotify::guard_exec(roots, Duration::from_millis(300), quick, move |p| late.push(p, None))
            .map_err(|e| format!("fanotify (exec): {e}"))?;
        let (shared, responder) = (shared.clone(), responder.clone());
        thread::Builder::new()
            .name("exec".into())
            .spawn(move || {
                let mut engine = Engine::new(shared);
                for job in jobs {
                    let mut found = Vec::new();
                    // A dup of the event fd: the job keeps its own until answered.
                    let scan = || job.file.try_clone().map(|f| engine.scan_handle(&job.path, f, |d| found.push(d)));
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
                    let path = job.path.clone();
                    // Answer first: the exec waits on it, and acting (quarantine, fsync) can take longer than the
                    // deadline. The exec is blocked, so no process action: the caller only tried to run the file.
                    job.answer(allow);
                    if !allow {
                        log::warn!("blocked exec of {}", path.display());
                        responder.respond(&found, None);
                    }
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
        if let Some(dir) = &dir {
            crate::protect::heartbeat(dir);
        }
        if stopping {
            break;
        }
    }
    // Sensor threads stay blocked in their reads; the process exits right after this returns.
    pipeline.stop();
    if let Some(dir) = &dir {
        crate::protect::clean_stop(dir);
    }
    log::info!("stopped");
    Ok(())
}
