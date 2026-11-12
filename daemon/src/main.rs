//! Service binary: `avd scan` runs a manual scan, `avd run` (or the Windows service) monitors in real time.

mod realtime;
#[cfg(windows)]
mod service;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use av_core::cache::{self, Cache};
use av_core::{Config, Engine, Platform, Shared};

fn platform(config: &Config) -> Option<Arc<dyn Platform>> {
    #[cfg(windows)]
    return Some(Arc::new(sensors_windows::WindowsPlatform::new(&config.trust)));
    #[cfg(target_os = "linux")]
    return Some(Arc::new(sensors_linux::LinuxPlatform::new(&config.trust)));
    #[allow(unreachable_code)]
    {
        let _ = config;
        None
    }
}

/// `cache_dir` from config, else the system location when writable (service / admin), else the user's cache dir.
// ponytail: a system dir created by a normal user is owned by that user; M4 self-protection locks down the ACLs.
fn cache_dir(config: &Config) -> Option<PathBuf> {
    let env = |k| std::env::var_os(k).map(PathBuf::from);
    let (system, user) = if cfg!(windows) {
        (env("ProgramData"), env("LOCALAPPDATA"))
    } else {
        (Some("/var/lib".into()), env("XDG_CACHE_HOME").or_else(|| env("HOME").map(|h| h.join(".cache"))))
    };
    let writable = |dir: &PathBuf| {
        let probe = dir.join(".probe");
        let ok = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&probe, b"")).is_ok();
        let _ = std::fs::remove_file(probe);
        ok
    };
    let default = || system.map(|d| d.join("avd/cache")).filter(writable).or(user.map(|d| d.join("avd/cache")));
    let dir = config.cache_dir.clone().or_else(default);
    if dir.is_none() {
        log::warn!("no cache directory found, verdict cache off");
    }
    dir
}

/// Signatures plus platform identity/trust and the on-disk verdict cache in `dir`.
fn shared(config: &Config, dir: Option<&Path>) -> Result<Shared, String> {
    let mut shared = Shared::load(config)?;
    shared.platform = platform(config);
    if shared.platform.is_some() {
        shared.cache = dir.map(|d| {
            let cache = Cache::load(&d.join("verdicts.bin"), shared.ruleset(), cache::DEFAULT_CAP);
            Arc::new(Mutex::new(cache))
        });
    }
    Ok(shared)
}

fn save_cache(shared: &Shared) {
    if let Some(Err(e)) = shared.cache.as_ref().map(|c| av_core::lock(c).save()) {
        log::warn!("verdict cache not saved: {e}");
    }
}

/// `<timestamp> LEVEL message` lines.
struct Logger {
    level: log::Level,
    out: Mutex<Box<dyn Write + Send>>,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let _ = writeln!(av_core::lock(&self.out), "{now} {:<5} {}", record.level(), record.args());
        }
    }
    fn flush(&self) {
        let _ = av_core::lock(&self.out).flush();
    }
}

fn init_log(level: log::Level, out: Box<dyn Write + Send>) {
    log::set_logger(Box::leak(Box::new(Logger { level, out: Mutex::new(out) }))).expect("logger set once");
    log::set_max_level(level.to_level_filter());
}

const USAGE: &str =
    "usage: avd scan <path> [-c config] | avd run [-c config] | avd install [-c config] | avd uninstall";

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let config = match args.iter().position(|a| a == "-c") {
        Some(i) if i + 1 < args.len() => {
            args.remove(i);
            args.remove(i)
        }
        Some(_) => String::new(), // `-c` without a value: falls through to usage below
        None => "antivirus.toml".into(),
    };
    let config = PathBuf::from(config);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args[..] {
        _ if config.as_os_str().is_empty() => Err(USAGE.into()),
        ["scan", path] => {
            init_log(log::Level::Warn, Box::new(std::io::stderr()));
            return scan(Path::new(path), &config);
        }
        ["run"] => {
            init_log(log::Level::Info, Box::new(std::io::stderr()));
            let (stop_tx, stop) = std::sync::mpsc::channel();
            // SIGTERM/SIGINT → clean stop. Must come before any thread exists.
            #[cfg(target_os = "linux")]
            sensors_linux::on_terminate(move || {
                let _ = stop_tx.send(());
            });
            // ponytail: Windows Ctrl+C just kills the process; the USN cursor replay and periodic cache save cover it.
            #[cfg(not(target_os = "linux"))]
            let _keep = stop_tx;
            realtime::run(&config, stop)
        }
        #[cfg(windows)]
        ["service"] => service::dispatch(config),
        #[cfg(windows)]
        ["install"] => {
            init_log(log::Level::Info, Box::new(std::io::stderr()));
            service::install(&config)
        }
        #[cfg(windows)]
        ["uninstall"] => {
            init_log(log::Level::Info, Box::new(std::io::stderr()));
            service::uninstall()
        }
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("avd: {e}");
            ExitCode::from(2)
        }
    }
}

/// `avd scan`. Exit codes: 0 clean, 1 detections, 2 error.
fn scan(path: &Path, config: &Path) -> ExitCode {
    let loaded = Config::load(config).and_then(|config| shared(&config, cache_dir(&config).as_deref()));
    let shared = match loaded {
        Ok(shared) => shared,
        Err(e) => {
            eprintln!("avd: {e}");
            return ExitCode::from(2);
        }
    };
    let mut engine = Engine::new(shared.clone());
    // A nonexistent path shows up as a walk error, so it exits 2 below.
    let start = Instant::now();
    let stats = engine.scan(path, |d| {
        println!("{}\t{}\t{}\t{:?}", d.path.display(), d.engine, d.name, d.file_type);
    });
    eprintln!(
        "scanned {}, skipped {}, errors {}, detections {}, limit hits {}, encrypted {}, unsupported {}, cache hits {}, trusted {}, elapsed {:.2?}",
        stats.scanned,
        stats.skipped,
        stats.errors,
        stats.detections,
        stats.limit_hits,
        stats.encrypted,
        stats.unsupported,
        stats.cache_hits,
        stats.trusted,
        start.elapsed()
    );
    save_cache(&shared);

    match (stats.detections, stats.errors) {
        (1.., _) => ExitCode::from(1),
        (_, 1..) => ExitCode::from(2),
        _ => ExitCode::SUCCESS,
    }
}
