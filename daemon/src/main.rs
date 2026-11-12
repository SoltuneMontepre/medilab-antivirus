//! Service binary: picks sensors per OS; `avd scan <path>` runs a manual scan.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use av_core::cache::{self, Cache};
use av_core::{Config, Engine, Platform};

fn platform(config: &Config) -> Option<Box<dyn Platform>> {
    #[cfg(windows)]
    return Some(Box::new(sensors_windows::WindowsPlatform::new(&config.trust)));
    #[cfg(target_os = "linux")]
    return Some(Box::new(sensors_linux::LinuxPlatform::new(&config.trust)));
    #[allow(unreachable_code)]
    {
        let _ = config;
        None
    }
}

/// `cache_dir` from config, else the system location when writable (service / admin), else the user's cache dir.
// ponytail: a system dir created by a normal user is owned by that user; M4 self-protection locks down the ACLs.
fn cache_file(config: &Config) -> Option<PathBuf> {
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
    dir.map(|d| d.join("verdicts.bin"))
}

/// Warnings and errors to stderr, one per line.
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{}: {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}

const USAGE: &str = "usage: avd scan <path> [-c config]";

fn main() -> ExitCode {
    log::set_logger(&StderrLogger).expect("logger set once");
    log::set_max_level(log::LevelFilter::Warn);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (path, config) = match args[..] {
        ["scan", path] => (path, "antivirus.toml"),
        ["scan", path, "-c", config] | ["scan", "-c", config, path] => (path, config),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let loaded = Config::load(Path::new(config)).and_then(|config| Ok((Engine::load(&config)?, config)));
    let (mut engine, config) = match loaded {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("avd: {e}");
            return ExitCode::from(2);
        }
    };
    engine.platform = platform(&config);
    if engine.platform.is_some() {
        engine.cache = cache_file(&config).map(|path| Cache::load(&path, engine.ruleset(), cache::DEFAULT_CAP));
    }
    // A nonexistent path shows up as a walk error, so it exits 2 below.
    let start = Instant::now();
    let stats = engine.scan(Path::new(path), |d| {
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
    if let Some(Err(e)) = engine.cache.as_mut().map(Cache::save) {
        log::warn!("verdict cache not saved: {e}");
    }

    match (stats.detections, stats.errors) {
        (1.., _) => ExitCode::from(1),
        (_, 1..) => ExitCode::from(2),
        _ => ExitCode::SUCCESS,
    }
}
