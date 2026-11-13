//! Service binary: `avd scan` runs a manual scan, `avd run` (or the Windows service) monitors in real time; the
//! rest manage the quarantine, the detection log and suspended processes.

mod notify;
mod protect;
mod realtime;
#[cfg(windows)]
mod service;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use av_core::cache::{self, Cache};
use av_core::response::{self, Responder};
use av_core::{quarantine, Config, Engine, Platform, ProcessOp, Shared};

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

/// avd's state directory: `data_dir` from config, else the system one (`%ProgramData%\avd`, `/var/lib/avd`) when
/// usable, else the user's. `write`: usable means writable (scans, the service; created if missing); otherwise
/// readable (listing commands), so an admin sees the service's data and a normal user their own.
fn data_dir(config: &Config, write: bool) -> Option<PathBuf> {
    let env = |k| std::env::var_os(k).map(PathBuf::from);
    let (system, user) = if cfg!(windows) {
        (env("ProgramData").map(|d| d.join("avd")), env("LOCALAPPDATA").map(|d| d.join("avd")))
    } else {
        let user = env("XDG_DATA_HOME").or_else(|| env("HOME").map(|h| h.join(".local/share")));
        (Some("/var/lib/avd".into()), user.map(|d| d.join("avd")))
    };
    let usable = |dir: &PathBuf| {
        if !write {
            return std::fs::read_dir(dir).is_ok();
        }
        let probe = dir.join(".probe");
        let ok = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&probe, b"")).is_ok();
        let _ = std::fs::remove_file(probe);
        ok
    };
    let dir = config.data_dir.clone().or_else(|| system.filter(usable).or(user));
    match &dir {
        Some(dir) if write => {
            if let Err(e) = std::fs::create_dir_all(dir) {
                log::warn!("{}: {e}", dir.display());
            }
        }
        Some(_) => {}
        None => log::warn!("no data directory found: no verdict cache, quarantine or detection log"),
    }
    dir
}

/// The config with `data_dir` resolved.
fn load(config: &Path, write: bool) -> Result<Config, String> {
    let mut loaded = Config::load(config)?;
    loaded.data_dir = data_dir(&loaded, write);
    Ok(loaded)
}

/// Signatures plus platform identity/trust and the on-disk verdict cache in the data dir.
fn shared(config: &Config) -> Result<Shared, String> {
    let mut shared = Shared::load(config)?;
    shared.platform = platform(config);
    if shared.platform.is_some() {
        shared.cache = config.data_dir.as_ref().map(|d| {
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

const USAGE: &str = "usage:
  avd scan <path>                  scan once (exit 0 clean, 1 detections, 2 error)
  avd run                          real-time protection in the foreground
  avd install | avd uninstall      Windows service (admin)
  avd quarantine list
  avd restore <id> [--to <path>] [--force] [--allow]
  avd allow <file>                 false positive: never detect this content again
  avd detections [--since 24h]     units: s, m, h, d
  avd process resume|kill <pid>
every command takes -c <config> (default: antivirus.toml)";

/// Removes `name` and its value from `args`. None: absent; Some(None): present without a value.
fn take_value(args: &mut Vec<String>, name: &str) -> Option<Option<String>> {
    let i = args.iter().position(|a| a == name)?;
    args.remove(i);
    Some((i < args.len()).then(|| args.remove(i)))
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    args.iter().position(|a| a == name).map(|i| args.remove(i)).is_some()
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (config, to, since) =
        (take_value(&mut args, "-c"), take_value(&mut args, "--to"), take_value(&mut args, "--since"));
    let (force, allow) = (take_flag(&mut args, "--force"), take_flag(&mut args, "--allow"));
    if [&config, &to, &since].iter().any(|v| matches!(v, Some(None))) {
        eprintln!("{USAGE}"); // an option without its value
        return ExitCode::from(2);
    }
    let config = PathBuf::from(config.flatten().unwrap_or_else(|| "antivirus.toml".into()));
    let (to, since) = (to.flatten(), since.flatten());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args[..] {
        ["service"] => {} // logs to a file, set up by the service
        ["run"] | ["install"] | ["uninstall"] => init_log(log::Level::Info, Box::new(std::io::stderr())),
        _ => init_log(log::Level::Warn, Box::new(std::io::stderr())),
    }
    let result = match args[..] {
        ["scan", path] => return scan(Path::new(path), &config),
        ["run"] => {
            let (stop_tx, stop) = std::sync::mpsc::channel();
            // SIGTERM/SIGINT (Ctrl+C on Windows) → clean stop. Must come before any thread exists.
            #[cfg(target_os = "linux")]
            sensors_linux::on_terminate(move || {
                let _ = stop_tx.send(());
            });
            #[cfg(windows)]
            sensors_windows::on_terminate(move || {
                let _ = stop_tx.send(());
            });
            #[cfg(not(any(windows, target_os = "linux")))]
            let _keep = stop_tx;
            realtime::run(&config, stop)
        }
        #[cfg(windows)]
        ["service"] => service::dispatch(config),
        #[cfg(windows)]
        ["install"] => service::install(&config),
        #[cfg(windows)]
        ["uninstall"] => service::uninstall(),
        ["quarantine", "list"] => quarantine_list(&config),
        ["restore", id] => restore(&config, id, to.as_deref(), force, allow),
        ["allow", file] => allow_file(&config, Path::new(file)),
        ["detections"] => detections(&config, since.as_deref().unwrap_or("24h")),
        ["process", op @ ("resume" | "kill"), pid] => process(&config, op, pid),
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

/// `avd scan`. Exit codes: 0 clean, 1 detections, 2 error. Configured actions apply here too.
fn scan(path: &Path, config: &Path) -> ExitCode {
    let loaded = load(config, true).and_then(|config| Ok((shared(&config)?, config)));
    let (shared, config) = match loaded {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("avd: {e}");
            return ExitCode::from(2);
        }
    };
    let responder = Responder::new(&config, shared.platform.clone(), None);
    let mut engine = Engine::new(shared.clone());
    // A nonexistent path shows up as a walk error, so it exits 2 below.
    let start = Instant::now();
    let stats = engine.scan_grouped(path, |found| {
        for d in found {
            println!("{}\t{}\t{}\t{:?}", d.path.display(), d.engine, d.name, d.file_type);
        }
        responder.respond(found, None);
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

fn data_dir_of(config: &Path) -> Result<PathBuf, String> {
    load(config, false)?.data_dir.ok_or_else(|| "no data directory".into())
}

/// `id  time  detections  original path`, oldest first.
fn quarantine_list(config: &Path) -> Result<(), String> {
    let dir = data_dir_of(config)?.join("quarantine");
    for e in quarantine::list(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        println!("{}\t{}\t{}\t{}", e.id, e.time, e.detections.join(","), e.path.display());
    }
    Ok(())
}

fn restore(config: &Path, id: &str, to: Option<&str>, force: bool, allow: bool) -> Result<(), String> {
    let dir = data_dir_of(config)?;
    let qdir = dir.join("quarantine");
    let entry = quarantine::entry(&qdir, id).map_err(|e| e.to_string())?;
    if allow {
        // Before the file reappears, so real-time protection doesn't catch it again.
        add_allowed(&dir, &entry.sha256, &format!("restored {} from {}", entry.id, entry.path.display()))?;
    }
    let target = quarantine::restore(&qdir, &entry, to.map(Path::new), force).map_err(|e| e.to_string())?;
    println!("restored {id} to {}", target.display());
    if !allow {
        eprintln!("note: it is still detected; real-time protection may quarantine it again (--allow releases it)");
    }
    Ok(())
}

/// `avd allow <file>`: a false positive left in place (alert mode) stops being detected, contents included.
fn allow_file(config: &Path, file: &Path) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    std::fs::File::open(file)
        .and_then(|mut f| std::io::copy(&mut f, &mut hasher))
        .map_err(|e| format!("{}: {e}", file.display()))?;
    let sha256 = quarantine::hex(&hasher.finalize());
    let full = std::path::absolute(file).unwrap_or_else(|_| file.into());
    add_allowed(&data_dir_of(config)?, &sha256, &format!("allowed {}", full.display()))?;
    println!("{sha256} allowed; any file with this content is no longer detected");
    Ok(())
}

/// Appends `<sha256> <note>` to `<data dir>/allowed.txt`; a running service re-reads it on its next scan.
fn add_allowed(dir: &Path, sha256: &str, note: &str) -> Result<(), String> {
    let allowed = dir.join("allowed.txt");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&allowed)
        .and_then(|mut f| f.write_all(format!("{sha256} {note}\n").as_bytes()))
        .map_err(|e| format!("{}: {e}", allowed.display()))
}

/// `time  action  result  engine  rule  path` for records newer than `since`.
fn detections(config: &Path, since: &str) -> Result<(), String> {
    let dir = data_dir_of(config)?;
    let bad = || format!("bad --since `{since}`: expected a number and s, m, h or d");
    let (n, unit) = since.split_at(since.len().saturating_sub(1));
    let n: i64 = n.parse().map_err(|_| bad())?;
    let seconds = n * match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(bad()),
    };
    let cutoff = chrono::Local::now().timestamp() - seconds;
    for r in response::read_log(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        if chrono::DateTime::parse_from_rfc3339(&r.time).is_ok_and(|t| t.timestamp() >= cutoff) {
            println!("{}\t{}\t{}\t{}\t{}\t{}", r.time, r.action, r.action_result, r.engine, r.rule, r.path);
        }
    }
    Ok(())
}

fn process(config: &Path, op: &str, pid: &str) -> Result<(), String> {
    let platform = platform(&Config::load(config)?).ok_or("not supported on this OS")?;
    let pid: u32 = pid.parse().map_err(|_| format!("bad pid `{pid}`"))?;
    let op = if op == "kill" { ProcessOp::Kill } else { ProcessOp::Resume };
    platform.process(pid, op).map_err(|e| format!("pid {pid}: {e}"))?;
    println!("pid {pid}: {}", if op == ProcessOp::Kill { "killed" } else { "resumed" });
    Ok(())
}
