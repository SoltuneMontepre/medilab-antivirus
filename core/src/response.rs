//! What happens after a detection: the configured action, one JSON line per detection in
//! `<data_dir>/detections.jsonl`, and a notification message.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::{lock, quarantine, Config, Detection, Platform, ProcessOp};

/// Each action includes the ones before it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Log and notify only.
    #[default]
    Alert,
    /// Also move the file into quarantine.
    Quarantine,
    /// Also suspend the process that wrote the file, when the sensor knows it (Linux fanotify).
    Suspend,
    /// Also kill that process.
    Kill,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Action::Alert => "alert",
            Action::Quarantine => "quarantine",
            Action::Suspend => "suspend",
            Action::Kill => "kill",
        })
    }
}

/// `[actions]`: `default`, plus one key per engine (`hash = "quarantine"`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Actions {
    #[serde(default)]
    pub default: Action,
    #[serde(flatten)]
    pub engines: BTreeMap<String, Action>,
}

impl Actions {
    pub fn for_engine(&self, engine: &str) -> Action {
        self.engines.get(engine).copied().unwrap_or(self.default)
    }
}

/// One line of the detection log.
#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub time: String,
    /// `a.zip!b/c.exe` inside containers.
    pub path: String,
    pub sha256: String,
    pub file_type: String,
    pub engine: String,
    pub rule: String,
    pub pid: Option<u32>,
    pub action: Action,
    pub action_result: String,
    pub quarantine_id: Option<String>,
}

const LOG_MAX: u64 = 10 << 20;
/// Rotated files kept: detections.jsonl.1 … .5.
const LOG_KEEP: u32 = 5;

pub struct Responder {
    actions: Actions,
    data_dir: Option<PathBuf>,
    platform: Option<Arc<dyn Platform>>,
    /// One writer at a time, so lines never interleave and rotation doesn't race.
    log_lock: Mutex<()>,
    notify: Option<Box<dyn Fn(String) + Send + Sync>>,
}

impl Responder {
    pub fn new(
        config: &Config,
        platform: Option<Arc<dyn Platform>>,
        notify: Option<Box<dyn Fn(String) + Send + Sync>>,
    ) -> Self {
        Self {
            actions: config.actions.clone(),
            data_dir: config.data_dir.clone(),
            platform,
            log_lock: Mutex::new(()),
            notify,
        }
    }

    /// Acts on one file's detections (the strongest action of their engines, once), logs one record per
    /// detection, and sends one notification. `pid`: the process that wrote the file, if known.
    pub fn respond(&self, found: &[Detection], pid: Option<u32>) {
        let Some(first) = found.first() else { return };
        let action = found.iter().map(|d| self.actions.for_engine(d.engine)).max().unwrap_or_default();
        let mut results = Vec::new();
        // The process first, so it can't rewrite the file while it is being quarantined.
        let mut stopped = None;
        if action >= Action::Suspend {
            let (op, done) =
                if action == Action::Kill { (ProcessOp::Kill, "killed") } else { (ProcessOp::Suspend, "suspended") };
            results.push(match (pid, &self.platform) {
                (Some(pid), Some(platform)) => match platform.process(pid, op) {
                    Ok(()) => {
                        stopped = Some(pid);
                        format!("{done} pid {pid}")
                    }
                    Err(e) => format!("pid {pid} not {done}: {e}"),
                },
                _ => "writing process unknown".into(),
            });
        }
        let mut quarantine_id = None;
        if action >= Action::Quarantine {
            let dir = self.data_dir.as_ref().map(|d| d.join("quarantine"));
            let done = dir
                .ok_or_else(|| io::Error::other("no data directory"))
                .and_then(|dir| quarantine::quarantine(&dir, &first.file, found, self.platform.as_deref()));
            results.push(match done {
                Ok(q) => {
                    quarantine_id = Some(q.id);
                    if q.at_reboot { "quarantined (original in use, deleted at reboot)" } else { "quarantined" }.into()
                }
                Err(e) => format!("quarantine failed: {e}"),
            });
        }
        let result = if results.is_empty() { "alerted".to_owned() } else { results.join("; ") };

        let time = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false);
        for d in found {
            let line = format!(
                "detection\t{}\t{}\t{}\t{:?}\t{action}: {result}",
                d.path.display(),
                d.engine,
                d.name,
                d.file_type
            );
            // An alert is routine; anything that acted (or failed to) is worth a warning.
            if action == Action::Alert {
                log::info!("{line}");
            } else {
                log::warn!("{line}");
            }
            self.log(&Record {
                time: time.clone(),
                path: d.path.display().to_string(),
                sha256: quarantine::hex(&d.sha256),
                file_type: format!("{:?}", d.file_type),
                engine: d.engine.into(),
                rule: d.name.clone(),
                pid,
                action,
                action_result: result.clone(),
                quarantine_id: quarantine_id.clone(),
            });
        }

        if let Some(notify) = &self.notify {
            let more = if found.len() > 1 { format!(" (+{} more)", found.len() - 1) } else { String::new() };
            let mut next = vec!["avd detections".to_owned()];
            if let Some(id) = &quarantine_id {
                next.push(format!("avd restore {id}"));
            }
            if let (Some(pid), Action::Suspend) = (stopped, action) {
                next.push(format!("avd process resume {pid}  or  avd process kill {pid}"));
            }
            let (name, file) = (&first.name, shorten(&first.file, 80));
            notify(format!("{name}{more} found in\n{file}\n\nAction: {result}.\n\n{}", next.join("\n")));
        }
    }

    fn log(&self, record: &Record) {
        let Some(dir) = &self.data_dir else { return };
        let path = dir.join("detections.jsonl");
        let _guard = lock(&self.log_lock);
        let written = rotate(&path).and_then(|()| {
            let mut line = serde_json::to_vec(record)?;
            line.push(b'\n');
            OpenOptions::new().create(true).append(true).open(&path)?.write_all(&line)
        });
        if let Err(e) = written {
            log::error!("detection log {}: {e}", path.display());
        }
    }
}

/// The current detection log (rotated files are not read). Missing = empty; malformed lines are skipped.
pub fn read_log(data_dir: &Path) -> io::Result<Vec<Record>> {
    let file = match fs::File::open(data_dir.join("detections.jsonl")) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(io::BufReader::new(file).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str(&l).ok()).collect())
}

/// Past `LOG_MAX`: .4 → .5, …, current → .1.
fn rotate(path: &Path) -> io::Result<()> {
    if fs::metadata(path).map_or(true, |m| m.len() < LOG_MAX) {
        return Ok(());
    }
    let numbered = |i: u32| {
        let mut p = path.as_os_str().to_owned();
        p.push(format!(".{i}"));
        PathBuf::from(p)
    };
    for i in (1..LOG_KEEP).rev() {
        let _ = fs::rename(numbered(i), numbered(i + 1));
    }
    fs::rename(path, numbered(1))
}

/// `C:\Users\me\…\deep\file.exe`: keeps both ends of a long path.
fn shorten(path: &Path, max: usize) -> String {
    let chars: Vec<char> = path.display().to_string().chars().collect();
    if chars.len() <= max {
        return chars.into_iter().collect();
    }
    let head = max / 3;
    let tail = max - head - 1;
    chars[..head].iter().chain(['…'].iter()).chain(&chars[chars.len() - tail..]).collect()
}
