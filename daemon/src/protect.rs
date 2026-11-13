//! Self-protection at startup: lock down the data directory, warn when ordinary users could change the config or
//! signatures, log config changes (alerting when protection got weaker), and report an unexpected previous stop.
//! None of this stops admin/root malware; it makes tampering noticed.

use std::fs;
use std::path::{Path, PathBuf};

use av_core::Config;

/// Exists while avd runs; holds the last heartbeat time. Still there at startup = the last run didn't stop cleanly.
const RUNNING: &str = "running";
/// The effective config of the previous start.
const SNAPSHOT: &str = "config.json";

pub fn startup(config: &Config, config_path: &Path, dir: &Path, alert: &dyn Fn(String)) {
    #[cfg(target_os = "linux")]
    use sensors_linux::{lock_down, user_writable};
    #[cfg(windows)]
    use sensors_windows::{lock_down, user_writable};

    #[cfg(any(windows, target_os = "linux"))]
    {
        if let Err(e) = lock_down(dir) {
            log::warn!("{}: could not restrict access to admins: {e}", dir.display());
        }
        // The files plus their directories (whoever can write a directory can replace what's in it).
        let mut paths: Vec<PathBuf> = vec![std::path::absolute(config_path).unwrap_or_else(|_| config_path.into())];
        paths.extend([config.hash_list.clone(), config.rules_dir.clone()]);
        if let Ok(rules) = fs::read_dir(&config.rules_dir) {
            paths.extend(rules.flatten().map(|e| e.path()));
        }
        let parents: Vec<PathBuf> = paths.iter().filter_map(|p| p.parent().map(Path::to_path_buf)).collect();
        paths.extend(parents);
        paths.sort();
        paths.dedup();
        let open: Vec<String> =
            paths.iter().filter(|p| user_writable(p).unwrap_or(false)).map(|p| p.display().to_string()).collect();
        if !open.is_empty() {
            alert(format!(
                "Non-admin users can change avd's config or signatures, so any program can switch protection off:\n{}\n\nMove them to an admin-only location (see the README).",
                open.join("\n")
            ));
        }
    }
    audit_config(config, dir, alert);

    if let Ok(last) = fs::read_to_string(dir.join(RUNNING)) {
        alert(format!(
            "avd stopped unexpectedly; it was last seen running at {}. It may have crashed or been killed.",
            last.trim()
        ));
    }
    heartbeat(dir);
}

/// Called every checkpoint.
pub fn heartbeat(dir: &Path) {
    let now = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    if let Err(e) = fs::write(dir.join(RUNNING), now) {
        log::warn!("heartbeat: {e}");
    }
}

pub fn clean_stop(dir: &Path) {
    let _ = fs::remove_file(dir.join(RUNNING));
}

/// Logs what changed since the previous start; alerts when exclusions grew, watched paths shrank, an action got
/// weaker, trust widened or notifications were switched off.
fn audit_config(config: &Config, dir: &Path, alert: &dyn Fn(String)) {
    let path = dir.join(SNAPSHOT);
    let now = match serde_json::to_string_pretty(config) {
        Ok(now) => now,
        Err(e) => return log::warn!("config snapshot: {e}"),
    };
    let before = fs::read_to_string(&path).ok();
    if let Some(before) = before.as_deref().filter(|b| *b != now) {
        let (old, new): (Vec<&str>, Vec<&str>) = (before.lines().collect(), now.lines().collect());
        let removed = old.iter().filter(|l| !new.contains(l)).map(|l| format!("- {}", l.trim()));
        let added = new.iter().filter(|l| !old.contains(l)).map(|l| format!("+ {}", l.trim()));
        log::warn!("config changed since the last start:\n{}", removed.chain(added).collect::<Vec<_>>().join("\n"));

        if let Ok(old) = serde_json::from_str::<Config>(before) {
            let mut weaker = Vec::new();
            weaker.extend(
                config
                    .watch
                    .exclude
                    .iter()
                    .filter(|e| !old.watch.exclude.contains(e))
                    .map(|e| format!("new exclusion {e}")),
            );
            weaker.extend(
                old.watch
                    .paths
                    .iter()
                    .filter(|p| !config.watch.paths.contains(p))
                    .map(|p| format!("{} no longer watched", p.display())),
            );
            // Engines that exist, plus any the old config named.
            let engines: std::collections::BTreeSet<String> =
                ["hash", "yara"].into_iter().map(String::from).chain(old.actions.engines.keys().cloned()).collect();
            for engine in engines {
                let (was, is) = (old.actions.for_engine(&engine), config.actions.for_engine(&engine));
                if is < was {
                    weaker.push(format!("{engine} action {was} -> {is}"));
                }
            }
            weaker.extend(
                config
                    .trust
                    .publishers
                    .iter()
                    .filter(|p| !old.trust.publishers.contains(p))
                    .map(|p| format!("new trusted publisher {p}")),
            );
            if old.notify && !config.notify {
                weaker.push("notifications off".into());
            }
            if !weaker.is_empty() {
                alert(format!("avd's config was changed to protect less:\n{}", weaker.join("\n")));
            }
        }
    }
    let tmp = dir.join(format!("{SNAPSHOT}.tmp"));
    if let Err(e) = fs::write(&tmp, now).and_then(|()| fs::rename(&tmp, &path)) {
        log::warn!("config snapshot: {e}");
    }
}
