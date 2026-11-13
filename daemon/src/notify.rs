//! Desktop notifications from the daemon, at most one per `GAP`. Messages arriving in between wait and go out
//! together: the first one, plus "…and N more".

use std::sync::mpsc;
use std::time::{Duration, Instant};

const GAP: Duration = Duration::from_secs(10);
const TITLE: &str = "avd antivirus";

#[derive(Clone)]
pub struct Notifier(mpsc::Sender<String>);

impl Notifier {
    /// Never blocks.
    pub fn send(&self, message: String) {
        let _ = self.0.send(message);
    }
}

/// Spawns the notification thread. Showing one is a process spawn (Linux) or a WTS call (Windows); neither may run
/// on a scan worker.
pub fn start() -> Notifier {
    let (tx, rx) = mpsc::channel::<String>();
    let spawned = std::thread::Builder::new().name("notify".into()).spawn(move || {
        while let Ok(mut message) = rx.recv() {
            loop {
                show(&message);
                let end = Instant::now() + GAP;
                let (mut next, mut more) = (None, 0);
                while let Ok(m) = rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
                    match next {
                        None => next = Some(m),
                        Some(_) => more += 1,
                    }
                }
                match next {
                    Some(m) if more > 0 => message = format!("{m}\n\n…and {more} more; run `avd detections`."),
                    Some(m) => message = m,
                    None => break,
                }
            }
        }
    });
    if let Err(e) = spawned {
        log::error!("notification thread: {e}; notifications off");
    }
    Notifier(tx)
}

fn show(message: &str) {
    #[cfg(windows)]
    sensors_windows::notify(TITLE, message);
    #[cfg(target_os = "linux")]
    sensors_linux::notify(TITLE, message);
    #[cfg(not(any(windows, target_os = "linux")))]
    log::info!("{TITLE}: {message}");
}
