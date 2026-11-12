//! Windows service: SCM entry point (`avd service`) and `avd install` / `avd uninstall`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, OnceLock};
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "avd";
const LOG_ROTATE: u64 = 10 * 1024 * 1024;

/// The SCM calls `service_main` without our launch arguments, so the config path waits here.
static CONFIG: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// `avd service -c <config>`: only works when started by the SCM.
pub fn dispatch(config: PathBuf) -> Result<(), String> {
    CONFIG.set(config).expect("dispatch runs once");
    service_dispatcher::start(NAME, ffi_service_main)
        .map_err(|e| format!("not started by the service manager: {}", os(e)))
}

fn service_main(_: Vec<OsString>) {
    let config = CONFIG.get().expect("set by dispatch");
    // Log next to the verdict cache: `<cache dir>\avd.log`, the previous one kept as avd.log.old past 10 MB.
    let dir = av_core::Config::load(config).ok().and_then(|c| crate::cache_dir(&c));
    let file = dir.map(|d| d.join("avd.log")).and_then(|log| {
        if std::fs::metadata(&log).is_ok_and(|m| m.len() > LOG_ROTATE) {
            let _ = std::fs::rename(&log, log.with_extension("log.old"));
        }
        std::fs::OpenOptions::new().create(true).append(true).open(log).ok()
    });
    match file {
        Some(file) => crate::init_log(log::Level::Info, Box::new(file)),
        None => crate::init_log(log::Level::Info, Box::new(std::io::stderr())),
    }

    let (stop_tx, stop) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = match service_control_handler::register(NAME, handler) {
        Ok(status) => status,
        Err(e) => {
            log::error!("service control handler: {}", os(e));
            return;
        }
    };
    let report = |current_state, controls_accepted, exit_code| {
        let s = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        };
        if let Err(e) = status.set_service_status(s) {
            log::error!("service status: {}", os(e));
        }
    };

    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        ServiceExitCode::NO_ERROR,
    );
    log::info!("service started");
    let exit = match crate::realtime::run(config, stop) {
        Ok(()) => ServiceExitCode::NO_ERROR,
        Err(e) => {
            log::error!("{e}");
            ServiceExitCode::ServiceSpecific(2) // same as the CLI's error exit code
        }
    };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), exit);
}

/// Registers the service (LocalSystem, delayed auto-start, restart on failure) and starts it. Needs admin.
pub fn install(config: &Path) -> Result<(), String> {
    let config = std::path::absolute(config).map_err(|e| format!("{}: {e}", config.display()))?;
    if !config.is_file() {
        return Err(format!("{}: config file not found", config.display()));
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("service manager (run as admin): {}", os(e)))?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "avd antivirus".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().map_err(|e| e.to_string())?,
        launch_arguments: vec!["service".into(), "-c".into(), config.into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("create service: {}", os(e)))?;
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    let failure = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(30), restart(60)]),
    };
    service
        .set_description("Real-time file scanning (hash list + YARA). Runs alongside Defender.")
        .and_then(|_| service.set_delayed_auto_start(true))
        .and_then(|_| service.update_failure_actions(failure))
        // Also restart after a startup error (Stopped with a nonzero exit code), not only after a crash.
        .and_then(|_| service.set_failure_actions_on_non_crash_failures(true))
        .and_then(|_| service.start::<&str>(&[]))
        .map_err(|e| format!("configure/start service: {}", os(e)))?;
    log::info!("service {NAME} installed and started");
    Ok(())
}

/// Stops the service if it runs, then deletes it. Needs admin.
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("service manager (run as admin): {}", os(e)))?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = manager.open_service(NAME, access).map_err(|e| format!("open service: {}", os(e)))?;
    let stopped = || service.query_status().is_ok_and(|s| s.current_state == ServiceState::Stopped);
    if !stopped() {
        if let Err(e) = service.stop() {
            log::warn!("stop service: {}", os(e));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stopped() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete().map_err(|e| format!("delete service: {}", os(e)))?;
    log::info!("service {NAME} removed");
    Ok(())
}

/// windows-service's own message is just "IO error in winapi call"; the OS error underneath says what went wrong.
fn os(e: windows_service::Error) -> String {
    std::error::Error::source(&e).map_or_else(|| e.to_string(), |s| s.to_string())
}
