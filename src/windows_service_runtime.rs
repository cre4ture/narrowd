use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use log::{error, info};
use tokio::sync::oneshot;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use narrowd::config::AppConfig;
use narrowd::sshd;

use crate::logging;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const STARTUP_FAILURE_EXIT_CODE: u32 = 1;
const RUNTIME_FAILURE_EXIT_CODE: u32 = 2;

static SERVICE_LAUNCH: OnceLock<WindowsServiceLaunchOptions> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct WindowsServiceLaunchOptions {
    pub service_name: String,
    pub config_path: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
}

pub fn dispatch(options: WindowsServiceLaunchOptions) -> Result<()> {
    let service_name = options.service_name.clone();
    SERVICE_LAUNCH
        .set(options)
        .map_err(|_| anyhow!("windows service launch options were already initialized"))?;

    service_dispatcher::start(service_name.as_str(), ffi_service_main)
        .context("failed to start the Windows service dispatcher")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let _ = run_service();
}

fn run_service() -> Result<()> {
    let launch = SERVICE_LAUNCH
        .get()
        .cloned()
        .context("missing windows service launch options")?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
    let status_handle = Arc::new(Mutex::new(None));

    let event_shutdown_tx = Arc::clone(&shutdown_tx);
    let event_status_handle = Arc::clone(&status_handle);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = set_service_status(
                    &event_status_handle,
                    service_status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::NO_ERROR,
                        1,
                        Duration::from_secs(15),
                    ),
                );

                if let Some(tx) = event_shutdown_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }

                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let registered_handle =
        match service_control_handler::register(launch.service_name.as_str(), event_handler) {
            Ok(handle) => handle,
            Err(err) => {
                logging::append_bootstrap_error(
                    launch.log_file.as_deref(),
                    &format!(
                        "failed to register service control handler for {}: {err:#}",
                        launch.service_name
                    ),
                );
                return Err(err).context("failed to register the Windows service control handler");
            }
        };
    *status_handle.lock().unwrap() = Some(registered_handle);

    set_service_status(
        &status_handle,
        service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            1,
            Duration::from_secs(30),
        ),
    )?;

    let config = match AppConfig::load(launch.config_path.clone()) {
        Ok(config) => config,
        Err(err) => {
            logging::append_bootstrap_error(
                launch.log_file.as_deref(),
                &format!("failed to load config for {}: {err:#}", launch.service_name),
            );
            let _ = set_service_status(
                &status_handle,
                service_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(STARTUP_FAILURE_EXIT_CODE),
                    0,
                    Duration::default(),
                ),
            );
            return Err(err);
        }
    };

    if let Err(err) = logging::init(config.log_level, launch.log_file.clone()) {
        logging::append_bootstrap_error(
            launch.log_file.as_deref(),
            &format!(
                "failed to initialize logging for service {}: {err:#}",
                launch.service_name
            ),
        );
        let _ = set_service_status(
            &status_handle,
            service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(STARTUP_FAILURE_EXIT_CODE),
                0,
                Duration::default(),
            ),
        );
        return Err(err);
    }

    info!("service={} event=start", launch.service_name);

    set_service_status(
        &status_handle,
        service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::NO_ERROR,
            0,
            Duration::default(),
        ),
    )?;

    let service_name = launch.service_name.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create Tokio runtime for the Windows service")?;
    let run_result = runtime.block_on(async move {
        sshd::run_until_shutdown(config, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    match run_result {
        Ok(()) => {
            info!("service={} event=stop result=success", service_name);
            set_service_status(
                &status_handle,
                service_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::NO_ERROR,
                    0,
                    Duration::default(),
                ),
            )?;
            Ok(())
        }
        Err(err) => {
            error!(
                "service={} event=stop result=failure error={err:#}",
                service_name
            );
            let _ = set_service_status(
                &status_handle,
                service_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(RUNTIME_FAILURE_EXIT_CODE),
                    0,
                    Duration::default(),
                ),
            );
            Err(err)
        }
    }
}

fn set_service_status(
    handle: &Arc<Mutex<Option<windows_service::service_control_handler::ServiceStatusHandle>>>,
    status: ServiceStatus,
) -> Result<()> {
    handle
        .lock()
        .unwrap()
        .as_ref()
        .context("missing Windows service status handle")?
        .set_service_status(status)
        .context("failed to update the Windows service status")
}

fn service_status(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state,
        controls_accepted,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    }
}
