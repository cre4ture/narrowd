use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use narrowd::config::{AppConfig, SAMPLE_CONFIG};
#[cfg(unix)]
use narrowd::executor;
use narrowd::logging;
#[cfg(unix)]
use narrowd::sandbox;
use narrowd::sshd;

#[cfg(windows)]
mod windows_service_runtime;

#[derive(Clone, Debug, Parser)]
#[command(name = "narrowd", version, about = "Single-user Rust SSH daemon")]
struct Cli {
    /// Path to a narrowd config file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Validate the config file and exit.
    #[arg(long)]
    check_config: bool,

    /// Print a sample config and exit.
    #[arg(long)]
    print_sample_config: bool,

    /// Append application logs to a rotating log file.
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Run under the Windows Service Control Manager.
    #[cfg(windows)]
    #[arg(long, hide = true)]
    run_windows_service: bool,

    /// Windows service name registered with the Service Control Manager.
    #[cfg(windows)]
    #[arg(long, hide = true, requires = "run_windows_service")]
    service_name: Option<String>,

    /// Internal executor process mode (Unix only).
    #[cfg(unix)]
    #[arg(long, hide = true)]
    internal_executor: bool,

    /// Control fd inherited by the internal executor process (Unix only).
    #[cfg(unix)]
    #[arg(long, hide = true)]
    control_fd: Option<i32>,

    /// Internal pre-auth sandbox probe mode (Unix only).
    #[cfg(unix)]
    #[arg(long, hide = true)]
    internal_preauth_sandbox_probe: Option<PathBuf>,

    /// Internal probe for the pre-auth sandbox default-deny seccomp policy (Unix only).
    #[cfg(unix)]
    #[arg(long, hide = true)]
    internal_preauth_default_deny_probe: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(windows)]
    if cli.run_windows_service {
        let service_name = cli
            .service_name
            .clone()
            .context("missing --service-name for --run-windows-service mode")?;
        return windows_service_runtime::dispatch(
            windows_service_runtime::WindowsServiceLaunchOptions {
                service_name,
                config_path: cli.config.clone(),
                log_file: cli.log_file.clone(),
            },
        );
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create Tokio runtime")?;
    runtime.block_on(run_cli(cli))
}

async fn run_cli(cli: Cli) -> Result<()> {
    #[cfg(unix)]
    if cli.internal_executor {
        let control_fd = cli
            .control_fd
            .context("missing --control-fd for --internal-executor mode")?;
        return executor::run_from_control_fd(control_fd).await;
    }

    #[cfg(unix)]
    if let Some(probe_path) = cli.internal_preauth_sandbox_probe {
        print!("{}", sandbox::internal_preauth_probe(&probe_path)?);
        return Ok(());
    }

    #[cfg(unix)]
    if let Some(probe_path) = cli.internal_preauth_default_deny_probe {
        return sandbox::internal_preauth_default_deny_probe(&probe_path);
    }

    if cli.print_sample_config {
        print!("{SAMPLE_CONFIG}");
        return Ok(());
    }

    let config = AppConfig::load(cli.config)?;
    logging::init(config.log_level, cli.log_file)?;

    if cli.check_config {
        println!("config ok");
        return Ok(());
    }

    sshd::run(config).await
}
