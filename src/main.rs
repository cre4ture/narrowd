use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use narrowd::config::{self, AppConfig, SAMPLE_CONFIG};
use narrowd::executor;
use narrowd::sandbox;
use narrowd::sshd;

#[derive(Debug, Parser)]
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

    /// Internal executor process mode.
    #[arg(long, hide = true)]
    internal_executor: bool,

    /// Control fd inherited by the internal executor process.
    #[arg(long, hide = true)]
    control_fd: Option<i32>,

    /// Internal pre-auth sandbox probe mode.
    #[arg(long, hide = true)]
    internal_preauth_sandbox_probe: Option<PathBuf>,
}

fn init_logging(level: config::LogLevel) {
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level.to_level_filter());

    if std::env::var_os("RUST_LOG").is_some() {
        builder.parse_default_env();
    }

    builder.init();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.internal_executor {
        let control_fd = cli
            .control_fd
            .context("missing --control-fd for --internal-executor mode")?;
        return executor::run_from_control_fd(control_fd).await;
    }

    if let Some(probe_path) = cli.internal_preauth_sandbox_probe {
        print!("{}", sandbox::internal_preauth_probe(&probe_path)?);
        return Ok(());
    }

    if cli.print_sample_config {
        print!("{SAMPLE_CONFIG}");
        return Ok(());
    }

    let config = AppConfig::load(cli.config)?;
    init_logging(config.log_level);

    if cli.check_config {
        println!("config ok");
        return Ok(());
    }

    sshd::run(config).await
}
