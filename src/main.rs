use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use narrowd::config::{self, AppConfig, SAMPLE_CONFIG};
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
}

fn init_logging(level: config::LogLevel) {
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level.to_level_filter());

    if std::env::var_os("RUST_LOG").is_some() {
        builder.parse_default_env();
    }

    builder.init();
}

#[cfg(target_os = "linux")]
fn enable_no_new_privs() -> Result<()> {
    // Prevent this process and its children from gaining privileges via exec.
    let result = unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_no_new_privs() -> Result<()> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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

    enable_no_new_privs()?;
    sshd::run(config).await
}
