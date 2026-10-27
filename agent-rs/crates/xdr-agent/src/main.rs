//! xdr-agent-rs: the Rust endpoint agent. Usage:
//!
//!   xdr-agent-rs [--config /etc/xdr-agent/agent.yaml] [--state-dir DIR] [--enrollment-token TOKEN]
//!
//! It reads the Go agent's config file. Until it reaches feature parity it
//! runs beside the Go agent with its own state directory and enrollment, so
//! it shows up as a second endpoint in the console.

use std::path::PathBuf;

use anyhow::{Result, bail};
use tracing_subscriber::EnvFilter;
use xdr_core::config::Config;

fn main() -> Result<()> {
    let mut config = PathBuf::from("/etc/xdr-agent/agent.yaml");
    let mut state_dir: Option<PathBuf> = None;
    let mut token: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config = args.next().map(PathBuf::from).unwrap_or(config),
            "--state-dir" => state_dir = args.next().map(PathBuf::from),
            "--enrollment-token" => token = args.next(),
            "--version" => {
                println!("xdr-agent-rs {}", xdr_core::VERSION);
                return Ok(());
            }
            other => bail!("unknown argument {other}"),
        }
    }
    let mut cfg = Config::load(&config)?;
    // The Go agent's state directory holds its own identity; never share it.
    cfg.state_dir = state_dir.unwrap_or_else(|| "/var/lib/xdr-agent-rs".into());
    if let Some(t) = token {
        cfg.enrollment_token = t;
    }
    tracing_subscriber::fmt()
        // Plain text under systemd/journald.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level)))
        .init();
    tracing::info!(version = xdr_core::VERSION, config = %config.display(), state_dir = %cfg.state_dir.display(),
        "xdr-agent-rs starting");
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(xdr_core::agent::run(cfg, xdr_linux::Linux::default()))
}
