//! xdr-agent: the endpoint agent. Usage:
//!
//!   xdr-agent [--config /etc/xdr-agent/agent.yaml] [--state-dir DIR] [--enrollment-token TOKEN]
//!   xdr-agent -version
//!   xdr-agent maintenance [--token T | --password P]
//!
//! It replaced the Go agent in place: same binary path, unit, config, state
//! directory and identity, so a Go endpoint moves to it with a console
//! update and keeps its agent ID.

use std::path::PathBuf;

use anyhow::{Result, bail};
use tracing_subscriber::EnvFilter;
use xdr_core::config::Config;

fn main() -> Result<()> {
    let mut config = PathBuf::from("/etc/xdr-agent/agent.yaml");
    let mut state_dir: Option<PathBuf> = None;
    let mut token: Option<String> = None;
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(String::as_str) == Some("maintenance") {
        // The console's scripts call this before reinstalling or removing a
        // tamper-protected agent. Tamper protection is not ported yet, so
        // there is nothing to unlock but the Go agent's leftovers.
        xdr_linux::migrate::release_tamper();
        println!("tamper protection is not active; maintenance not needed");
        return Ok(());
    }
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-config" => config = args.next().map(PathBuf::from).unwrap_or(config),
            "--state-dir" => state_dir = args.next().map(PathBuf::from),
            "--enrollment-token" => token = args.next(),
            // Exactly the version: the update check compares this output.
            "--version" | "-version" => {
                println!("{}", xdr_core::VERSION);
                return Ok(());
            }
            other => bail!("unknown argument {other}"),
        }
    }
    let mut cfg = Config::load(&config)?;
    if let Some(d) = state_dir {
        cfg.state_dir = d;
    }
    if let Some(t) = token {
        cfg.enrollment_token = t;
    }
    tracing_subscriber::fmt()
        // Plain text under systemd/journald.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level)))
        .init();
    tracing::info!(version = xdr_core::VERSION, config = %config.display(), state_dir = %cfg.state_dir.display(),
        "xdr-agent starting");
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(async {
            let platform = xdr_linux::Linux::new(&cfg);
            xdr_core::agent::run(cfg, platform).await
        })
}
