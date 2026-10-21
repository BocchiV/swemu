//! swemu — single-process SoulWorker GB private server.
//!
//! Every client->server frame is logged (decoded + hexdump) to `log/packets.log`
//! so each protocol step can be verified against real traffic. Handlers only
//! implement packets whose layout is backed by evidence (decompiled client
//! reader/writer); everything else is logged as UNHANDLED.

mod codec;
mod config;
mod db;
mod gamedata;
mod handlers;
mod http;
mod maze;
mod proto;
mod session;
mod vfun;
mod wire;

use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Arc::new(config::Config::load_or_default("swemu.json")?);
    std::fs::create_dir_all(&cfg.log_dir)?;
    let file_appender = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::path::Path::new(&cfg.log_dir).join("server.log"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::sync::Mutex::new(Tee(file_appender)))
        .with_ansi(false)
        .init();

    info!(?cfg, "swemu starting");
    let state = Arc::new(session::Shared::new(cfg.clone())?);

    for (role, port) in [(session::Role::Login, cfg.login_port), (session::Role::Game, cfg.game_port)] {
        let listener = TcpListener::bind((cfg.bind_ip.as_str(), port)).await?;
        info!(?role, port, "listening");
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((sock, peer)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = session::run(state, role, sock, peer).await {
                                error!(?role, %peer, "session ended with error: {e:#}");
                            }
                        });
                    }
                    Err(e) => error!("accept failed: {e}"),
                }
            }
        });
    }

    if cfg.vfun_port != 0 {
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = http::serve(st).await {
                error!("vfun http stub failed: {e:#}");
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}

/// Write log lines to both stdout and the log file.
struct Tee(std::fs::File);
impl std::io::Write for Tee {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stdout().write_all(buf);
        self.0.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
