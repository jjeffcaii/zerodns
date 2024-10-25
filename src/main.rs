#[macro_use]
extern crate log;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::sync::Notify;

#[derive(Parser)]
#[command(name = "ZeroDNS")]
#[command(author = "Jeffsky <jjeffcaii@outlook.com>")]
#[command(version = "0.1.0")]
#[command(about = "A modern, simple and fast DNS server.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a ZeroDNS server from a configuration TOML file
    Run {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Commands::Run { config: path } => {
            let c = zerodns::config::read_from_toml(path)?;

            match &c.logger {
                Some(lc) => zerodns::setup_logger(lc)?,
                None => {
                    let lc = zerodns::logger::Config::default();
                    zerodns::setup_logger(&lc)?;
                }
            }

            zerodns::setup();

            let closer = Arc::new(Notify::new());
            let stopped = Arc::new(Notify::new());

            {
                let closer = Clone::clone(&closer);
                let stopped = Clone::clone(&stopped);
                tokio::spawn(async move {
                    if let Err(e) = zerodns::bootstrap::run(c, closer).await {
                        error!("zerodns server is stopped: {:?}", e);
                    }
                    stopped.notify_one();
                });
            }

            tokio::signal::ctrl_c().await?;

            closer.notify_waiters();

            stopped.notified().await
        }
    }

    // RUN:
    // dig @127.0.0.1 -p5454 www.youtube.com

    Ok(())
}
