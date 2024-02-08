#![allow(dead_code)]
// #![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::from_over_into)]
#![allow(clippy::module_inception)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use slog::Drain;
use tokio::net::UdpSocket;

use server::Server;

use crate::handler::RuledHandler;

mod builtin;
mod client;
mod config;
mod filter;
mod handler;
mod protocol;
mod server;

pub type Result<T> = anyhow::Result<T>;

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

#[tokio::main]
async fn main() -> Result<()> {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(drain, slog::slog_o!("version" => env!("CARGO_PKG_VERSION")));

    let scope_guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init().unwrap();

    builtin::init();

    match Cli::parse().command {
        Commands::Run { config: path } => {
            let c = config::read_from_toml(path)?;

            let socket = UdpSocket::bind(&c.server.listen).await?;

            let mut rb = RuledHandler::builder();

            for (k, v) in c.filters.iter() {
                rb = rb.filter(k, v)?;
            }

            for next in c.rules.iter() {
                rb = rb.rule(next)?;
            }

            let h = rb.build();

            let server = Server::new(socket, h);

            server.run().await?;
        }
    }

    // RUN:
    // dig +short @127.0.0.1 -p5354 baidu.com

    drop(scope_guard);

    Ok(())
}
