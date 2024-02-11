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

use bytes::BytesMut;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
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
    pretty_env_logger::try_init_timed().ok();

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

            let server = Server::new(socket, h, BytesMut::with_capacity(4096));

            server.listen().await?;
        }
    }

    // RUN:
    // dig +short @127.0.0.1 -p5454 google.com

    Ok(())
}
