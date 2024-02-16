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

use bytes::BytesMut;
use clap::{Parser, Subcommand};
use tokio::join;
use tokio::net::{TcpListener, UdpSocket};

use crate::handler::RuledHandler;
use crate::server::{TcpServer, UdpServer};

mod builtin;
mod cache;
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

            let cs = match &c.server.cache_size {
                None => None,
                Some(size) => {
                    if *size == 0 {
                        None
                    } else {
                        Some(cache::CacheStore::builder().capacity(*size).build())
                    }
                }
            };

            let udp_server = {
                let mut buffsize = c.server.buff_size.unwrap_or(4096);

                if buffsize < 1024 {
                    buffsize = 1024;
                }

                UdpServer::new(
                    socket,
                    Clone::clone(&h),
                    BytesMut::with_capacity(buffsize),
                    Clone::clone(&cs),
                )
            };

            let tcp_server = {
                let l = TcpListener::bind(&c.server.listen).await?;
                TcpServer::new(l, Clone::clone(&h), Clone::clone(&cs))
            };

            let (_first, _second) = join!(udp_server.listen(), tcp_server.listen(),);
        }
    }

    // RUN:
    // dig +short @127.0.0.1 -p5454 google.com

    Ok(())
}
