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

use slog::Drain;
use tokio::net::UdpSocket;

use crate::server::{FilteredHandler, Server};

mod builtin;
mod client;
mod config;
mod filter;
pub mod protocol;
pub mod server;

pub type Result<T> = anyhow::Result<T>;

#[tokio::main]
async fn main() -> Result<()> {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(drain, slog::slog_o!("version" => env!("CARGO_PKG_VERSION")));

    let scope_guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init().unwrap();

    builtin::init();

    let socket = UdpSocket::bind("127.0.0.1:5757").await?;

    let h = FilteredHandler::builder()
        .append_with("proxyby", &())
        .build()
        .unwrap();
    let server = Server::new(socket, h);

    server.run().await?;

    // RUN:
    // dig +short @127.0.0.1 -p5757 baidu.com

    drop(scope_guard);

    Ok(())
}
