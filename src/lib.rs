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
extern crate cfg_if;
#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;

/// cached string
pub mod cachestr {
    include!(concat!(env!("OUT_DIR"), "/cachestr.rs"));
}

pub mod bootstrap;
pub(crate) mod builtin;
pub(crate) mod cache;
pub mod client;
pub mod config;
pub(crate) mod error;
pub mod filter;
pub mod handler;
pub mod logger;
pub(crate) mod misc;
pub mod protocol;
pub mod server;

pub(crate) use error::Error;

pub type Result<T> = anyhow::Result<T>;

pub use builtin::{setup, setup_logger};

pub const DEFAULT_UDP_PORT: u16 = 53;
