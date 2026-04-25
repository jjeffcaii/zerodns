pub(crate) use chinadns::ChinaDNSFilterFactory;
pub(crate) use hosts::HostsFilterFactory;
pub(crate) use lua::LuaFilterFactory;
#[cfg(test)]
pub(crate) use noop::NoopFilter;
pub(crate) use noop::NoopFilterFactory;
pub use proto::{Context, ContextFlags, Filter};
pub(crate) use proxyby::ProxyByFilterFactory;
pub(crate) use registry::FilterFactoryExt;
pub(crate) use registry::load;
pub use registry::{FilterFactory, Options, register};

pub(crate) use proto::handle_next;

mod chinadns;
mod hosts;
mod lua;
mod misc;
mod noop;
mod proto;
mod proxyby;
mod registry;
