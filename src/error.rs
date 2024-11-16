use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("unknown internal error")]
    Unknown,

    #[error("invalid configuration '{0}'")]
    InvalidConfig(Cow<'static, str>),

    #[error("invalid dns url '{0}'")]
    InvalidDNSUrl(String),

    #[error("operation timeout")]
    Timeout,

    #[error("cannot bind address {0}: {1}")]
    NetworkBindFailure(SocketAddr, io::Error),

    #[error("network failure: {0}")]
    NetworkFailure(io::Error),

    #[error("resolve returns nothing")]
    ResolveNothing,

    #[error(transparent)]
    Other(#[from] anyhow::Error), // source and Display delegate to anyhow::Error
}
