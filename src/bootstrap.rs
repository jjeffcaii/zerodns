use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Notify;

use crate::cache::InMemoryCache;
use crate::config::Config;
use crate::handler::RuledHandler;
use crate::server::{TcpServer, UdpServer};

pub async fn run(c: Config, closer: Arc<Notify>) -> anyhow::Result<()> {
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
                Some(Arc::new(InMemoryCache::builder().capacity(*size).build()))
            }
        }
    };

    let udp_server = {
        let socket = UdpSocket::bind(&c.server.listen).await?;

        UdpServer::new(
            socket,
            Clone::clone(&h),
            Clone::clone(&cs),
            Clone::clone(&closer),
        )
    };

    let tcp_server = {
        TcpServer::new(
            TcpListener::bind(&c.server.listen).await?,
            Clone::clone(&h),
            Clone::clone(&cs),
            Clone::clone(&closer),
        )
    };

    let (_first, _second) = tokio::join!(udp_server.listen(), tcp_server.listen());

    Ok(())
}
