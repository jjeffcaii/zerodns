use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Type};
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
        let addr = socket2::SockAddr::from(c.server.listen.parse::<SocketAddr>()?);
        let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // SO_REUSEADDR+SO_REUSEPORT
        if let Err(e) = socket.set_reuse_address(true) {
            warn!("failed to set SO_REUSEADDR for {:?}: {:?}", &socket, e);
        }
        if let Err(e) = socket.set_reuse_port(true) {
            warn!("failed to set SO_REUSEPORT for {:?}: {:?}", &socket, e);
        }

        // enable balance for freebsd
        cfg_if! {
            if #[cfg(target_os="freebsd")]  {
                // SO_REUSEPORT_LB
                if let Err(e) = socket.set_reuse_port_lb(true) {
                    warn!("failed to set SO_REUSEPORT for {:?}: {:?}", &socket, e);
                }
            }
        }

        socket.set_recv_buffer_size(4096)?;
        socket.set_send_buffer_size(4096)?;
        socket.set_nonblocking(true)?;

        socket.bind(&addr)?;

        let socket = {
            use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
            let fd: RawFd = socket.into_raw_fd();
            let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            UdpSocket::from_std(socket)
        }?;

        UdpServer::new(
            socket,
            Clone::clone(&h),
            Clone::clone(&cs),
            Clone::clone(&closer),
        )
    };

    let tcp_server = {
        let addr = socket2::SockAddr::from(c.server.listen.parse::<SocketAddr>()?);
        let socket = socket2::Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

        // SO_REUSEADDR+SO_REUSEPORT
        if let Err(e) = socket.set_reuse_address(true) {
            warn!("failed to set SO_REUSEADDR for {:?}: {:?}", &socket, e);
        }
        if let Err(e) = socket.set_reuse_port(true) {
            warn!("failed to set SO_REUSEPORT for {:?}: {:?}", &socket, e);
        }

        socket.set_recv_buffer_size(4096)?;
        socket.set_send_buffer_size(4096)?;
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;

        socket.bind(&addr)?;

        socket.listen(65535)?;

        TcpServer::new(
            TcpListener::from_std(socket.into())?,
            Clone::clone(&h),
            Clone::clone(&cs),
            Clone::clone(&closer),
        )
    };

    let (_first, _second) = tokio::join!(udp_server.listen(), tcp_server.listen());

    Ok(())
}
