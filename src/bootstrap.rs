use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Type};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Notify;

use crate::cache::MemoryLoadingCache;
use crate::config::Config;
use crate::handler::RuledHandler;
use crate::server::{TcpServer, UdpServer};

pub async fn run(c: Config, closer: Arc<Notify>) -> anyhow::Result<()> {
    let addr = c.server.listen.parse::<SocketAddr>()?;

    // build rule handler
    let h = {
        let mut rb = RuledHandler::builder();

        for (k, v) in c.filters.iter() {
            rb = rb.filter(k, v)?;
        }

        for next in c.rules.iter() {
            rb = rb.rule(next)?;
        }

        rb.build()
    };

    let cs = match &c.global.cache_size {
        Some(size) if *size > 0 => Some(Arc::new(
            MemoryLoadingCache::builder().capacity(*size).build(),
        )),
        _ => None,
    };

    let udp_server = {
        let socket = {
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

            let bind = socket2::SockAddr::from(addr);
            socket.bind(&bind)?;

            use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
            let fd: RawFd = socket.into_raw_fd();
            let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            UdpSocket::from_std(socket)?
        };

        UdpServer::new(
            socket,
            Clone::clone(&h),
            Clone::clone(&cs),
            Clone::clone(&closer),
        )
    };

    let tcp_server = {
        let socket = {
            let addr = socket2::SockAddr::from(addr);
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

            socket
        };

        TcpServer::new(
            addr,
            TcpListener::from_std(socket.into())?,
            Clone::clone(&h),
            Clone::clone(&cs),
            Clone::clone(&closer),
        )
    };

    let (_first, _second) = tokio::join!(udp_server.listen(), tcp_server.listen());

    Ok(())
}
