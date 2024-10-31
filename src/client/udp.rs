use futures::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::protocol::Message;
use crate::{Error as ZeroError, Result};

use super::Client;

#[derive(Debug, Clone)]
pub struct UdpClient {
    addr: SocketAddr,
    timeout: Duration,
    source: Option<SocketAddr>,
}

impl UdpClient {
    pub fn builder(addr: SocketAddr) -> UdpClientBuilder {
        UdpClientBuilder {
            inner: Self {
                addr,
                timeout: Duration::from_secs(3),
                source: None,
            },
        }
    }

    #[inline]
    async fn request_(&self, req: &Message) -> Result<Message> {
        let socket = {
            let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            let source = match self.source {
                Some(source) => {
                    socket.set_reuse_address(true)?;
                    socket.set_reuse_port(true)?;
                    source
                }
                None => "0.0.0.0:0".parse::<SocketAddr>()?,
            };
            let addr = socket2::SockAddr::from(source);

            socket
                .bind(&addr)
                .map_err(|e| ZeroError::NetworkBindFailure(source, e))?;

            socket.set_nonblocking(true)?;

            use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
            let fd: RawFd = socket.into_raw_fd();
            let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

            UdpSocket::from_std(socket)?
        };

        let mut framed = UdpFramed::new(socket, BytesCodec::default());

        let bb = req.clone().0.freeze();

        framed.send((bb, self.addr)).await?;

        match framed.next().await {
            Some(next) => {
                let (b, _) = next?;
                Ok(Message::from(b))
            }
            None => bail!(ZeroError::ResolveNothing),
        }
    }
}

#[async_trait::async_trait]
impl Client for UdpClient {
    async fn request(&self, req: &Message) -> Result<Message> {
        tokio::time::timeout(self.timeout, self.request_(req)).await?
    }
}

pub struct UdpClientBuilder {
    inner: UdpClient,
}

impl UdpClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner.timeout = timeout;
        self
    }

    pub fn source(mut self, source: SocketAddr) -> Self {
        self.inner.source.replace(source);
        self
    }

    pub fn build(self) -> UdpClient {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::client::Client;
    use crate::protocol::{Class, Flags, Kind, Message, OpCode};

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_request() -> anyhow::Result<()> {
        init();

        let c = UdpClient::builder("1.1.1.1:53".parse()?)
            .timeout(Duration::from_secs(5))
            .source("0.0.0.0:5354".parse::<SocketAddr>()?)
            .build();

        let req = Message::builder()
            .id(0x1234)
            .flags(
                Flags::builder()
                    .request()
                    .opcode(OpCode::StandardQuery)
                    .recursive_query(true)
                    .build(),
            )
            .question("www.google.com", Kind::HTTPS, Class::IN)
            .build()?;

        let res = c.request(&req).await;

        assert!(res.is_ok_and(|msg| {
            for next in msg.answers() {
                info!(
                    "{}.\t{}\t{:?}\t{:?}\t{}",
                    next.name(),
                    next.time_to_live(),
                    next.class(),
                    next.kind(),
                    next.rdata().unwrap()
                );
            }
            msg.answer_count() > 0
        }));

        Ok(())
    }
}
