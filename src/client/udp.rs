use futures::{SinkExt, StreamExt};
use hashbrown::HashMap;
use once_cell::sync::Lazy;
use socket2::{Domain, Protocol, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, OnceCell};
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::protocol::Message;
use crate::{Error as ZeroError, Result};

use super::Client;

static GOOGLE: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("8.8.8.8:53".parse().unwrap()).build());

static GOOGLE2: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("8.8.4.4:53".parse().unwrap()).build());

static CLOUDFLARE: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("1.1.1.1:53".parse().unwrap()).build());

static CLOUDFLARE2: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("1.0.0.1:53".parse().unwrap()).build());

static OPENDNS: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("208.67.222.222:53".parse().unwrap()).build());

static OPENDNS2: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("208.67.220.220:53".parse().unwrap()).build());

static ALIYUN: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("223.5.5.5:53".parse().unwrap()).build());

static ALIYUN2: Lazy<UdpClient> =
    Lazy::new(|| UdpClient::builder("223.6.6.6:53".parse().unwrap()).build());

#[derive(Debug, Clone)]
pub struct UdpClient {
    addr: SocketAddr,
    timeout: Duration,
}

impl UdpClient {
    pub fn google() -> Self {
        Clone::clone(&GOOGLE)
    }

    pub fn google2() -> Self {
        Clone::clone(&GOOGLE2)
    }

    pub fn cloudflare() -> Self {
        Clone::clone(&ALIYUN)
    }

    pub fn cloudflare2() -> Self {
        Clone::clone(&CLOUDFLARE2)
    }

    pub fn aliyun() -> Self {
        Clone::clone(&ALIYUN)
    }

    pub fn aliyun2() -> Self {
        Clone::clone(&ALIYUN2)
    }

    pub fn opendns() -> Self {
        Clone::clone(&OPENDNS)
    }

    pub fn opendns2() -> Self {
        Clone::clone(&OPENDNS2)
    }

    pub fn builder(addr: SocketAddr) -> UdpClientBuilder {
        UdpClientBuilder {
            inner: Self {
                addr,
                timeout: Duration::from_secs(3),
            },
        }
    }
}

static DEFAULT_MULTIPLEX_UDP_CLIENT: OnceCell<MultiplexUdpClient> = OnceCell::const_new();

#[inline]
async fn requester<'a>() -> Result<&'a MultiplexUdpClient> {
    DEFAULT_MULTIPLEX_UDP_CLIENT
        .get_or_try_init(MultiplexUdpClient::new)
        .await
}

type Handlers = Arc<Mutex<HashMap<(u16, SocketAddr), oneshot::Sender<Message>>>>;

struct MultiplexUdpClient {
    queue: mpsc::Sender<(Message, SocketAddr)>,
    handlers: Handlers,
}

impl MultiplexUdpClient {
    async fn new() -> Result<MultiplexUdpClient> {
        let socket = {
            let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            let source = "0.0.0.0:0".parse::<SocketAddr>()?;
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

        Ok(Self::start(socket).await)
    }

    async fn start(socket: UdpSocket) -> MultiplexUdpClient {
        let (mut sink, mut stream) = UdpFramed::new(socket, BytesCodec::default()).split();

        let handlers: Handlers = Default::default();

        // TODO: notify to stop

        let cloned_handlers = Clone::clone(&handlers);
        tokio::spawn(async move {
            while let Some(next) = stream.next().await {
                match next {
                    Ok((b, remote)) => {
                        let msg = Message::from(b);
                        let id = msg.id();
                        let handler = {
                            let mut w = cloned_handlers.lock().await;
                            w.remove(&(id, remote))
                        };

                        if let Some(tx) = handler {
                            tx.send(msg).ok();
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let (tx, mut rx) = mpsc::channel::<(Message, SocketAddr)>(1);
        tokio::spawn(async move {
            while let Some((req, tgt)) = rx.recv().await {
                let b = req.0.freeze();
                if let Err(e) = sink.send((b, tgt)).await {
                    error!("failed to send message: {}", e);
                }
            }
        });

        Self {
            queue: tx,
            handlers,
        }
    }

    async fn request(
        &self,
        req: Message,
        remote: SocketAddr,
        timeout: Duration,
    ) -> Result<Message> {
        let id = req.id();

        let (tx, rx) = oneshot::channel::<Message>();
        {
            let mut w = self.handlers.lock().await;
            w.insert((id, remote), tx);
        }

        let res: Result<Message> = async move {
            self.queue.send((req, remote)).await?;
            let res = tokio::time::timeout(timeout, rx).await??;
            Ok(res)
        }
        .await;

        // clean handler if enqueue failed
        if res.is_err() {
            self.handlers.lock().await.remove(&(id, remote));
        }

        res
    }
}

#[async_trait::async_trait]
impl Client for UdpClient {
    async fn request(&self, req: &Message) -> Result<Message> {
        let w = requester().await?;
        let res = w
            .request(Clone::clone(req), self.addr, self.timeout)
            .await?;
        Ok(res)
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

    pub fn build(self) -> UdpClient {
        self.inner
    }
}

#[cfg(test)]
mod tests {

    use crate::client::Client;
    use crate::protocol::{Class, Flags, Kind, Message, OpCode};

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_request() -> anyhow::Result<()> {
        init();

        for c in &[
            UdpClient::google(),
            UdpClient::cloudflare(),
            UdpClient::aliyun(),
        ] {
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
        }

        Ok(())
    }
}
