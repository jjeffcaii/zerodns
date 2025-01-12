use futures::StreamExt;
use hashbrown::HashMap;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use socket2::{Domain, Protocol, Type};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::protocol::Message;
use crate::{Error as ZeroError, Result};

use super::Client;

macro_rules! udpv4 {
    ($name:ident,$ip:expr) => {
        impl UdpClient {
            pub fn $name() -> Self {
                static UC: Lazy<UdpClient> = Lazy::new(|| {
                    let ip = $ip.parse::<IpAddr>().unwrap();
                    UdpClient::builder(SocketAddr::new(ip, 53)).build()
                });
                Clone::clone(&UC)
            }
        }
    };
    ($name:ident,$ip1:expr,$ip2:expr) => {
        impl UdpClient {
            pub fn $name() -> Self {
                static UC: Lazy<[UdpClient; 2]> = Lazy::new(|| {
                    let ip1 = $ip1.parse::<IpAddr>().unwrap();
                    let ip2 = $ip2.parse::<IpAddr>().unwrap();
                    [
                        UdpClient::builder(SocketAddr::new(ip1, 53)).build(),
                        UdpClient::builder(SocketAddr::new(ip2, 53)).build(),
                    ]
                });

                static IDX: Lazy<AtomicUsize> = Lazy::new(|| AtomicUsize::new(0));
                let i = IDX.fetch_add(1, Ordering::Relaxed) & UC.len();
                Clone::clone(&UC[i])
            }
        }
    };
}

udpv4!(local, "127.0.0.1");
udpv4!(google, "8.8.8.8", "8.8.4.4");
udpv4!(cloudflare, "1.1.1.1", "1.0.0.1");
udpv4!(opendns, "208.67.222.222", "208.67.220.220");
udpv4!(aliyun, "223.5.5.5", "223.6.6.6");
udpv4!(quad9, "9.9.9.9", "149.112.112.112");

#[derive(Debug, Clone)]
pub struct UdpClient {
    addr: SocketAddr,
    timeout: Duration,
}

impl Display for UdpClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.addr.port() == crate::DEFAULT_UDP_PORT {
            write!(f, "udp://{}", &self.addr.ip())?;
        } else {
            write!(f, "udp://{}", &self.addr)?;
        }

        Ok(())
    }
}

impl UdpClient {
    pub fn builder(addr: SocketAddr) -> UdpClientBuilder {
        UdpClientBuilder {
            inner: Self {
                addr,
                timeout: Duration::from_secs(15),
            },
        }
    }
}

static DEFAULT_MULTIPLEX_UDP_CLIENTS: Lazy<RwLock<HashMap<SocketAddr, MultiplexUdpClient>>> =
    Lazy::new(Default::default);

#[inline]
async fn requester(addr: SocketAddr) -> Result<MultiplexUdpClient> {
    {
        let r = DEFAULT_MULTIPLEX_UDP_CLIENTS.read().await;
        if let Some(v) = r.get(&addr) {
            return Ok(Clone::clone(v));
        }
    }

    let mut w = DEFAULT_MULTIPLEX_UDP_CLIENTS.write().await;

    if let Some(v) = w.get(&addr) {
        return Ok(Clone::clone(v));
    }

    let c = MultiplexUdpClient::new(addr).await?;
    w.insert(addr, Clone::clone(&c));

    Ok(c)
}

type Handlers = Arc<Mutex<HashMap<u16, oneshot::Sender<Message>>>>;

#[derive(Clone)]
struct MultiplexUdpClient {
    queue: mpsc::Sender<Message>,
    handlers: Handlers,
    seq: Arc<AtomicU16>,
}

impl MultiplexUdpClient {
    async fn new(nameserver: SocketAddr) -> Result<MultiplexUdpClient> {
        let socket = {
            let (socket, source) = match &nameserver {
                SocketAddr::V4(_) => (
                    socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                ),
                SocketAddr::V6(_) => (
                    socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?,
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                ),
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

        Ok(Self::start(socket, nameserver).await)
    }

    async fn start(local: UdpSocket, remote: SocketAddr) -> MultiplexUdpClient {
        let handlers: Handlers = Default::default();

        let socket = Arc::new(local);

        // TODO: notify to stop
        // read worker
        {
            let socket = Clone::clone(&socket);
            let handlers = Clone::clone(&handlers);
            tokio::spawn(async move {
                let mut stream = UdpFramed::new(Clone::clone(&socket), BytesCodec::new());
                while let Some(next) = stream.next().await {
                    if let Ok((b, remote)) = next {
                        let msg = Message::from(b);
                        let id = msg.id();
                        let handler = {
                            let mut w = handlers.lock().await;
                            w.remove(&id)
                        };

                        if let Some(tx) = handler {
                            tx.send(msg).ok();
                        }
                    }
                }
                info!("udp stream {} is eof", socket.peer_addr().unwrap());
            });
        }

        // write worker
        let (tx, mut rx) = mpsc::channel::<Message>(1);

        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let id = req.id();
                let b = req.0.freeze();
                if let Err(e) = socket.send_to(&b, &remote).await {
                    error!(
                        "failed to send message-0x{:04x}({}B) to {}: {}",
                        id,
                        b.len(),
                        &remote,
                        e
                    );
                    continue;
                }
            }
        });

        let seq = {
            let mut rng = thread_rng();
            rng.gen_range(1..u16::MAX)
        };

        Self {
            queue: tx,
            handlers,
            seq: Arc::new(AtomicU16::new(seq)),
        }
    }

    #[inline]
    async fn next_seq(&self) -> u16 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    async fn request(&self, req: &Message, timeout: Duration) -> Result<Message> {
        let origin_id = req.id();

        let id = {
            let mut id = 0u16;
            loop {
                id = self.next_seq().await;
                if id != 0 {
                    break;
                }
            }
            id
        };

        let (tx, rx) = oneshot::channel::<Message>();
        {
            let mut w = self.handlers.lock().await;
            w.insert(id, tx);
        }

        let mut res: Result<Message> = {
            let req = {
                let mut req = Clone::clone(req);
                req.set_id(id);
                req
            };

            async move {
                self.queue.send(req).await?;
                let res = tokio::time::timeout(timeout, rx).await??;
                Ok(res)
            }
            .await
        };

        // clean handler if enqueue failed
        match &mut res {
            Ok(v) => {
                // reset origin id
                v.set_id(origin_id);
            }
            Err(_) => {
                self.handlers.lock().await.remove(&id);
            }
        }

        res
    }
}

#[async_trait::async_trait]
impl Client for UdpClient {
    async fn request(&self, req: &Message) -> Result<Message> {
        let w = requester(self.addr).await?;
        let res = w.request(req, self.timeout).await?;
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
    use tokio::task::JoinSet;

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    #[ignore]
    async fn test_weird() -> anyhow::Result<()> {
        init();

        let req = {
            let s = "a4e5010000010000000000000a68747470733a2f2f696d0864696e6774616c6b03636f6d0000010001";
            let b = hex::decode(s)?;
            Message::from(b)
        };

        // let req = Message::builder()
        //     .flags(Flags::request())
        //     .question("https://foobar.com", Kind::A, Class::IN)
        //     .build();

        let c = UdpClient::builder("127.0.0.1:5454".parse().unwrap()).build();
        let res = c.request(&req).await?;

        // let res = UdpClient::google().request(&req).await?;

        info!("questions: {}", res.question_count());
        info!("answers: {}", res.answer_count());
        info!("additional: {}", res.additional_count());
        info!("authority: {}", res.authority_count());

        for next in res.answers() {
            info!(
                "{}.\t{}\t{:?}\t{:?}\t{}",
                next.name(),
                next.time_to_live(),
                next.class(),
                next.kind(),
                next.rdata().unwrap()
            );
        }

        Ok(())
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

    #[tokio::test]
    #[ignore]
    async fn test_concurrency() -> anyhow::Result<()> {
        init();

        let mut joins = JoinSet::new();

        for i in 0..64 {
            joins.spawn(async move {
                let req = Message::builder()
                    .id(i)
                    .flags(
                        Flags::builder()
                            .request()
                            .opcode(OpCode::StandardQuery)
                            .recursive_query(true)
                            .build(),
                    )
                    .question("t.cn", Kind::A, Class::IN)
                    .build()
                    .unwrap();

                for j in 0..18 {
                    let c = match i % 3 {
                        0 => UdpClient::aliyun(),
                        1 => UdpClient::quad9(),
                        2 => UdpClient::google(),
                        _ => UdpClient::aliyun(),
                    };

                    match c.request(&req).await {
                        Ok(msg) => {
                            for next in msg.answers() {
                                info!(
                                    "#{}-{}\t{}.\t{}\t{:?}\t{:?}\t{}",
                                    i,
                                    j,
                                    next.name(),
                                    next.time_to_live(),
                                    next.class(),
                                    next.kind(),
                                    next.rdata().unwrap()
                                );
                            }
                        }
                        Err(e) => {
                            error!("#{}-{}\trequest failed: {}", i, j, e);
                        }
                    }
                }
            });
        }

        while let Some(next) = joins.join_next().await {}

        Ok(())
    }
}
