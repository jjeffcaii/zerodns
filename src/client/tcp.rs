use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::misc::tcp;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::protocol::{Codec, Message};
use crate::Result;

use super::Client;

macro_rules! tcpv4 {
    ($name:ident,$a:expr,$b:expr,$c:expr,$d:expr) => {
        impl TcpClient {
            pub fn $name() -> Self {
                static TC: Lazy<TcpClient> = Lazy::new(|| {
                    let ip = IpAddr::V4(Ipv4Addr::new($a, $b, $c, $d));
                    TcpClient::builder(SocketAddr::new(ip, 53)).build().unwrap()
                });
                Clone::clone(&TC)
            }
        }
    };
    ($name:ident,$a:expr,$b:expr,$c:expr,$d:expr,$port:expr) => {
        impl TcpClient {
            pub fn $name() -> Self {
                static TC: Lazy<TcpClient> = Lazy::new(|| {
                    let ip = IpAddr::V4(Ipv4Addr::new($a, $b, $c, $d));
                    TcpClient::builder(SocketAddr::new(ip, $port))
                        .build()
                        .unwrap()
                });
                Clone::clone(&TC)
            }
        }
    };
}

tcpv4!(opendns, 208, 67, 222, 222, 443);
tcpv4!(google, 8, 8, 8, 8);
tcpv4!(aliyun, 223, 5, 5, 5);
tcpv4!(cloudflare, 1, 1, 1, 1);

#[derive(Clone)]
pub struct TcpClient {
    pool: tcp::Pool,
    timeout: Duration,
}

impl TcpClient {
    pub fn builder(addr: SocketAddr) -> TcpClientBuilder {
        TcpClientBuilder {
            addr,
            timeout: Duration::from_secs(5),
            source: None,
        }
    }

    async fn request_with_socket(&self, req: &Message, socket: &mut TcpStream) -> Result<Message> {
        tokio::time::timeout(self.timeout, self.request_with_socket_(req, socket)).await?
    }

    async fn request_with_socket_(&self, req: &Message, socket: &mut TcpStream) -> Result<Message> {
        let (r, w) = socket.split();

        let mut r = FramedRead::new(r, Codec);
        let mut w = FramedWrite::new(w, Codec);

        w.send(req).await?;
        w.flush().await?;

        match r.next().await {
            Some(next) => next,
            None => bail!(crate::Error::ResolveNothing),
        }
    }
}

impl Display for TcpClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let addr = self.pool.manager().key().0;
        if addr.port() == crate::DEFAULT_UDP_PORT {
            write!(f, "tcp://{}", addr.ip())?;
        } else {
            write!(f, "tcp://{}", addr)?;
        }
        Ok(())
    }
}

#[async_trait]
impl Client for TcpClient {
    async fn request(&self, req: &Message) -> Result<Message> {
        // TODO: implement multiplexing
        let mut obj = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("cannot get tcp stream: {:?}", e))?;

        let res = self.request_with_socket(req, &mut obj.1).await;

        if res.is_err() {
            obj.0 = 1;
            let _ = obj.1.shutdown().await;
        }

        res
    }
}

pub struct TcpClientBuilder {
    addr: SocketAddr,
    timeout: Duration,
    source: Option<SocketAddr>,
}

impl TcpClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn source(mut self, source: SocketAddr) -> Self {
        self.source.replace(source);
        self
    }

    pub fn build(self) -> Result<TcpClient> {
        let Self {
            addr,
            timeout,
            source,
        } = self;
        let pool = tcp::get((addr, source))?;

        Ok(TcpClient { pool, timeout })
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::*;

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_request() -> Result<()> {
        init();

        for c in [
            TcpClient::google(),
            TcpClient::opendns(),
            TcpClient::aliyun(),
            TcpClient::cloudflare(),
        ] {
            for question in ["www.youtube.com", "www.taobao.com", "x.com"] {
                info!("======= resolve {} from {} =======", question, &c);

                let req = Message::builder()
                    .id(0x1234)
                    .flags(Flags::builder().request().recursive_query(true).build())
                    .question(question, Kind::A, Class::IN)
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
        }

        Ok(())
    }
}
