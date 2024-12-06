use super::Client;
use crate::misc::tls;
use crate::protocol::{Codec, Message, DEFAULT_DOT_PORT};
use crate::Result;

use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_util::codec::{FramedRead, FramedWrite};

static GOOGLE: Lazy<DoTClient> = Lazy::new(|| {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), DEFAULT_DOT_PORT);
    DoTClient::builder(addr)
        .sni("dns.google")
        .build()
        .expect("Cannot build Google DoT client!")
});

static CLOUDFLARE: Lazy<DoTClient> = Lazy::new(|| {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), DEFAULT_DOT_PORT);
    DoTClient::builder(addr)
        .sni("one.one.one.one")
        .build()
        .expect("Cannot build Cloudflare DoT client!")
});

static DNSPOD: Lazy<DoTClient> = Lazy::new(|| {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)), DEFAULT_DOT_PORT);
    DoTClient::builder(addr)
        .sni("dot.pub")
        .build()
        .expect("Cannot build DNSPod DoT client!")
});

static ALIYUN: Lazy<DoTClient> = Lazy::new(|| {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)), DEFAULT_DOT_PORT);
    DoTClient::builder(addr)
        .sni("dns.alidns.com")
        .build()
        .expect("Cannot build Aliyun DoT client!")
});

// https://www.rfc-editor.org/rfc/rfc7858.txt
#[derive(Clone)]
pub struct DoTClient {
    pool: tls::Pool,
    timeout: Duration,
}

impl DoTClient {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

    pub fn google() -> Self {
        Clone::clone(&GOOGLE)
    }

    pub fn dnspod() -> Self {
        Clone::clone(&DNSPOD)
    }

    pub fn cloudflare() -> Self {
        Clone::clone(&CLOUDFLARE)
    }

    pub fn aliyun() -> Self {
        Clone::clone(&ALIYUN)
    }

    pub fn builder(addr: SocketAddr) -> DoTClientBuilder {
        DoTClientBuilder {
            sni: None,
            addr,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    #[inline]
    async fn request_timeout(
        &self,
        req: &Message,
        socket: &mut TlsStream<TcpStream>,
    ) -> Result<Message> {
        tokio::time::timeout(self.timeout, self.request_timeout_(req, socket)).await?
    }

    #[inline]
    async fn request_timeout_(
        &self,
        req: &Message,
        socket: &mut TlsStream<TcpStream>,
    ) -> Result<Message> {
        let (r, w) = tokio::io::split(socket);

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

#[async_trait::async_trait]
impl Client for DoTClient {
    async fn request(&self, req: &Message) -> Result<Message> {
        // TODO: implement multiplexing
        let mut obj = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("cannot get tcp stream: {:?}", e))?;

        let res = self.request_timeout(req, &mut obj.1).await;

        if res.is_err() {
            obj.0 = 1;
            let _ = obj.1.shutdown().await;
        }

        res
    }
}

pub struct DoTClientBuilder {
    sni: Option<String>,
    addr: SocketAddr,
    timeout: Duration,
}

impl DoTClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn sni<A>(mut self, sni: A) -> Self
    where
        A: Into<String>,
    {
        self.sni.replace(sni.into());
        self
    }

    pub fn build(self) -> Result<DoTClient> {
        let Self { sni, addr, timeout } = self;

        let key = match sni {
            None => (Arc::new(addr.ip().to_string()), addr),
            Some(sni) => (Arc::new(sni), addr),
        };

        let pool = tls::get(key)?;
        Ok(DoTClient { pool, timeout })
    }
}

#[cfg(test)]
mod tests {
    use crate::client::dot::DoTClient;
    use crate::client::Client;
    use crate::protocol::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_dot_client() -> anyhow::Result<()> {
        init();

        // let c = DoTClient {
        //     sni: "one.one.one.one".to_string(),
        //     addr: "1.1.1.1:853".parse()?,
        //     timeout: None,
        // };

        let c = DoTClient::google();

        for _ in 0..3 {
            let req = Message::builder()
                .id(0x1234)
                .flags(Flags::builder().request().recursive_query(true).build())
                .question("www.youtube.com", Kind::A, Class::IN)
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
