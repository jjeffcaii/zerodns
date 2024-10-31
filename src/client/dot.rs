use super::Client;
use crate::protocol::{Codec, Message};
use crate::Result;

use ahash::HashMap;
use deadpool::managed;
use deadpool::managed::{Metrics, RecycleError, RecycleResult};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Clone)]
pub struct DoTClient {
    pool: Pool,
    timeout: Duration,
}

impl DoTClient {
    pub fn builder(addr: SocketAddr) -> DoTClientBuilder {
        DoTClientBuilder {
            sni: None,
            addr,
            timeout: Duration::from_secs(5),
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

        let pool = get_pool(key)?;
        Ok(DoTClient { pool, timeout })
    }
}

type Pool = managed::Pool<Manager>;

struct Manager {
    key: Key,
    lifetime: Duration,
}

#[async_trait::async_trait]
impl managed::Manager for Manager {
    type Type = (u32, TlsStream<TcpStream>);
    type Error = anyhow::Error;

    async fn create(&self) -> std::result::Result<Self::Type, Self::Error> {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let dnsname = ServerName::try_from(self.key.0.to_string())?;

        let stream = TcpStream::connect(self.key.1).await?;
        let stream = connector.connect(dnsname, stream).await?;

        Ok((0, stream))
    }

    async fn recycle(&self, obj: &mut Self::Type, metrics: &Metrics) -> RecycleResult<Self::Error> {
        if metrics.created.elapsed() > self.lifetime {
            return Err(RecycleError::Backend(anyhow!("exceed max lifetime!")));
        }

        if obj.0 != 0 {
            return Err(RecycleError::Backend(anyhow!("invalid connection!")));
        }

        if let Err(e) = validate(&obj.1) {
            return Err(RecycleError::Backend(e));
        }

        Ok(())
    }
}

#[inline]
fn validate(stream: &TlsStream<TcpStream>) -> Result<()> {
    let (c, _) = stream.get_ref();
    super::tcp::validate(c)
}

type Key = (Arc<String>, SocketAddr);

fn get_pool(key: Key) -> Result<Pool> {
    static POOLS: Lazy<Arc<RwLock<HashMap<Key, Pool>>>> = Lazy::new(Default::default);

    let pools = POOLS.clone();

    {
        let r = pools.read();
        if let Some(existing) = r.get(&key) {
            return Ok(Clone::clone(existing));
        }
    }

    let mut w = pools.write();
    if let Some(existing) = w.get(&key) {
        return Ok(Clone::clone(existing));
    }

    let mgr = Manager {
        key: Clone::clone(&key),
        lifetime: Duration::from_secs(60),
    };
    let pool = Pool::builder(mgr).max_size(8).build()?;
    w.insert(key, Clone::clone(&pool));

    Ok(pool)
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

        let c = DoTClient::builder("162.14.21.178:853".parse()?)
            .sni("dot.pub")
            .build()?;

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
