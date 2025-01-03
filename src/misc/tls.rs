use crate::Result;
use deadpool::managed;
use deadpool::managed::{Metrics, RecycleError, RecycleResult};
use futures::{future, FutureExt};
use hashbrown::HashMap;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rustls::pki_types::ServerName;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

pub(crate) static DEFAULT_TLS_CLIENT_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let c = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(c)
});

pub(crate) type Pool = managed::Pool<Manager>;

pub(crate) type Key = (Arc<String>, SocketAddr);

pub(crate) struct Manager {
    key: Key,
    lifetime: Duration,
}

impl Manager {
    #[inline]
    async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let connector = TlsConnector::from(Clone::clone(&*DEFAULT_TLS_CLIENT_CONFIG));
        let dnsname = ServerName::try_from(self.key.0.to_string())?;
        let stream = TcpStream::connect(self.key.1).await?;
        let stream = connector.connect(dnsname, stream).await?;
        Ok(stream)
    }
}

#[async_trait::async_trait]
impl managed::Manager for Manager {
    type Type = (u32, TlsStream<TcpStream>);
    type Error = anyhow::Error;

    fn create(&self) -> impl Future<Output = std::result::Result<Self::Type, Self::Error>> + Send {
        self.connect().map(|it| it.map(|it| (0, it)))
    }

    fn recycle(
        &self,
        obj: &mut Self::Type,
        metrics: &Metrics,
    ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
        if metrics.created.elapsed() > self.lifetime {
            return future::err(RecycleError::Backend(anyhow!("exceed max lifetime!")));
        }

        if obj.0 != 0 {
            return future::err(RecycleError::Backend(anyhow!("invalid connection!")));
        }

        if let Err(e) = validate(&obj.1) {
            return future::err(RecycleError::Backend(e));
        }

        future::ok(())
    }
}

#[inline]
fn validate(stream: &TlsStream<TcpStream>) -> Result<()> {
    let (c, _) = stream.get_ref();
    super::tcp::validate(c)
}

pub(crate) fn get(key: Key) -> Result<Pool> {
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
