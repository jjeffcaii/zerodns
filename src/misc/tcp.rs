use crate::Result;
use deadpool::managed::{self, Metrics, RecycleError, RecycleResult};
use hashbrown::HashMap;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use socket2::{Domain, Protocol, SockAddr, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

pub(crate) type Key = (SocketAddr, Option<SocketAddr>);

pub(crate) fn get(key: Key) -> Result<Pool> {
    static POOLS: Lazy<Arc<RwLock<HashMap<(SocketAddr, Option<SocketAddr>), Pool>>>> =
        Lazy::new(Default::default);

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
        key,
        lifetime: Duration::from_secs(60),
    };
    let pool = Pool::builder(mgr).max_size(8).build()?;
    w.insert(key, Clone::clone(&pool));

    Ok(pool)
}

pub(crate) type Pool = managed::Pool<Manager>;

pub(crate) struct Manager {
    key: Key,
    lifetime: Duration,
}

impl Manager {
    pub fn key(&self) -> Key {
        self.key
    }
}

#[async_trait::async_trait]
impl managed::Manager for Manager {
    type Type = (u32, TcpStream);
    type Error = anyhow::Error;

    async fn create(&self) -> std::result::Result<Self::Type, Self::Error> {
        let stream: std::net::TcpStream = {
            let dst = SockAddr::from(self.key.0);

            let socket = socket2::Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_nodelay(true)?;
            socket.set_keepalive(true)?;

            if let Some(source) = self.key.1 {
                socket.set_reuse_address(true)?;
                socket.set_reuse_port(true)?;
                let src = SockAddr::from(source);
                socket
                    .bind(&src)
                    .map_err(|e| crate::Error::NetworkBindFailure(source, e))?;
            }

            socket.connect(&dst)?;

            socket.set_nonblocking(true)?;

            socket.into()
        };

        let socket = TcpStream::from_std(stream)?;
        Ok((0, socket))
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
pub(crate) fn validate(conn: &TcpStream) -> Result<()> {
    use std::io::ErrorKind::WouldBlock;
    let mut b = [0u8; 0];
    // check if connection is readable
    match conn.try_read(&mut b) {
        Ok(n) => {
            if n == 0 {
                debug!("connection {:?} is closed", conn.local_addr());
            } else {
                warn!(
                    "invalid connection {:?}: should not read any bytes",
                    conn.local_addr()
                );
            }
            bail!("invalid connection")
        }
        Err(ref e) if e.kind() == WouldBlock => {
            // check if connection is writeable
            if let Err(e) = conn.try_write(&b[..]) {
                if e.kind() != WouldBlock {
                    debug!(
                        "connection {:?} is not writeable: {:?}",
                        conn.local_addr(),
                        e
                    );
                    bail!("invalid connection");
                }
            }
            Ok(())
        }
        Err(e) => {
            error!("broken connection {:?}: {:?}", conn.local_addr(), e);
            bail!("invalid connection");
        }
    }
}
