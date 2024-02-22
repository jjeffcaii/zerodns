use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ahash::HashMap;
use async_trait::async_trait;
use deadpool::managed::{self, Metrics, RecycleError, RecycleResult};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use socket2::{Domain, Protocol, SockAddr, Type};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::protocol::{Codec, Message};
use crate::Result;

use super::Client;

#[derive(Clone)]
pub struct TcpClient {
    pool: Pool,
    timeout: Duration,
}

impl TcpClient {
    pub fn builder(addr: SocketAddr) -> TcpClientBuilder {
        TcpClientBuilder {
            addr,
            timeout: Duration::from_secs(5),
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
            None => bail!("no record resolved!"),
        }
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
}

impl TcpClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn build(self) -> Result<TcpClient> {
        let Self { addr, timeout } = self;
        let pool = get_pool(addr)?;

        Ok(TcpClient { pool, timeout })
    }
}

fn get_pool(addr: SocketAddr) -> Result<Pool> {
    static POOLS: Lazy<Arc<RwLock<HashMap<SocketAddr, Pool>>>> = Lazy::new(Default::default);

    let pools = POOLS.clone();

    {
        let r = pools.read();
        if let Some(existing) = r.get(&addr) {
            return Ok(Clone::clone(existing));
        }
    }

    let mut w = pools.write();
    if let Some(existing) = w.get(&addr) {
        return Ok(Clone::clone(existing));
    }

    let pool = Pool::builder(Manager::from(addr)).max_size(8).build()?;
    w.insert(addr, Clone::clone(&pool));

    Ok(pool)
}

type Pool = managed::Pool<Manager>;

struct Manager {
    addr: SocketAddr,
}

impl From<SocketAddr> for Manager {
    fn from(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

#[async_trait]
impl managed::Manager for Manager {
    type Type = (u32, TcpStream);
    type Error = anyhow::Error;

    async fn create(&self) -> std::result::Result<Self::Type, Self::Error> {
        let stream = {
            let addr = SockAddr::from(self.addr);

            let socket = socket2::Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_nodelay(true)?;
            socket.set_keepalive(true)?;

            socket.connect_timeout(&addr, Duration::from_secs(1))?;

            let stream: std::net::TcpStream = socket.into();
            stream.set_nonblocking(true)?;
            stream
        };

        let socket = TcpStream::from_std(stream)?;
        Ok((0, socket))
    }

    async fn recycle(&self, obj: &mut Self::Type, metrics: &Metrics) -> RecycleResult<Self::Error> {
        if metrics.created.elapsed() > Duration::from_secs(5 * 60) {
            return Err(RecycleError::Backend(anyhow!("exceed max lifetime!")));
        }

        if obj.0 != 0 {
            return Err(RecycleError::Backend(anyhow!("invalid connection!")));
        }

        if let Err(e) = validate(&obj.1) {
            return Err(RecycleError::Backend(e));
        }

        return Ok(());
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

#[cfg(test)]
mod tests {
    use crate::protocol::{Class, Flags, Kind};

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_request() -> Result<()> {
        init();

        let c = TcpClient::builder("199.85.127.10:53".parse()?).build()?;

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
