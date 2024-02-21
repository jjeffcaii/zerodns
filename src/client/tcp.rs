use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use deadpool::managed::{self, Metrics, RecycleError, RecycleResult};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncWriteExt, Interest};
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
            timeout: Duration::from_secs(3),
        }
    }

    async fn request_with_socket(
        &self,
        req: &Message,
        socket: &mut TcpStream,
    ) -> Result<Option<Message>> {
        tokio::time::timeout(self.timeout, self.request_with_socket_(req, socket)).await?
    }

    async fn request_with_socket_(
        &self,
        req: &Message,
        socket: &mut TcpStream,
    ) -> Result<Option<Message>> {
        let (r, w) = socket.split();

        let mut r = FramedRead::new(r, Codec);
        let mut w = FramedWrite::new(w, Codec);

        w.send(req).await?;

        Ok(match r.next().await {
            Some(next) => Some(next?),
            None => None,
        })
    }
}

#[async_trait]
impl Client for TcpClient {
    async fn request(&self, req: &Message) -> Result<Option<Message>> {
        let mut socket = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("cannot get tcp stream: {:?}", e))?;

        let res = self.request_with_socket(req, &mut socket).await;

        if matches!(&res, Err(_) | Ok(None)) {
            let _ = socket.shutdown().await;
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
        let pool = Pool::builder(Manager::from(addr)).max_size(32).build()?;

        Ok(TcpClient { pool, timeout })
    }
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
    type Type = TcpStream;
    type Error = anyhow::Error;

    async fn create(&self) -> std::result::Result<Self::Type, Self::Error> {
        let socket = TcpStream::connect(self.addr).await?;
        Ok(socket)
    }

    async fn recycle(&self, obj: &mut Self::Type, metrics: &Metrics) -> RecycleResult<Self::Error> {
        if let Ok(ready) = obj.ready(Interest::WRITABLE | Interest::READABLE).await {
            if ready.is_writable() && ready.is_readable() {
                return Ok(());
            }
        }
        Err(RecycleError::Backend(anyhow!("invalid connection")))
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

        let c = TcpClient::builder("208.67.222.222:443".parse()?).build()?;

        let req = Message::builder()
            .id(0x1234)
            .flags(Flags::builder().request().recursive_query(true).build())
            .question("www.youtube.com", Kind::A, Class::IN)
            .build()?;
        let res = c.request(&req).await?;

        assert!(res.is_some_and(|msg| {
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
