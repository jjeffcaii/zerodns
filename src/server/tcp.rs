use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

use crate::cache::CacheStore;
use crate::handler::Handler;
use crate::protocol::Codec;
use crate::Result;
use tokio_util::codec::{FramedRead, FramedWrite};

pub struct TcpServer<H> {
    h: H,
    listener: TcpListener,
    cache: Option<CacheStore>,
}

impl<H> TcpServer<H> {
    pub fn new(listener: TcpListener, h: H, cache: Option<CacheStore>) -> Self {
        Self { h, listener, cache }
    }
}

impl<H> TcpServer<H>
where
    H: Handler,
{
    pub async fn listen(self) -> Result<()> {
        let Self { h, listener, cache } = self;
        let h = Arc::new(h);

        info!("tcp dns server is listening on {}", listener.local_addr()?);

        loop {
            let (stream, addr) = listener.accept().await?;

            let h = Clone::clone(&h);
            let cache = Clone::clone(&cache);
            tokio::spawn(async move {
                if let Err(e) = Self::handle(stream, addr, h, cache).await {
                    error!("failed to handle tcp stream: {:?}", e);
                }
            });
        }
    }

    async fn handle(
        mut stream: TcpStream,
        addr: SocketAddr,
        handler: Arc<H>,
        cache: Option<CacheStore>,
    ) -> Result<()> {
        let (r, w) = stream.split();
        let mut r = FramedRead::with_capacity(r, Codec, 4096);
        let mut w = FramedWrite::new(w, Codec);

        while let Some(next) = r.next().await {
            let mut req = next?;

            if let Some(cache) = &cache {
                let id = req.id();
                req.set_id(0);

                if let Some((expired_at, mut exist)) = cache.get(&req).await {
                    let ttl = expired_at - Instant::now();
                    if ttl > Duration::ZERO {
                        exist.set_id(id);

                        debug!("use cache: ttl={:?}", ttl);

                        w.send(&exist).await?;

                        return Ok(());
                    }
                }

                req.set_id(id);
            }

            let msg = handler
                .handle(&mut req)
                .await?
                .expect("no record resolved!");

            if let Some(cache) = &cache {
                cache.set(&req, &msg).await;
                debug!("set dns cache ok");
            }

            w.send(&msg).await?;
        }

        Ok(())
    }
}
