use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::cache::CacheStore;
use crate::handler::Handler;
use crate::protocol::Codec;
use crate::Result;

pub struct TcpServer<H, C> {
    h: H,
    listener: TcpListener,
    cache: Option<Arc<C>>,
    closer: Arc<Notify>,
}

impl<H, C> TcpServer<H, C> {
    pub fn new(listener: TcpListener, h: H, cache: Option<Arc<C>>, closer: Arc<Notify>) -> Self {
        Self {
            h,
            listener,
            cache,
            closer,
        }
    }
}

impl<H, C> TcpServer<H, C>
where
    H: Handler,
    C: CacheStore,
{
    pub async fn listen(self) -> Result<()> {
        let Self {
            h,
            listener,
            cache,
            closer,
        } = self;
        let h = Arc::new(h);

        info!("tcp dns server is listening on {}", listener.local_addr()?);

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, addr) = accept?;
                    let h = Clone::clone(&h);
                    let cache = Clone::clone(&cache);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle(stream, addr, h, cache).await {
                            error!("failed to handle tcp stream: {:?}", e);
                        }
                    });
                }
                () = closer.notified() => {
                    info!("close signal is received, tcp dns server is stopping...");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle(
        mut stream: TcpStream,
        addr: SocketAddr,
        handler: Arc<H>,
        cache: Option<Arc<C>>,
    ) -> Result<()> {
        let (r, w) = stream.split();
        let mut r = FramedRead::with_capacity(r, Codec, 4096);
        let mut w = FramedWrite::new(w, Codec);

        while let Some(next) = r.next().await {
            let mut req = next?;

            if let Some(cache) = cache.as_deref() {
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
                let id = req.id();
                req.set_id(0);
                cache.set(&req, &msg).await;
                req.set_id(id);
                debug!("set dns cache ok");
            }

            w.send(&msg).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::InMemoryCache;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::protocol::{Message, DNS};

    use super::*;

    #[derive(Clone)]
    struct MockHandler {
        cnt: Arc<AtomicU64>,
        resp: Message,
    }

    #[async_trait::async_trait]
    impl Handler for MockHandler {
        async fn handle(&self, req: &mut Message) -> Result<Option<Message>> {
            self.cnt.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Clone::clone(&self.resp)))
        }
    }

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_tcp_listen() -> anyhow::Result<()> {
        init();

        let req = {
            let raw = hex::decode(
                "f2500120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )
            .unwrap();
            Message::from(raw)
        };

        let res = {
            let raw = hex::decode("f2508180000100020000000105626169647503636f6d0000010001c00c00010001000000b70004279c420ac00c00010001000000b700046ef244420000290580000000000000").unwrap();
            Message::from(raw)
        };

        let cnts = Arc::new(AtomicU64::new(0));

        let h = MockHandler {
            cnt: Clone::clone(&cnts),
            resp: Clone::clone(&res),
        };

        let cs = Arc::new(InMemoryCache::builder().build());

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr().unwrap().port();
        let closer = Arc::new(Notify::new());

        let server = TcpServer::new(listener, h, Some(cs), Clone::clone(&closer));

        tokio::spawn(async move {
            server.listen().await.expect("server stopped");
        });

        let dns = DNS::from_str(&format!("tcp://127.0.0.1:{}", port))?;

        // no cache
        assert!(dns.request(&req).await.is_ok_and(|msg| &msg == &res));

        // use cache
        assert!(dns.request(&req).await.is_ok_and(|msg| &msg == &res));

        assert_eq!(
            1,
            cnts.load(Ordering::SeqCst),
            "should only call handler once!"
        );

        closer.notify_waiters();

        Ok(())
    }
}
