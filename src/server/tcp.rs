use std::net::SocketAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::cache::LoadingCache;
use crate::handler::Handler;
use crate::protocol::Codec;
use crate::Result;

pub struct TcpServer<H, C> {
    h: H,
    listener: TcpListener,
    cache: Option<Arc<C>>,
    closer: Arc<Notify>,
    addr: SocketAddr,
}

impl<H, C> TcpServer<H, C> {
    pub fn new(
        addr: SocketAddr,
        listener: TcpListener,
        h: H,
        cache: Option<Arc<C>>,
        closer: Arc<Notify>,
    ) -> Self {
        Self {
            h,
            addr,
            listener,
            cache,
            closer,
        }
    }
}

impl<H, C> TcpServer<H, C>
where
    H: Handler,
    C: LoadingCache,
{
    pub async fn listen(self) -> Result<()> {
        let Self {
            addr,
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
            let req = next?;
            let handler = Clone::clone(&handler);
            let cache = Clone::clone(&cache);
            let (res, cached) = super::helper::handle(addr, req, handler, cache).await;

            if res.answer_count() > 0 {
                for next in res.answers() {
                    if let Ok(rdata) = next.rdata() {
                        if cached {
                            info!(
                                "0x{:04x} <- {}.\t{}\t{:?}\t{:?}\t{}\t<CACHE>",
                                res.id(),
                                next.name(),
                                next.time_to_live(),
                                next.class(),
                                next.kind(),
                                rdata,
                            );
                        } else {
                            info!(
                                "0x{:04x} <- {}.\t{}\t{:?}\t{:?}\t{}",
                                res.id(),
                                next.name(),
                                next.time_to_live(),
                                next.class(),
                                next.kind(),
                                rdata,
                            );
                        }
                    }
                }
            }

            w.send(&res).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::MemoryLoadingCache;
    use crate::client::request;
    use crate::filter::Context;
    use crate::protocol::{Message, DNS};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[derive(Clone)]
    struct MockHandler {
        cnt: Arc<AtomicU64>,
        resp: Message,
    }

    #[async_trait::async_trait]
    impl Handler for MockHandler {
        async fn handle(&self, _ctx: &mut Context, _req: &mut Message) -> Result<Option<Message>> {
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
            )?;
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

        let cs = Arc::new(MemoryLoadingCache::builder().build());
        let addr = "127.0.0.1:0".parse::<SocketAddr>()?;

        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();
        let closer = Arc::new(Notify::new());

        let server = TcpServer::new(addr, listener, h, Some(cs), Clone::clone(&closer));

        tokio::spawn(async move {
            server.listen().await.expect("server stopped");
        });

        let dns = DNS::from_str(&format!("tcp://127.0.0.1:{}", port))?;

        // no cache
        assert!(request(&dns, &req, Duration::from_secs(3))
            .await
            .is_ok_and(|msg| &msg == &res));

        // use cache
        assert!(request(&dns, &req, Duration::from_secs(3))
            .await
            .is_ok_and(|msg| &msg == &res));

        assert_eq!(
            1,
            cnts.load(Ordering::SeqCst),
            "should only call handler once!"
        );

        closer.notify_waiters();

        Ok(())
    }
}
