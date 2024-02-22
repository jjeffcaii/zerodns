use std::sync::Arc;

use futures::StreamExt;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::cache::{CacheStore, CacheStoreExt};
use crate::handler::Handler;
use crate::protocol::Message;
use crate::Result;

pub struct UdpServer<H, C> {
    h: H,
    socket: UdpSocket,
    cache: Option<Arc<C>>,
    closer: Arc<Notify>,
}

impl<H, C> UdpServer<H, C> {
    pub fn new(socket: UdpSocket, handler: H, cache: Option<Arc<C>>, closer: Arc<Notify>) -> Self {
        Self {
            h: handler,
            socket,
            cache,
            closer,
        }
    }
}

impl<H, C> UdpServer<H, C>
where
    H: Handler,
    C: CacheStore,
{
    #[inline]
    async fn handle(mut req: Message, h: Arc<H>, cache: Option<Arc<C>>) -> Result<Message> {
        if let Some(cache) = cache.as_deref() {
            let id = req.id();
            req.set_id(0);
            let cached = cache.get_fixed(&req).await;
            req.set_id(id);

            if let Some(mut exist) = cached {
                exist.set_id(id);
                debug!("use dns cache");
                return Ok(exist);
            }
        }

        let res = h.handle(&mut req).await?;

        let msg = res.expect("no record resolved");

        if let Some(cache) = &cache {
            let id = req.id();
            req.set_id(0);
            cache.set(&req, &msg).await;
            req.set_id(id);

            debug!("set dns cache ok");
        }

        Ok(msg)
    }

    pub async fn listen(self) -> Result<()> {
        let Self {
            h,
            socket,
            cache,
            closer,
        } = self;

        info!("udp dns server is listening on {}", socket.local_addr()?);

        let h = Arc::new(h);
        let socket = Arc::new(socket);

        let mut framed = UdpFramed::new(Clone::clone(&socket), BytesCodec::new());

        loop {
            tokio::select! {
                recv = framed.next() => {
                    match recv{
                        Some(Ok((b,peer))) => {
                            let req = Message::from(b);
                            let h = Clone::clone(&h);
                            let cache = Clone::clone(&cache);
                            let socket = Clone::clone(&socket);

                            if req.question_count() > 0 {
                                for next in req.questions() {
                                    info!("{}-0x{:04x} => {}.\t\t{:?}\t{:?}", &peer, req.id(), next.name(), next.class(), next.kind());
                                }
                            }

                            tokio::spawn(async move {
                                match Self::handle(req, h, cache).await {
                                    Ok(res) => {
                                        if res.answer_count() > 0 {
                                            for next in res.answers() {
                                                if let Ok(rdata) = next.rdata(){
                                                    info!(
                                                        "{}-0x{:04x} <= {}.\t{}\t{:?}\t{:?}\t{}",
                                                        &peer,
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
                                        if let Err(e) = socket.send_to(res.as_ref(), peer).await {
                                            error!("failed to reply dns response: {:?}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!("failed to handle dns request: {:?}", e);
                                    }
                                }
                            });
                        }
                        _ => {
                            break;
                        }
                    }
                }
                () = closer.notified() => {
                    info!("close signal is received, udp dns server is stopping...");
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::cache::InMemoryCache;
    use crate::client::request;
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
    async fn test_udp_listen() -> anyhow::Result<()> {
        init();

        let req = {
            let raw = hex::decode(
                "abe6010000010000000000000770616e63616b65056170706c6503636f6d0000410001",
            )
            .unwrap();
            Message::from(raw)
        };

        let res = {
            let raw = hex::decode("abe6818000010003000000000770616e63616b65056170706c6503636f6d0000410001c00c000500010000000100220770616e63616b650963646e2d6170706c6503636f6d06616b61646e73036e657400c02f000500010000000100140770616e63616b650167076161706c696d67c01ac05d0041000100000001002a0001008000002368747470733a2f2f646f682e646e732e6170706c652e636f6d2f646e732d7175657279").unwrap();
            Message::from(raw)
        };

        let cnts = Arc::new(AtomicU64::new(0));

        let h = MockHandler {
            cnt: Clone::clone(&cnts),
            resp: Clone::clone(&res),
        };

        let cs = Arc::new(InMemoryCache::builder().build());
        let socket = UdpSocket::bind("127.0.0.1:5454").await?;
        let port = socket.local_addr().unwrap().port();
        let closer = Arc::new(Notify::new());

        let server = UdpServer::new(socket, h, Some(cs), Clone::clone(&closer));

        tokio::spawn(async move {
            server.listen().await.expect("udp server is stopped!");
        });

        let dns = DNS::from_str(&format!("127.0.0.1:{}", port))?;

        // no cache
        assert!(request(&dns, &req).await.is_ok_and(|msg| &msg == &res));

        // use cache
        assert!(request(&dns, &req).await.is_ok_and(|msg| &msg == &res));

        assert_eq!(
            1,
            cnts.load(Ordering::SeqCst),
            "should only call handler once!"
        );

        closer.notify_waiters();

        Ok(())
    }
}
