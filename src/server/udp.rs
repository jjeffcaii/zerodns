use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::net::UdpSocket;

use crate::cache::CacheStore;
use crate::handler::Handler;
use crate::protocol::Message;
use crate::Result;

pub struct UdpServer<H> {
    h: H,
    socket: UdpSocket,
    buf: BytesMut,
    cache: Option<CacheStore>,
}

impl<H> UdpServer<H> {
    pub fn new(socket: UdpSocket, handler: H, buf: BytesMut, cache: Option<CacheStore>) -> Self {
        Self {
            h: handler,
            socket,
            buf,
            cache,
        }
    }
}

impl<H> UdpServer<H>
where
    H: Handler,
{
    pub async fn listen(self) -> Result<()> {
        let Self {
            h,
            socket,
            mut buf,
            cache,
        } = self;

        info!("udp dns server is listening on {}", socket.local_addr()?);

        let h = Arc::new(h);
        let socket = Arc::new(socket);

        loop {
            match socket.recv_buf_from(&mut buf).await {
                Ok((n, peer)) => {
                    let socket = Clone::clone(&socket);

                    let b = buf.split_to(n);
                    let h = Clone::clone(&h);
                    let cache = Clone::clone(&cache);

                    tokio::spawn(async move {
                        let mut req = Message::from(b);

                        if let Some(cache) = &cache {
                            let id = req.id();
                            req.set_id(0);

                            if let Some((expired_at, mut exist)) = cache.get(&req).await {
                                let ttl = expired_at - Instant::now();
                                if ttl > Duration::ZERO {
                                    exist.set_id(id);

                                    debug!("use cache: ttl={:?}", ttl);

                                    if let Err(e) = socket.send_to(exist.as_ref(), peer).await {
                                        error!("failed to reply response: {:?}", e);
                                    }

                                    return;
                                }
                            }

                            req.set_id(id);
                        }

                        match h.handle(&mut req).await {
                            Ok(res) => {
                                let msg = res.expect("no record resolved");

                                if let Some(cache) = &cache {
                                    let id = req.id();
                                    req.set_id(0);
                                    cache.set(&req, &msg).await;
                                    req.set_id(id);

                                    debug!("set dns cache ok");
                                }

                                // TODO: handle no result
                                if let Err(e) = socket.send_to(msg.as_ref(), peer).await {
                                    error!("failed to reply response: {:?}", e);
                                }
                            }
                            Err(e) => {
                                error!("failed to handle request: {:?}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("handler stopped: {:?}", e);
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

        let cs = CacheStore::builder().build();
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr().unwrap().port();

        let server = UdpServer::new(socket, h, BytesMut::with_capacity(4096), Some(cs));

        tokio::spawn(async move {
            server.listen().await.expect("udp server is stopped!");
        });

        let dns = DNS::from_str(&format!("127.0.0.1:{}", port))?;

        // no cache
        assert!(dns.request(&req).await.is_ok_and(|msg| &msg == &res));

        // use cache
        assert!(dns.request(&req).await.is_ok_and(|msg| &msg == &res));

        assert_eq!(
            1,
            cnts.load(Ordering::SeqCst),
            "should only call handler once!"
        );

        Ok(())
    }
}
