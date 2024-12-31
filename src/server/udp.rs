use futures::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use super::helper;
use crate::cache::CacheStore;
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
    pub fn new(socket: UdpSocket, h: H, cache: Option<Arc<C>>, closer: Arc<Notify>) -> Self {
        Self {
            h,
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
    async fn handle_request(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        req: Message,
        h: Arc<H>,
        cache: Option<Arc<C>>,
    ) {
        let result = helper::handle(req, h, cache).await;
        if let Err(e) = socket.send_to(result.as_ref(), peer).await {
            error!("failed to reply dns response: {:?}", e);
        }
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
                    match recv {
                        Some(Ok((b, peer))) => {
                            let req = Message::from(b);
                            let h = Clone::clone(&h);
                            let cache = Clone::clone(&cache);
                            let socket = Clone::clone(&socket);

                            if req.question_count() > 0 {
                                for next in req.questions() {
                                    info!("0x{:04x} -> {}.\t\t{:?}\t{:?}", req.id(), next.name(), next.class(), next.kind());
                                }
                            }

                            tokio::spawn(async move {
                                Self::handle_request(socket, peer, req, h, cache).await;
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
    use super::*;
    use crate::cache::InMemoryCache;
    use crate::client::request;
    use crate::filter::Context;
    use crate::protocol::{Class, Flags, Kind, Message, DNS};
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
    async fn test_udp_listen() -> anyhow::Result<()> {
        init();

        let res = {
            let raw = hex::decode("0001818000010003000100000770616e63616b65056170706c6503636f6d0000410001c00c00050001000050bd00220770616e63616b650963646e2d6170706c6503636f6d06616b61646e73036e657400c02f000500010000012c00170d6170706c65646f776e6c6f61640671746c63646ec01ac05d000500010000000500210d6170706c65646f776e6c6f61640671746c63646e03636f6d0563646e6d67c01ac099000600010000003c003004646e73310563646e3230036f726700097765626d6173746572c09954cace5700002a3000000e1000093a800000003c")?;
            Message::from(raw)
        };

        let req = {
            let flags = Flags::builder().request().recursive_query(true).build();
            Message::builder()
                .id(0x0001)
                .flags(flags)
                .question("pancake.apple.com", Kind::HTTPS, Class::IN)
                .build()?
        };

        let cnts = Arc::new(AtomicU64::new(0));

        let h = MockHandler {
            cnt: Clone::clone(&cnts),
            resp: Clone::clone(&res),
        };

        let cs = Arc::new(InMemoryCache::builder().build());
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        let closer = Arc::new(Notify::new());

        let server = UdpServer::new(socket, h, Some(cs), Clone::clone(&closer));

        tokio::spawn(async move {
            server.listen().await.expect("udp server is stopped!");
        });

        let dns = DNS::from_str(&format!("127.0.0.1:{}", port))?;

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
