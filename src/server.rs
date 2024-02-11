use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::net::UdpSocket;

use crate::cache::CacheStore;
use crate::handler::Handler;
use crate::protocol::Message;
use crate::Result;

pub struct Server<H> {
    h: H,
    socket: UdpSocket,
    buf: BytesMut,
    cache: Option<CacheStore>,
}

impl<H> Server<H> {
    pub fn new(socket: UdpSocket, handler: H, buf: BytesMut, cache: Option<CacheStore>) -> Self {
        Self {
            h: handler,
            socket,
            buf,
            cache,
        }
    }
}

impl<H> Server<H>
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

        info!("dns handler is listening on {:?}", &socket);

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
                                    cache.set(&req, &msg).await;
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
