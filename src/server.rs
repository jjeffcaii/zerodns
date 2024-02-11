use bytes::BytesMut;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::handler::Handler;
use crate::protocol::Message;
use crate::Result;

pub struct Server<H> {
    h: H,
    socket: UdpSocket,
    buf: BytesMut,
}

impl<H> Server<H> {
    pub fn new(socket: UdpSocket, handler: H, buf: BytesMut) -> Self {
        Self {
            h: handler,
            socket,
            buf,
        }
    }
}

impl<H> Server<H>
where
    H: Handler,
{
    pub async fn listen(self) -> Result<()> {
        let Self { h, socket, mut buf } = self;

        info!("dns handler is listening on {:?}", &socket);

        let h = Arc::new(h);
        let socket = Arc::new(socket);

        loop {
            match socket.recv_buf_from(&mut buf).await {
                Ok((n, peer)) => {
                    let socket = Clone::clone(&socket);

                    let b = buf.split_to(n).freeze();
                    let h = Clone::clone(&h);

                    tokio::spawn(async move {
                        let mut req = Message::from(b);

                        match h.handle(&mut req).await {
                            Ok(res) => {
                                let msg = res.expect("no record resolved");
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
