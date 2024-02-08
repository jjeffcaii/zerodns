use async_trait::async_trait;
use bytes::BytesMut;
use tokio::net::UdpSocket;

use crate::protocol::Message;
use crate::Result;

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: &mut Message) -> Result<Option<Message>>;
}

pub struct Server<H> {
    h: H,
    socket: UdpSocket,
    buf: BytesMut,
}

impl<H> Server<H> {
    pub fn new(socket: UdpSocket, h: H) -> Self {
        Self {
            h,
            socket,
            buf: BytesMut::with_capacity(4096),
        }
    }
}

impl<H> Server<H>
where
    H: Handler,
{
    pub async fn run(self) -> Result<()> {
        let Self { h, socket, mut buf } = self;

        info!("dns server is listening on {:?}", &socket);

        loop {
            match socket.recv_buf_from(&mut buf).await {
                Ok((n, peer)) => {
                    info!("recv {} bytes from peer {:?}", n, peer);
                    let b = buf.split_to(n).freeze();
                    let mut req = Message::from(b);

                    let res = h.handle(&mut req).await?;

                    // TODO: handle no result
                    socket
                        .send_to(res.expect("no record resolved").as_ref(), peer)
                        .await?;
                }
                Err(e) => {
                    error!("server stopped: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}
