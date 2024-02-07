use async_trait::async_trait;
use bytes::BytesMut;
use tokio::net::UdpSocket;

use crate::protocol::Message;
use crate::Result;

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: &Message) -> Result<Message>;
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
                    let req = Message::from(b);

                    let resp = h.handle(&req).await?;

                    socket.send_to(resp.as_ref(), peer).await?;
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
