use std::net::SocketAddr;

use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use tokio::net::UdpSocket;

use crate::protocol::Message;
use crate::Result;

pub struct Client {
    addr: SocketAddr,
    buf: BytesMut,
}

impl Client {
    pub async fn request(&mut self, req: &Message) -> Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.addr).await?;

        let _ = socket.send(req.as_ref()).await?;
        let n = socket.recv_buf(&mut self.buf).await?;

        BigEndian::write_u16(&mut self.buf[..], req.id());

        let b = self.buf.split_to(n).freeze();

        Ok(Message::from(b))
    }
}

impl From<SocketAddr> for Client {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            buf: BytesMut::with_capacity(4096),
        }
    }
}
