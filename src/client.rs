use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use tokio::net::{ToSocketAddrs, UdpSocket};

use crate::protocol::Message;
use crate::Result;

pub struct Client<A> {
    addr: A,
    buf: BytesMut,
}

impl<A> Client<A>
where
    A: ToSocketAddrs,
{
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

impl<A> From<A> for Client<A>
where
    A: ToSocketAddrs,
{
    fn from(addr: A) -> Self {
        Self {
            addr,
            buf: BytesMut::with_capacity(4096),
        }
    }
}
