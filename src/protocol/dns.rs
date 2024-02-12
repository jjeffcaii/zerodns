use std::net::SocketAddr;

use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::protocol::Message;
use crate::Result;

use super::tcp::Codec;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DNS {
    UDP(SocketAddr),
    TCP(SocketAddr),
    DoT(SocketAddr),
    DoH(url::Url),
}

impl DNS {
    pub async fn request(&self, req: &Message) -> Result<Message> {
        match self {
            DNS::UDP(addr) => {
                let mut b = BytesMut::with_capacity(4096);
                Self::request_udp(addr, req, &mut b).await
            }
            DNS::TCP(addr) => Self::request_tcp(addr, req).await,
            _ => {
                todo!()
            }
        }
    }

    #[inline]
    async fn request_udp(addr: &SocketAddr, req: &Message, buf: &mut BytesMut) -> Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;

        let _ = socket.send(req.as_ref()).await?;
        let n = socket.recv_buf(buf).await?;

        BigEndian::write_u16(&mut buf[..], req.id());

        let b = buf.split_to(n);

        Ok(Message::from(b))
    }

    async fn request_tcp(addr: &SocketAddr, req: &Message) -> Result<Message> {
        //TODO: tcp pool + multiplexing
        let mut socket = TcpStream::connect(addr).await?;
        let (r, w) = socket.split();
        let mut r = FramedRead::with_capacity(r, Codec, 4096);
        let mut w = FramedWrite::new(w, Codec);

        w.send(req).await?;
        let res = r.next().await.ok_or(anyhow!("no response read"))??;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::Bytes;

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    fn get_request() -> Message {
        let b = hex::decode(
            "ca580120000100000000000106676f6f676c6503636f6d00000100010000291000000000000000",
        )
        .unwrap();
        let req = Message::from(Bytes::from(b));

        for (i, question) in req.questions().enumerate() {
            info!("question#{}: {}", i, question.name_string());
        }

        req
    }

    #[tokio::test]
    async fn test_addr_request_udp() {
        init();

        let addr = DNS::UDP("8.8.4.4:53".parse().unwrap());
        let req = get_request();
        let res = addr.request(&req).await;

        assert!(res.is_ok_and(|it| {
            for answer in it.answers() {
                let data = answer.data();
                let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                info!(
                    "answer#{}: domain={} addr={:?}",
                    i,
                    answer.name_string(),
                    ip
                );
            }
            true
        }));
    }

    #[tokio::test]
    async fn test_addr_request_tcp() {
        init();

        let addr = DNS::TCP("223.5.5.5:53".parse().unwrap());
        let req = get_request();
        let res = addr.request(&req).await;

        assert!(res.is_ok_and(|it| {
            for (i, answer) in it.answers().enumerate() {
                let data = answer.data();
                let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);

                info!(
                    "answer#{}: domain={} addr={:?}",
                    i,
                    answer.name_string(),
                    ip
                );
            }
            true
        }));
    }
}
