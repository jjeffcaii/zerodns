use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::codec::{FramedRead, FramedWrite};
use url::Url;

use crate::protocol::Message;
use crate::Result;

use super::tcp::Codec;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DNS {
    UDP(SocketAddr),
    TCP(SocketAddr),
    DoT(SocketAddr),
    DoH(Url),
}

impl DNS {
    pub async fn request(&self, req: &Message) -> Result<Message> {
        let resp = match self {
            DNS::UDP(addr) => {
                let mut b = BytesMut::with_capacity(4096);
                Self::request_udp(addr, req, &mut b).await
            }
            DNS::TCP(addr) => Self::request_tcp(addr, req).await,
            _ => {
                todo!()
            }
        };

        if let Ok(res) = &resp {
            debug!("0x{:x} >>>: {}", req.id(), hex::encode(req.as_ref()));
            debug!("0x{:x} <<<: {}", res.id(), hex::encode(res.as_ref()));
        }

        resp
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

impl FromStr for DNS {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let from_host_port = |host: IpAddr, port: u16| match host {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
        };

        if s.contains('/') {
            // schema://xxx/xxx
            let url = Url::parse(s)?;
            match url.scheme() {
                "udp" => {
                    if let Some(host) = url.host_str() {
                        let ip = host.parse::<IpAddr>()?;
                        let addr = from_host_port(ip, url.port().unwrap_or(53));
                        return Ok(DNS::UDP(addr));
                    }
                }
                "tcp" => {
                    if let Some(host) = url.host_str() {
                        let ip = host.parse::<IpAddr>()?;
                        let addr = from_host_port(ip, url.port().unwrap_or(53));
                        return Ok(DNS::TCP(addr));
                    }
                }
                _ => (),
            }
        } else if s.contains(':') {
            // host:port
            let addr = SocketAddr::from_str(s)?;
            return Ok(DNS::UDP(addr));
        } else {
            let ip = IpAddr::from_str(s)?;
            let addr = from_host_port(ip, 53);
            return Ok(DNS::UDP(addr));
        }

        bail!("invalid dns url '{}'", s)
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{Class, Flags, Kind, OpCode};

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    fn get_request(domain: &str) -> Result<Message> {
        let flags = Flags::builder()
            .request()
            .recursive_query(true)
            .opcode(OpCode::StandardQuery)
            .build();
        Message::builder()
            .id(0x1234)
            .question(domain, Kind::A, Class::IN)
            .flags(flags)
            .build()
    }

    #[test]
    fn test_from_str() {
        init();
        {
            let dns = DNS::from_str("tcp://127.0.0.1:53");
            assert!(dns.is_ok_and(|dns| matches!(dns, DNS::TCP(_))));
        }

        {
            let dns = DNS::from_str("tcp://127.0.0.1");
            assert!(dns.is_ok_and(|dns| matches!(dns, DNS::TCP(_))));
        }
    }

    #[tokio::test]
    async fn test_addr_request_udp() {
        init();

        let addr = DNS::UDP("8.8.4.4:53".parse().unwrap());
        let req = get_request("google.com.").unwrap();
        let res = addr.request(&req).await;

        assert!(res.is_ok_and(|it| {
            for (i, answer) in it.answers().enumerate() {
                let rdata = answer.rdata().unwrap();
                info!("answer#{}: domain={} rdata={}", i, answer.name(), rdata);
            }
            true
        }));
    }

    #[tokio::test]
    async fn test_addr_request_tcp() {
        init();

        let addr = DNS::TCP("223.5.5.5:53".parse().unwrap());

        let req = get_request("baidu.com").unwrap();

        let res = addr.request(&req).await;

        assert!(res.is_ok_and(|it| {
            for (i, answer) in it.answers().enumerate() {
                let rdata = answer.rdata().unwrap();
                info!("answer#{}: domain={} rdata={}", i, answer.name(), rdata);
            }
            true
        }));
    }
}
