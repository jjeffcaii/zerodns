use crate::client::doh::DoHClient;
use crate::client::dot::DoTClient;
use crate::protocol::*;
use crate::Result;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
pub use tcp::{TcpClient, TcpClientBuilder};
pub use udp::{UdpClient, UdpClientBuilder};

mod doh;
mod dot;
mod tcp;
mod udp;

pub static DEFAULT_DNS: Lazy<RwLock<Arc<dyn Client>>> = Lazy::new(|| {
    let c = UdpClient::builder("8.8.8.8:53".parse().unwrap()).build();
    RwLock::new(Arc::new(c))
});

#[async_trait::async_trait]
pub trait Client: Sync + Send + 'static {
    async fn request(&self, req: &Message) -> Result<Message>;
}

pub async fn request(dns: &DNS, request: &Message, timeout: Duration) -> Result<Message> {
    match dns {
        DNS::UDP(addr) => {
            let c = UdpClient::builder(*addr).timeout(timeout).build();
            c.request(request).await
        }
        DNS::TCP(addr) => {
            let c = TcpClient::builder(*addr).timeout(timeout).build()?;
            c.request(request).await
        }
        DNS::DoT(addr) => match addr {
            Address::SocketAddr(addr) => {
                let c = DoTClient::builder(*addr).timeout(timeout).build()?;
                c.request(request).await
            }
            Address::HostAddr(host_addr) => {
                let domain = &host_addr.host;
                let ip = lookup(domain, timeout).await?;
                let addr = SocketAddr::new(IpAddr::V4(ip), host_addr.port);
                let c = DoTClient::builder(addr)
                    .sni(domain.as_ref())
                    .timeout(timeout)
                    .build()?;
                c.request(request).await
            }
        },
        DNS::DoH(doh_addr) => {
            let dc = match &doh_addr.addr {
                Address::SocketAddr(addr) => DoHClient::builder(*addr).https(doh_addr.https),
                Address::HostAddr(addr) => {
                    let domain = &addr.host;
                    let ip = lookup(domain, timeout).await?;
                    let mut bu = DoHClient::builder(SocketAddr::new(IpAddr::V4(ip), addr.port))
                        .host(domain)
                        .https(doh_addr.https);

                    if let Some(path) = &doh_addr.path {
                        bu = bu.path(path);
                    }
                    bu
                }
            }
            .build();

            dc.request(request).await
        }
    }
}

pub fn set_default_dns<C>(client: C)
where
    C: Client,
{
    let mut w = DEFAULT_DNS.write();
    *w = Arc::new(client)
}

#[inline]
async fn lookup(host: &str, timeout: Duration) -> Result<Ipv4Addr> {
    // TODO: add cache
    let flags = Flags::builder()
        .request()
        .recursive_query(true)
        .opcode(OpCode::StandardQuery)
        .build();
    let req0 = Message::builder()
        .id(1234)
        .flags(flags)
        .question(host, Kind::A, Class::IN)
        .build()?;

    let c = {
        let r = DEFAULT_DNS.read();
        Clone::clone(&*r)
    };

    let v = c.request(&req0).await?;

    for next in v.answers() {
        if let Ok(RData::A(a)) = next.rdata() {
            return Ok(a.ipaddr());
        }
    }

    bail!(crate::Error::ResolveNothing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_request() -> anyhow::Result<()> {
        init();

        let req = {
            // type=A domain=baidu.com
            let raw = hex::decode(
                "128e0120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )?;
            Message::from(raw)
        };

        for next in [
            "223.5.5.5",
            "tcp://223.5.5.5",
            "dot://dot.pub",
            "https://1.1.1.1",
        ] {
            let dns = DNS::from_str(next)?;
            let res = request(&dns, &req, Duration::from_secs(3)).await;

            assert!(res.is_ok());

            info!("resolve from {}: {:?}", next, res?);
        }

        Ok(())
    }
}
