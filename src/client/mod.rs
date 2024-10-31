use crate::client::dot::DoTClient;
use crate::protocol::*;
use crate::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
pub use tcp::{TcpClient, TcpClientBuilder};
pub use udp::{UdpClient, UdpClientBuilder};

mod dot;
mod tcp;
mod udp;

#[async_trait::async_trait]
pub trait Client {
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
        DNS::DoT(host, port) => match host {
            Host::IpAddr(ip) => {
                let addr = SocketAddr::new(*ip, *port);
                let c = DoTClient::builder(addr).timeout(timeout).build()?;
                c.request(request).await
            }
            Host::Domain(domain) => {
                let mut ip = None;

                // TODO: lookup address of domain, how to define the default dns???
                {
                    let dc = UdpClient::builder("223.5.5.5:53".parse()?)
                        .timeout(timeout)
                        .build();
                    let flags = Flags::builder()
                        .request()
                        .recursive_query(true)
                        .opcode(OpCode::StandardQuery)
                        .build();
                    let req0 = Message::builder()
                        .id(request.id())
                        .flags(flags)
                        .question(domain, Kind::A, Class::IN)
                        .build()?;
                    let v = dc.request(&req0).await?;

                    for next in v.answers() {
                        if let Ok(RData::A(a)) = next.rdata() {
                            ip.replace(a.ipaddr());
                            break;
                        }
                    }
                }

                let ip = ip.ok_or_else(|| crate::Error::ResolveNothing)?;

                let addr = SocketAddr::new(IpAddr::V4(ip), *port);

                let c = DoTClient::builder(addr)
                    .sni(domain)
                    .timeout(timeout)
                    .build()?;
                c.request(request).await
            }
        },
        _ => todo!(),
    }
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

        for next in ["223.5.5.5", "dot://dot.pub"] {
            let dns = DNS::from_str(next)?;
            let res = request(&dns, &req, Duration::from_secs(3)).await;

            assert!(res.is_ok());

            info!("resolve from {}: {:?}", next, res?);
        }

        Ok(())
    }
}
