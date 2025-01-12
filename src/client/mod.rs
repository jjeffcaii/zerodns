use crate::protocol::*;
use crate::Result;
use arc_swap::ArcSwap;
pub use doh::DoHClient;
pub use dot::DoTClient;
use once_cell::sync::Lazy;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
pub use system::SystemClient;
pub use tcp::{TcpClient, TcpClientBuilder};
pub use tokio::sync::OnceCell;
pub use udp::{UdpClient, UdpClientBuilder};

mod doh;
mod dot;
mod lookup;
mod system;
mod tcp;
mod udp;

pub(super) static SYSTEM_CLIENT: Lazy<ArcSwap<SystemClient>> =
    Lazy::new(|| ArcSwap::from_pointee(SystemClient::default()));

static DEFAULT_LOOKUPS: Lazy<lookup::LookupCache> = Lazy::new(|| {
    use moka::future::Cache;
    let cache = Cache::builder()
        .max_capacity(4096)
        .time_to_live(Duration::from_secs(30))
        .build();
    lookup::LookupCache::from(cache)
});

pub fn set_default_resolver(client: SystemClient) {
    info!("customize resolver from {}", &client);
    SYSTEM_CLIENT.store(Arc::new(client));
}

#[async_trait::async_trait]
pub trait Client: Sync + Send + 'static {
    async fn request(&self, request: &Message) -> Result<Message>;
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
                let ip = DEFAULT_LOOKUPS.lookup(domain, timeout).await?;
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
                    let ip = DEFAULT_LOOKUPS.lookup(domain, timeout).await?;
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
            let flags = Flags::builder().recursive_query(true).build();
            Message::builder()
                .flags(flags)
                .question("baidu.com", Kind::A, Class::IN)
                .build()?
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
