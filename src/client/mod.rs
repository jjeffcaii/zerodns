use crate::cachestr::Cachestr;
use crate::client::doh::DoHClient;
use crate::client::dot::DoTClient;
use crate::error::Error;
use crate::protocol::*;
use crate::Result;
use moka::future::Cache;
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
pub use tcp::{TcpClient, TcpClientBuilder};
pub use tokio::sync::OnceCell;
pub use udp::{UdpClient, UdpClientBuilder};

mod doh;
mod dot;
mod tcp;
mod udp;

static DEFAULT_DNS: OnceCell<Arc<dyn Client>> = OnceCell::const_new();

static DEFAULT_LOOKUPS: Lazy<LookupCache> = Lazy::new(|| {
    let cache = Cache::builder()
        .max_capacity(4096)
        .time_to_live(Duration::from_secs(30))
        .build();
    LookupCache(cache)
});

pub async fn default_dns() -> Result<Arc<dyn Client>> {
    let v = DEFAULT_DNS
        .get_or_try_init(|| async {
            use crate::ext::resolvconf;
            use resolv_conf::ScopedIp;

            if let Ok(c) = resolvconf::GLOBAL_CONFIG
                .get_or_try_init(|| async {
                    let path = PathBuf::from(resolvconf::DEFAULT_RESOLV_CONF_PATH);
                    let c = resolvconf::read(&path).await?;
                    Ok::<_, anyhow::Error>(c)
                })
                .await
            {
                if let Some(next) = c.nameservers.first() {
                    let ipaddr = match next {
                        ScopedIp::V4(v4) => IpAddr::V4(*v4),
                        ScopedIp::V6(v6, _) => IpAddr::V6(*v6),
                    };

                    info!("use {} as default resolver", ipaddr);

                    let mut bu = UdpClient::builder(SocketAddr::new(ipaddr, DEFAULT_UDP_PORT));

                    if c.timeout > 0 {
                        bu = bu.timeout(Duration::from_secs(c.timeout as u64));
                    }

                    let c = bu.build();
                    let c: Arc<dyn Client> = Arc::new(c);
                    return Ok::<Arc<dyn Client>, anyhow::Error>(c);
                }
            }

            const DEFAULT_DNS: &str = "8.8.8.8:53";

            let c = UdpClient::builder(DEFAULT_DNS.parse().unwrap()).build();
            let c: Arc<dyn Client> = Arc::new(c);

            info!("use {} as default resolver", DEFAULT_DNS);

            Ok(c)
        })
        .await?;

    Ok(Clone::clone(v))
}

#[async_trait::async_trait]
pub trait Client: Sync + Send + 'static {
    async fn request(&self, req: &Message) -> Result<Message>;
}

#[derive(Debug, Default, Copy, Clone)]
pub(crate) struct DefaultClient;

#[async_trait::async_trait]
impl Client for DefaultClient {
    async fn request(&self, req: &Message) -> Result<Message> {
        let c = default_dns().await?;
        c.request(req).await
    }
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

struct LookupCache(Cache<Cachestr, SmallVec<[Ipv4Addr; 2]>>);

impl LookupCache {
    async fn lookup(&self, host: &str, timeout: Duration) -> Result<Ipv4Addr> {
        let key = Cachestr::from(host);

        let res = self
            .0
            .try_get_with(key, Self::lookup_(host, timeout))
            .await
            .map_err(|e| anyhow!("lookup failed: {}", e))?;

        if let Some(first) = res.first() {
            return Ok(Clone::clone(first));
        }

        bail!(Error::ResolveNothing)
    }

    #[inline]
    async fn lookup_(host: &str, timeout: Duration) -> Result<SmallVec<[Ipv4Addr; 2]>> {
        let flags = Flags::builder()
            .request()
            .recursive_query(true)
            .opcode(OpCode::StandardQuery)
            .build();

        let id = {
            use rand::prelude::*;

            let mut rng = thread_rng();
            rng.gen_range(1..u16::MAX)
        };

        let req0 = Message::builder()
            .id(id)
            .flags(flags)
            .question(host, Kind::A, Class::IN)
            .build()?;

        let mut ret = SmallVec::<[Ipv4Addr; 2]>::new();
        let v = DefaultClient.request(&req0).await?;
        for next in v.answers() {
            if let Ok(RData::A(a)) = next.rdata() {
                ret.push(a.ipaddr());
            }
        }

        if !ret.is_empty() {
            return Ok(ret);
        }

        bail!(Error::ResolveNothing)
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
    async fn test_default_client() -> anyhow::Result<()> {
        init();

        let c = DefaultClient::default();
        let flags = Flags::builder().recursive_query(true).build();
        let req = Message::builder()
            .flags(flags)
            .id(0x1234)
            .question("www.taobao.com", Kind::A, Class::IN)
            .build()?;

        let res = c.request(&req).await;
        assert!(res.is_ok_and(|res| {
            for next in res.answers() {
                info!(
                    "{}\t{}\t{}\t{}",
                    next.name(),
                    next.kind(),
                    next.class(),
                    next.rdata().unwrap()
                );
            }

            res.flags().response_code() == RCode::NoError
        }));

        Ok(())
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
