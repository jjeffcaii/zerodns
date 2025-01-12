use super::{Client, TcpClient, UdpClient};
use crate::protocol::Message;
use crate::Result;
use resolv_conf::{Config, ScopedIp};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

enum InnerClient {
    Udp(UdpClient),
    Tcp(TcpClient),
}

pub struct SystemClient(Vec<InnerClient>);

impl Display for SystemClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SystemClient{")?;

        let mut iter = self.0.iter();

        if let Some(first) = iter.next() {
            match first {
                InnerClient::Udp(uc) => write!(f, "{}", uc),
                InnerClient::Tcp(tc) => write!(f, "{}", tc),
            }?
        }

        for next in iter {
            match next {
                InnerClient::Udp(uc) => write!(f, ",{}", uc),
                InnerClient::Tcp(tc) => write!(f, ",{}", tc),
            }?
        }

        f.write_str("}")?;

        Ok(())
    }
}

impl SystemClient {
    pub fn builder() -> SystemClientBuilder {
        Default::default()
    }

    pub fn from_resolv_file(path: &PathBuf) -> Self {
        let mut clients = vec![];

        let mut timeout = None;

        if let Ok(b) = std::fs::read(path) {
            if let Ok(c) = Config::parse(&b[..]) {
                if c.timeout > 0 {
                    timeout.replace(Duration::from_secs(c.timeout as u64));
                }

                for next in c.nameservers {
                    if let Some(addr) = match next {
                        ScopedIp::V4(v4) if !v4.is_loopback() => Some(IpAddr::V4(v4)),
                        ScopedIp::V6(v6, _) if !v6.is_loopback() => Some(IpAddr::V6(v6)),
                        _ => None,
                    } {
                        let mut bu = UdpClient::builder(SocketAddr::new(addr, 53));
                        if let Some(timeout) = timeout {
                            bu = bu.timeout(timeout);
                        }
                        clients.push(InnerClient::Udp(bu.build()));
                    }
                }
            }
        }

        Self(clients)
    }
}

impl Default for SystemClient {
    fn default() -> Self {
        Self::from_resolv_file(&PathBuf::from("/etc/resolv.conf"))
    }
}

#[async_trait::async_trait]
impl Client for SystemClient {
    async fn request(&self, req: &Message) -> Result<Message> {
        let mut last = None;
        for c in &self.0 {
            let res = match c {
                InnerClient::Udp(c) => c.request(req).await,
                InnerClient::Tcp(c) => c.request(req).await,
            };

            if res.is_ok() {
                return res;
            }

            last = Some(res)
        }

        if let Some(exist) = last {
            return exist;
        }

        UdpClient::google().request(req).await
    }
}

#[derive(Default)]
pub struct SystemClientBuilder {
    timeout: Option<Duration>,
    nameservers: Vec<(SocketAddr, /* is_tcp */ bool)>,
}

impl SystemClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn nameserver(mut self, nameserver: SocketAddr, is_tcp: bool) -> Self {
        let item = (nameserver, is_tcp);
        if !self.nameservers.contains(&item) {
            self.nameservers.push(item);
        }
        self
    }

    pub fn build(self) -> Result<SystemClient> {
        let Self {
            timeout,
            nameservers,
        } = self;

        let mut clients = Vec::with_capacity(nameservers.len());

        for (addr, is_tcp) in nameservers {
            if is_tcp {
                let mut bu = TcpClient::builder(addr);
                if let Some(timeout) = timeout {
                    bu = bu.timeout(timeout);
                }
                clients.push(InnerClient::Tcp(bu.build()?));
            } else {
                let mut bu = UdpClient::builder(addr);
                if let Some(timeout) = timeout {
                    bu = bu.timeout(timeout);
                }
                clients.push(InnerClient::Udp(bu.build()));
            }
        }

        Ok(SystemClient(clients))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Class, Flags, Kind, RCode};

    fn init() {
        pretty_env_logger::try_init().ok();
    }

    #[tokio::test]
    async fn test_default_client() -> anyhow::Result<()> {
        init();

        let c = SystemClient::default();
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
}
