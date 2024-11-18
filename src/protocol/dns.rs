use crate::cachestr::Cachestr;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use url::Url;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DNS {
    UDP(SocketAddr),
    TCP(SocketAddr),
    DoT(Address),
    DoH(DoHAddress),
}

impl Display for DNS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DNS::UDP(addr) => write!(f, "udp://{}", addr),
            DNS::TCP(addr) => write!(f, "tcp://{}", addr),
            DNS::DoT(addr) => write!(f, "dot://{}", addr),
            DNS::DoH(addr) => write!(f, "doh+{}", addr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostAddr {
    pub host: Cachestr,
    pub port: u16,
}

impl Display for HostAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketAddr(SocketAddr),
    HostAddr(HostAddr),
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::SocketAddr(addr) => write!(f, "{}", addr),
            Address::HostAddr(addr) => write!(f, "{}", addr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DoHAddress {
    pub addr: Address,
    pub path: Option<Cachestr>,
    pub https: bool,
}

impl Display for DoHAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.https {
            write!(f, "https://")?;
        } else {
            write!(f, "http://")?;
        }

        write!(f, "{}", &self.addr)?;

        if let Some(path) = &self.path {
            write!(f, "{}", path)?;
        }

        Ok(())
    }
}

impl FromStr for DNS {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let from_host_port = |host: IpAddr, port: u16| match host {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
        };

        if s.contains("://") {
            // schema://xxx/xxx
            let url = Url::parse(s)?;

            let extract_addr = |default_port: u16| match url.host_str() {
                Some(host) => {
                    let addr = {
                        let port = url.port().unwrap_or(default_port);
                        match host.parse::<IpAddr>() {
                            Ok(ip) => Address::SocketAddr(SocketAddr::new(ip, port)),
                            _ => {
                                let ha = HostAddr {
                                    host: Cachestr::from(host),
                                    port,
                                };
                                Address::HostAddr(ha)
                            }
                        }
                    };
                    Some(addr)
                }
                None => None,
            };

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
                "dot" => {
                    if let Some(addr) = extract_addr(853) {
                        return Ok(DNS::DoT(addr));
                    }
                }
                "doh" | "https" => {
                    if let Some(addr) = extract_addr(443) {
                        let path = match url.path() {
                            "" | "/" => None,
                            other => Some(Cachestr::from(other)),
                        };
                        return Ok(DNS::DoH(DoHAddress {
                            addr,
                            path,
                            https: true,
                        }));
                    }
                }
                "http" => {
                    if let Some(addr) = extract_addr(80) {
                        let path = match url.path() {
                            "" | "/" => None,
                            other => Some(Cachestr::from(other)),
                        };
                        return Ok(DNS::DoH(DoHAddress {
                            addr,
                            path,
                            https: false,
                        }));
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

        bail!(crate::Error::InvalidDNSUrl(s.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[test]
    fn test_from_str() {
        init();

        for (input, expect) in [
            ("1.1.1.1", "udp://1.1.1.1:53"),
            ("udp://1.1.1.1", "udp://1.1.1.1:53"),
            ("tcp://1.1.1.1", "tcp://1.1.1.1:53"),
            ("dot://1.1.1.1", "dot://1.1.1.1:853"),
            ("dot://one.one.one.one", "dot://one.one.one.one:853"),
            ("doh://dns.google", "doh+https://dns.google.com:443"),
            (
                "doh://dns.google/dns-query",
                "doh+https://dns.google.com:443/dns-query",
            ),
            ("doh://1.1.1.1", "doh+https://1.1.1.1"),
            ("http://1.2.3.4", "doh+http://1.2.3.4:80"),
            ("https://1.1.1.1", "doh+http://1.1.1.1:443"),
        ] {
            let actual = DNS::from_str(input);
            assert!(actual.is_ok_and(|dns| {
                let disp = dns.to_string();
                matches!(&disp, expect)
            }));
        }
    }
}
