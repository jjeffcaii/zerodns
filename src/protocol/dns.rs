use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use url::Url;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DNS {
    UDP(SocketAddr),
    TCP(SocketAddr),
    DoT(Host, u16),
    DoH(Url),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    IpAddr(IpAddr),
    Domain(String),
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
                    if let Some(host) = url.host_str() {
                        let port = url.port().unwrap_or(853);
                        if let Ok(ip) = host.parse::<IpAddr>() {
                            return Ok(DNS::DoT(Host::IpAddr(ip), port));
                        }
                        return Ok(DNS::DoT(Host::Domain(host.to_string()), port));
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
    use std::net::IpAddr;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[test]
    fn test_from_str() {
        init();

        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        {
            let dns = DNS::from_str("tcp://1.1.1.1:53");
            assert!(dns.is_ok_and(|dns| matches!(dns, DNS::TCP(_))));
        }

        {
            let dns = DNS::from_str("tcp://1.1.1.1");
            assert!(dns.is_ok_and(|dns| matches!(dns, DNS::TCP(_))));
        }

        {
            let dns = DNS::from_str("dot://1.1.1.1");
            assert!(dns.is_ok_and(|dns| matches!(dns, DNS::DoT(Host::IpAddr(ip), 853))));
        }

        {
            let dns = DNS::from_str("dot://1.1.1.1:8853");
            let expect = DNS::DoT(Host::IpAddr(ip), 8853);
            assert!(dns.is_ok_and(|dns| matches!(dns, expect)));
        }

        let domain = "one.one.one.one";
        {
            let dns = DNS::from_str("dot://one.one.one.one");
            let expect = DNS::DoT(Host::Domain(domain.to_string()), 853);
            assert!(dns.is_ok_and(|dns| matches!(dns, expect)));
        }
    }
}
