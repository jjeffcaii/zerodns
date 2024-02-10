use super::Options;
use crate::Result;
use serde::de::DeserializeOwned;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use toml::Value;

pub struct OptionsReader<'a>(&'a Options);

impl OptionsReader<'_> {
    pub fn get_option<K, T>(&self, key: K) -> Result<Option<T>>
    where
        K: AsRef<str>,
        T: DeserializeOwned + 'static,
    {
        match self.0.get(key.as_ref()) {
            None => Ok(None),
            Some(v) => {
                let s = toml::to_string(v)?;
                let t = toml::from_str::<T>(&s)?;
                Ok(Some(t))
            }
        }
    }

    pub fn get_addrs<A>(&self, k: A) -> Result<Option<Vec<SocketAddr>>>
    where
        A: AsRef<str>,
    {
        let parse_addr = |s: &str| {
            let mut addr: Option<SocketAddr> = None;

            match s.parse::<SocketAddr>() {
                Ok(it) => {
                    addr.replace(it);
                }
                Err(_) => {
                    if let Ok(it) = s.parse::<IpAddr>() {
                        let vv = match it {
                            IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, 53)),
                            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 0)),
                        };
                        addr.replace(vv);
                    }
                }
            }
            addr
        };

        let key = k.as_ref();
        match self.0.get(key) {
            None => Ok(None),
            Some(v) => match v {
                Value::String(s) => match parse_addr(s) {
                    None => bail!("invalid server '{}'", s),
                    Some(addr) => Ok(Some(vec![addr])),
                },
                Value::Array(arr) => {
                    let mut addrs = vec![];

                    for next in arr {
                        match next {
                            Value::String(s) => match parse_addr(s) {
                                None => bail!("invalid server '{}'", s),
                                Some(addr) => {
                                    addrs.push(addr);
                                }
                            },
                            _ => bail!("invalid property '{}'", key),
                        }
                    }
                    Ok(Some(addrs))
                }
                _ => bail!("invalid property '{}'", key),
            },
        }
    }
}

impl<'a> From<&'a Options> for OptionsReader<'a> {
    fn from(value: &'a Options) -> Self {
        Self(value)
    }
}
