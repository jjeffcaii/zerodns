use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use async_trait::async_trait;
use smallvec::SmallVec;
use toml::Value;

use crate::client::Client;
use crate::protocol::Message;
use crate::Result;

use super::{Context, Filter, FilterFactory, Options};

#[derive(Default)]
pub(crate) struct ProxyByFilter {
    upstreams: Arc<Vec<SocketAddr>>,
    next: Option<Box<dyn Filter>>,
}

#[async_trait]
impl Filter for ProxyByFilter {
    async fn on_request(&self, _: &mut Context, req: &mut Message) -> Result<Option<Message>> {
        for addr in self.upstreams.iter() {
            let mut c = Client::from(Clone::clone(addr));
            if let Ok(res) = c.request(req).await {
                if log_enabled!(log::Level::Debug) {
                    let mut v = SmallVec::<[u8; 64]>::new();
                    for (i, next) in req.queries().name().enumerate() {
                        if i != 0 {
                            v.push(b'.');
                        }
                        v.extend_from_slice(next);
                    }
                    debug!("proxyby ok: server={:?}, domain={}", addr, unsafe {
                        std::str::from_utf8_unchecked(&v[..])
                    });
                }
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    async fn on_response(&self, ctx: &mut Context, res: &mut Option<Message>) -> Result<()> {
        match &self.next {
            None => Ok(()),
            Some(next) => next.on_response(ctx, res).await,
        }
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub(crate) struct ProxyByFilterFactory {
    upstreams: Arc<Vec<SocketAddr>>,
}

impl ProxyByFilterFactory {
    pub fn new(opts: &Options) -> Result<Self> {
        const KEY_SERVERS: &str = "servers";

        let mut upstreams: Vec<SocketAddr> = Default::default();

        match opts.get(KEY_SERVERS) {
            None => bail!("missing property '{}'", KEY_SERVERS),
            Some(v) => match v {
                Value::Array(arr) => {
                    for it in arr {
                        match it {
                            Value::String(s) => {
                                let mut addr = None;

                                match s.parse::<SocketAddr>() {
                                    Ok(it) => {
                                        addr.replace(it);
                                    }
                                    Err(_) => {
                                        if let Ok(it) = s.parse::<IpAddr>() {
                                            let vv = match it {
                                                IpAddr::V4(ip) => {
                                                    SocketAddr::V4(SocketAddrV4::new(ip, 53))
                                                }
                                                IpAddr::V6(ip) => {
                                                    SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 0))
                                                }
                                            };
                                            addr.replace(vv);
                                        }
                                    }
                                }

                                match addr {
                                    Some(addr) => {
                                        upstreams.push(addr);
                                    }
                                    None => bail!("invalid server '{}'", s),
                                }
                            }
                            _ => bail!("invalid format of property '{}'", KEY_SERVERS),
                        }
                    }
                }
                _ => bail!("invalid format of property '{}'", KEY_SERVERS),
            },
        }

        if upstreams.is_empty() {
            bail!("invalid format of property '{}'", KEY_SERVERS);
        }

        Ok(Self {
            upstreams: Arc::new(upstreams),
        })
    }
}

impl FilterFactory for ProxyByFilterFactory {
    type Item = ProxyByFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(ProxyByFilter {
            upstreams: Clone::clone(&self.upstreams),
            next: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_proxyby_filter() {
        init();

        let mut ctx = Context::default();
        let mut req = {
            // type=A domain=baidu.com
            let raw = hex::decode(
                "128e0120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )
            .unwrap();
            Message::from(Bytes::from(raw))
        };

        let f = ProxyByFilter::default();

        let resp = f.on_request(&mut ctx, &mut req).await;

        assert!(resp.is_ok_and(|res| res.is_some_and(|record| {
            info!("got: {}", record.id());
            true
        })));
    }
}
