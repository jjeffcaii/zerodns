use crate::client::request;
use async_trait::async_trait;
use maxminddb::Reader;
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::filter::misc::OptionsReader;
use crate::protocol::{Kind, Message, RData, DNS};
use crate::Result;

use super::{handle_next, Context, Filter, FilterFactory, Options};

pub(crate) struct ChinaDNSFilter {
    trusted: Arc<Vec<DNS>>,
    mistrusted: Arc<Vec<DNS>>,
    next: Option<Box<dyn Filter>>,
    geoip: Arc<Reader<Vec<u8>>>,
}

impl ChinaDNSFilter {
    async fn request(
        req: &Message,
        servers: &[DNS],
        geoip: &Reader<Vec<u8>>,
        all_china: bool,
    ) -> Option<Message> {
        for server in servers.iter() {
            match request(server, req, Duration::from_secs(15)).await {
                Ok(r) => {
                    debug!("query from {:?} ok", server);
                    if all_china {
                        // reject answers of china ips
                        for next in r.answers().filter(|it| it.kind() == Kind::A) {
                            if let Ok(RData::A(a)) = next.rdata() {
                                if !Self::is_china(geoip, a.ipaddr()) {
                                    return None;
                                }
                            }
                        }
                    }
                    return Some(r);
                }
                Err(e) => {
                    let mut domain = SmallVec::<[u8; 64]>::new();

                    if let Some(question) = req.questions().next() {
                        for (i, b) in question.name().enumerate() {
                            if i != 0 {
                                domain.push(b'.');
                            }
                            domain.extend_from_slice(b);
                        }
                    }

                    warn!(
                        "failed to query '{}' from {:?}: {}",
                        unsafe { std::str::from_utf8_unchecked(&domain[..]) },
                        server,
                        e
                    );
                }
            }
        }
        None
    }

    #[inline(always)]
    fn is_china(geoip: &Reader<Vec<u8>>, addr: Ipv4Addr) -> bool {
        let mut is_china = false;
        if let Ok(country) = geoip.lookup::<maxminddb::geoip2::Country>(IpAddr::V4(addr)) {
            if let Some(country) = country.country {
                is_china = matches!(country.iso_code, Some("CN"));
            }
        }
        debug!("{:?}: is_china={}", addr, is_china);
        is_china
    }
}

#[async_trait]
impl Filter for ChinaDNSFilter {
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> Result<()> {
        if res.is_none() {
            let (tx, mut rx) = mpsc::channel::<(bool, Message)>(1);

            let trusted = Clone::clone(&self.trusted);
            let mistrusted = Clone::clone(&self.mistrusted);

            // resolve from mistrusted dns
            {
                let msg = Clone::clone(req);
                let geoip = Clone::clone(&self.geoip);
                let tx = Clone::clone(&tx);
                tokio::spawn(async move {
                    if let Some(msg) = Self::request(&msg, &mistrusted, &geoip, true).await {
                        tx.send((true, msg)).await.ok();
                    }
                });
            }

            // resolve from trusted dns
            {
                let msg = Clone::clone(req);
                let geoip = Clone::clone(&self.geoip);
                tokio::spawn(async move {
                    if let Some(msg) = Self::request(&msg, &trusted, &geoip, false).await {
                        tx.send((false, msg)).await.ok();
                    }
                });
            }

            if let Some((china, msg)) = rx.recv().await {
                res.replace(msg);
            }
        }

        handle_next(self.next.as_deref(), ctx, req, res).await
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub(crate) struct ChinaDNSFilterFactory {
    trusted: Arc<Vec<DNS>>,
    mistrusted: Arc<Vec<DNS>>,
    geoip: Arc<Reader<Vec<u8>>>,
}

impl TryFrom<&Options> for ChinaDNSFilterFactory {
    type Error = anyhow::Error;

    fn try_from(opts: &Options) -> std::result::Result<Self, Self::Error> {
        const KEY_TRUSTED: &str = "trusted";
        const KEY_MISTRUSTED: &str = "mistrusted";
        const KEY_GEOIP_DATABASE: &str = "geoip_database";

        let r = OptionsReader::from(opts);

        let trusted = {
            r.get_addrs(KEY_TRUSTED)?
                .ok_or(anyhow!("invalid property '{}'", KEY_TRUSTED))?
        };
        let mistrusted = {
            r.get_addrs(KEY_MISTRUSTED)?
                .ok_or(anyhow!("invalid property '{}'", KEY_MISTRUSTED))?
        };

        let path = opts
            .get(KEY_GEOIP_DATABASE)
            .map(|it| it.as_str())
            .ok_or(anyhow!("invalid property '{}'", KEY_GEOIP_DATABASE))?
            .ok_or(anyhow!("invalid property '{}'", KEY_GEOIP_DATABASE))?;

        Ok(Self {
            trusted: Arc::new(trusted),
            mistrusted: Arc::new(mistrusted),
            geoip: Arc::new(maxminddb::Reader::open_readfile(path)?),
        })
    }
}

impl FilterFactory for ChinaDNSFilterFactory {
    type Item = ChinaDNSFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(ChinaDNSFilter {
            trusted: Clone::clone(&self.trusted),
            mistrusted: Clone::clone(&self.mistrusted),
            next: None,
            geoip: Clone::clone(&self.geoip),
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
    async fn test_chinadns() -> Result<()> {
        init();

        let opts = toml::from_str::<Options>(
            r#"
        trusted = ["tcp://8.8.8.8"]
        mistrusted = ["223.5.5.5"]
        geoip_database = "GeoLite2-Country.mmdb"
        "#,
        )?;

        let factory = ChinaDNSFilterFactory::try_from(&opts)?;
        let mut ctx = Context::default();

        let show = |msg: &Message| {
            for next in msg.answers() {
                info!(
                    "answer: domain={}, rdata={}",
                    next.name(),
                    next.rdata().unwrap(),
                );
            }
        };

        {
            let f = factory.get()?;
            let mut req = {
                // type=A domain=baidu.com
                let baidu =
                    "16060120000100000000000105626169647503636f6d00000100010000291000000000000000";
                let raw = hex::decode(baidu)?;
                Message::from(Bytes::from(raw))
            };
            let mut resp = None;

            let res = f.handle(&mut ctx, &mut req, &mut resp).await;

            assert!(res.is_ok());
            assert!(resp.is_some_and(|it| {
                show(&it);
                true
            }));
        }

        {
            let f = factory.get()?;

            let mut req = {
                // type=A domain=google.com
                let google = "ca580120000100000000000106676f6f676c6503636f6d00000100010000291000000000000000";
                let raw = hex::decode(google)?;
                Message::from(Bytes::from(raw))
            };
            let mut resp = None;

            let res = f.handle(&mut ctx, &mut req, &mut resp).await;

            assert!(res.is_ok());
            assert!(resp.is_some_and(|it| {
                show(&it);
                true
            }));
        }

        Ok(())
    }
}
