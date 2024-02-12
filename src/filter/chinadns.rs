use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use maxminddb::Reader;
use smallvec::SmallVec;

use crate::filter::misc::OptionsReader;
use crate::protocol::{Message, Type, DNS};
use crate::Result;

use super::{Context, Filter, FilterFactory, Options};

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
            if let Ok(r) = server.request(req).await {
                if all_china {
                    for next in r.answers().filter(|it| it.typ() == Type::A) {
                        let data = next.data();
                        let mut v4 = [0u8; 4];
                        (0..4).for_each(|i| v4[i] = data[i]);
                        let addr = IpAddr::V4(Ipv4Addr::from(v4));

                        if !Self::is_china(geoip, &addr) {
                            return None;
                        }
                    }
                }

                return Some(r);
            }
        }
        None
    }

    fn is_china(geoip: &Reader<Vec<u8>>, addr: &IpAddr) -> bool {
        let mut is_china = false;
        if let Ok(country) = geoip.lookup::<maxminddb::geoip2::Country>(Clone::clone(addr)) {
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
    async fn on_request(&self, ctx: &mut Context, req: &mut Message) -> Result<Option<Message>> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(bool, Message)>(1);

        let trusted = Clone::clone(&self.trusted);
        let mistrusted = Clone::clone(&self.mistrusted);

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

        {
            let msg = Clone::clone(req);
            let geoip = Clone::clone(&self.geoip);
            tokio::spawn(async move {
                if let Some(msg) = Self::request(&msg, &trusted, &geoip, false).await {
                    tx.send((false, msg)).await.ok();
                }
            });
        }

        let mut domain = SmallVec::<[u8; 64]>::new();
        for (i, b) in req.questions().next().unwrap().name().enumerate() {
            if i != 0 {
                domain.push(b'.');
            }
            domain.extend_from_slice(b);
        }

        match rx.recv().await {
            Some((china, msg)) => {
                info!(
                    "{}: oversea={}",
                    String::from_utf8_lossy(&domain[..]),
                    !china
                );
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    async fn on_response(&self, ctx: &mut Context, res: &mut Option<Message>) -> Result<()> {
        match &self.next {
            None => Ok(()),
            Some(next) => next.on_response(ctx, res).await,
        }
    }

    fn next(&self) -> Option<&dyn Filter> {
        self.next.as_deref()
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
            let addrs = r
                .get_addrs(KEY_TRUSTED)?
                .ok_or(anyhow!("invalid property '{}'", KEY_TRUSTED))?;
            let mut v = vec![];
            for addr in addrs {
                v.push(DNS::UDP(addr));
            }
            v
        };
        let mistrusted = {
            let addrs = r
                .get_addrs(KEY_MISTRUSTED)?
                .ok_or(anyhow!("invalid property '{}'", KEY_MISTRUSTED))?;
            let mut v = vec![];
            for addr in addrs {
                v.push(DNS::UDP(addr));
            }
            v
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
    use smallvec::SmallVec;

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_chinadns() -> Result<()> {
        init();

        let opts = toml::from_str::<Options>(
            r#"
        trusted = ["8.8.8.8","8.8.4.4"]
        mistrusted = ["223.5.5.5","223.6.6.6"]
        geoip_database = "GeoLite2-Country.mmdb"
        "#,
        )?;

        let factory = ChinaDNSFilterFactory::try_from(&opts)?;
        let mut ctx = Context::default();

        let show = |msg: &Message| {
            for next in msg.answers() {
                let data = next.data();
                let mut v4 = [0u8; 4];
                (0..4).for_each(|i| v4[i] = data[i]);
                let addr = Ipv4Addr::from(v4);

                let mut v = SmallVec::<[u8; 64]>::new();
                for (i, b) in next.name().enumerate() {
                    if i != 0 {
                        v.push(b'.');
                    }
                    v.extend_from_slice(b);
                }

                info!(
                    "answer: domain={}, address={:?}",
                    String::from_utf8_lossy(&v[..]),
                    &addr
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

            let res = f.on_request(&mut ctx, &mut req).await?;

            assert!(res.is_some_and(|it| {
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

            let res = f.on_request(&mut ctx, &mut req).await?;

            assert!(res.is_some_and(|res| {
                show(&res);
                true
            }));
        }

        Ok(())
    }
}
