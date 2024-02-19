use std::sync::Arc;

use async_trait::async_trait;

use crate::filter::misc::OptionsReader;
use crate::protocol::{Message, DNS};
use crate::Result;

use super::{Context, Filter, FilterFactory, Options};

#[derive(Default)]
pub(crate) struct ProxyByFilter {
    upstreams: Arc<Vec<DNS>>,
    next: Option<Box<dyn Filter>>,
}

#[async_trait]
impl Filter for ProxyByFilter {
    async fn on_request(&self, _: &mut Context, req: &mut Message) -> Result<Option<Message>> {
        for addr in self.upstreams.iter() {
            if let Ok(res) = addr.request(req).await {
                if log_enabled!(log::Level::Debug) {
                    for (i, question) in req.questions().enumerate() {
                        debug!(
                            "proxyby#{} ok: server={:?}, name={}",
                            i,
                            addr,
                            question.name()
                        );
                    }
                }
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    fn next(&self) -> Option<&dyn Filter> {
        self.next.as_deref()
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub(crate) struct ProxyByFilterFactory {
    servers: Arc<Vec<DNS>>,
}

impl TryFrom<&Options> for ProxyByFilterFactory {
    type Error = anyhow::Error;

    fn try_from(opts: &Options) -> std::result::Result<Self, Self::Error> {
        const KEY_SERVERS: &str = "servers";

        let servers = OptionsReader::from(opts)
            .get_addrs(KEY_SERVERS)?
            .ok_or(anyhow!("invalid format of property '{}'", KEY_SERVERS))?;

        Ok(Self {
            servers: Arc::new(servers),
        })
    }
}

impl FilterFactory for ProxyByFilterFactory {
    type Item = ProxyByFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(ProxyByFilter {
            upstreams: Clone::clone(&self.servers),
            next: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::filter::FilterFactoryExt;

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

        let opts = toml::from_str::<Options>(
            r#"
        servers = ["223.5.5.5"]
        "#,
        )
        .unwrap();

        let factory = ProxyByFilterFactory::try_from(&opts).unwrap();
        let mut f = factory.get().unwrap();
        let resp = f.on_request(&mut ctx, &mut req).await;

        assert!(resp.is_ok_and(|res| res.is_some_and(|record| {
            info!("got: {}", record.id());
            true
        })));

        assert!(f.next().is_none());
        f.set_next(factory.get_boxed().unwrap());
        assert!(f.next().is_some());
    }
}
