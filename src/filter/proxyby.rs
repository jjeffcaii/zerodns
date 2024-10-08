use std::sync::Arc;

use crate::client::request;
use async_trait::async_trait;

use crate::filter::misc::OptionsReader;
use crate::protocol::{Message, DNS};
use crate::Result;

use super::{handle_next, Context, Filter, FilterFactory, Options};

#[derive(Default)]
pub(crate) struct ProxyByFilter {
    servers: Arc<Vec<DNS>>,
    next: Option<Box<dyn Filter>>,
}

#[async_trait]
impl Filter for ProxyByFilter {
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> Result<()> {
        if res.is_none() {
            for dns in self.servers.iter() {
                if let Ok(msg) = request(dns, req).await {
                    if log_enabled!(log::Level::Debug) {
                        for (i, question) in req.questions().enumerate() {
                            debug!(
                                "proxyby#{} ok: server={:?}, name={}",
                                i,
                                dns,
                                question.name()
                            );
                        }
                    }

                    res.replace(msg);
                    break;
                }
            }
        }

        handle_next(self.next.as_deref(), ctx, req, res).await
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
            servers: Clone::clone(&self.servers),
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
        let mut res = None;

        let opts = toml::from_str::<Options>(
            r#"
        servers = ["223.5.5.5"]
        "#,
        )
        .unwrap();

        let factory = ProxyByFilterFactory::try_from(&opts).unwrap();
        let f = factory.get().unwrap();
        let resp = f.handle(&mut ctx, &mut req, &mut res).await;

        assert!(resp.is_ok());
        assert!(res.is_some());
    }
}
