use async_trait::async_trait;

use crate::client::Client;
use crate::protocol::Message;
use crate::Result;

use super::{Context, Filter, FilterFactory, Options};

#[derive(Default)]
pub(crate) struct ProxyByFilter {
    next: Option<Box<dyn Filter>>,
}

#[async_trait]
impl Filter for ProxyByFilter {
    async fn on_request(&self, _ctx: &mut Context, req: &mut Message) -> Result<Option<Message>> {
        let mut c = Client::from("223.5.5.5:53");
        let resp = c.request(req).await?;
        Ok(Some(resp))
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

pub(crate) struct ProxyByFilterFactory {}

impl ProxyByFilterFactory {
    pub fn new(_opts: &Options) -> Self {
        Self {}
    }
}

impl FilterFactory for ProxyByFilterFactory {
    type Item = ProxyByFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(ProxyByFilter::default())
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
