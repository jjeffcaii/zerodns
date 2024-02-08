use async_trait::async_trait;

use crate::protocol::Message;
use crate::Result;

use super::{Context, Filter, FilterFactory, Options};

pub(crate) struct ChinaDNSFilter {}

#[async_trait]
impl Filter for ChinaDNSFilter {
    async fn on_request(&self, ctx: &mut Context, req: &mut Message) -> Result<Option<Message>> {
        todo!()
    }

    async fn on_response(&self, ctx: &mut Context, res: &mut Option<Message>) -> Result<()> {
        todo!()
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        todo!()
    }
}

pub(crate) struct ChinaDNSFilterFactory {}

impl ChinaDNSFilterFactory {
    pub fn new(_opts: &Options) -> Self {
        ChinaDNSFilterFactory {}
    }
}

impl FilterFactory for ChinaDNSFilterFactory {
    type Item = ChinaDNSFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(ChinaDNSFilter {})
    }
}
