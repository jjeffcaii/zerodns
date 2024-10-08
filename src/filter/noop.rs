use std::sync::atomic::{AtomicU64, Ordering};

use crate::Result;
use async_trait::async_trait;
use once_cell::sync::Lazy;

use crate::filter::{handle_next, Context, FilterFactory, Options};
use crate::protocol::Message;

use super::proto::Filter;

static NOOP_SEQ: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));

#[derive(Default)]
pub(crate) struct NoopFilter {
    next: Option<Box<dyn Filter>>,
}

impl NoopFilter {
    pub(crate) fn reset() {
        let seq = &*NOOP_SEQ;
        seq.store(0, Ordering::SeqCst);
    }

    pub(crate) fn requests() -> u64 {
        let seq = &*NOOP_SEQ;
        seq.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Filter for NoopFilter {
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> Result<()> {
        let seq = &*NOOP_SEQ;

        let cnt = seq.fetch_add(1, Ordering::SeqCst) + 1;
        info!("call 'handle' from noop filter ok: cnt={}", cnt);

        handle_next(self.next.as_deref(), ctx, req, res).await
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub(crate) struct NoopFilterFactory;

impl FilterFactory for NoopFilterFactory {
    type Item = NoopFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(Default::default())
    }
}

impl TryFrom<&Options> for NoopFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> std::result::Result<Self, Self::Error> {
        Ok(NoopFilterFactory)
    }
}
