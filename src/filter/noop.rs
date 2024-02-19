use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use once_cell::sync::Lazy;

use crate::filter::{Context, FilterFactory, Options};
use crate::protocol::Message;

use super::proto::Filter;

static NOOP_SEQ: Lazy<(AtomicU64, AtomicU64)> =
    Lazy::new(|| (AtomicU64::new(0), AtomicU64::new(0)));

#[derive(Default)]
pub(crate) struct NoopFilter {
    next: Option<Box<dyn Filter>>,
}

impl NoopFilter {
    pub(crate) fn reset() {
        let (req, res) = &*NOOP_SEQ;
        req.store(0, Ordering::SeqCst);
        res.store(0, Ordering::SeqCst);
    }

    pub(crate) fn requests() -> u64 {
        let (seq, _) = &*NOOP_SEQ;
        seq.load(Ordering::SeqCst)
    }

    pub(crate) fn responses() -> u64 {
        let (_, seq) = &*NOOP_SEQ;
        seq.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Filter for NoopFilter {
    async fn on_request(
        &self,
        ctx: &mut Context,
        req: &mut Message,
    ) -> crate::Result<Option<Message>> {
        let (seq, _) = &*NOOP_SEQ;

        let cnt = seq.fetch_add(1, Ordering::SeqCst) + 1;
        info!("call 'on_request' from noop filter ok: cnt={}", cnt);

        if let Some(next) = &self.next {
            return next.on_request(ctx, req).await;
        }

        Ok(None)
    }

    async fn on_response(&self, ctx: &mut Context, res: &mut Option<Message>) -> crate::Result<()> {
        let (_, seq) = &*NOOP_SEQ;

        let cnt = seq.fetch_add(1, Ordering::SeqCst) + 1;
        info!("call 'on_response' from noop filter ok: cnt={}", cnt);

        if let Some(next) = &self.next {
            return next.on_response(ctx, res).await;
        }

        Ok(())
    }

    fn next(&self) -> Option<&dyn Filter> {
        self.next.as_deref()
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub(crate) struct NoopFilterFactory;

impl FilterFactory for NoopFilterFactory {
    type Item = NoopFilter;

    fn get(&self) -> crate::Result<Self::Item> {
        Ok(Default::default())
    }
}

impl TryFrom<&Options> for NoopFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> Result<Self, Self::Error> {
        Ok(NoopFilterFactory)
    }
}
