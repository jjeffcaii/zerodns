use std::collections::VecDeque;

use async_trait::async_trait;

use crate::filter::{Context, Filter};
use crate::handler::Handler;
use crate::protocol::Message;
use crate::Result;

pub(crate) struct FilteredHandler {
    filter: Box<dyn Filter>,
}

impl FilteredHandler {
    pub(crate) fn builder() -> FilteredHandlerBuilder {
        FilteredHandlerBuilder {
            filters: Default::default(),
        }
    }
}

#[async_trait]
impl Handler for FilteredHandler {
    async fn handle(&self, req: &mut Message) -> Result<Option<Message>> {
        let mut ctx = Context::default();
        let mut resp = None;
        self.filter.handle(&mut ctx, req, &mut resp).await?;
        Ok(resp)
    }
}

pub(crate) struct FilteredHandlerBuilder {
    filters: VecDeque<Box<dyn Filter>>,
}

impl FilteredHandlerBuilder {
    pub(crate) fn append<T>(mut self, next: T) -> Self
    where
        T: Filter,
    {
        self.append_boxed(Box::new(next));
        self
    }

    pub(crate) fn append_boxed(&mut self, next: Box<dyn Filter>) {
        self.filters.push_back(next);
    }

    pub(crate) fn build(self) -> Option<FilteredHandler> {
        let Self { mut filters } = self;

        match filters.pop_front() {
            None => None,
            Some(mut root) => {
                while let Some(next) = filters.pop_back() {
                    match filters.back_mut() {
                        None => root.set_next(next),
                        Some(parent) => parent.set_next(next),
                    }
                }

                Some(FilteredHandler { filter: root })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    struct MockFilter {
        id: usize,
        next: Option<Box<dyn Filter>>,
    }

    impl MockFilter {
        fn new(id: usize) -> MockFilter {
            Self { id, next: None }
        }
    }

    #[async_trait::async_trait]
    impl Filter for MockFilter {
        async fn handle(
            &self,
            ctx: &mut Context,
            req: &mut Message,
            res: &mut Option<Message>,
        ) -> Result<()> {
            info!("{} handle called", self.id);
            match &self.next {
                None => Ok(()),
                Some(f) => f.handle(ctx, req, res).await,
            }
        }

        fn set_next(&mut self, next: Box<dyn Filter>) {
            self.next.replace(next);
        }
    }

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_filtered_handler() {
        init();

        let mut req = {
            let raw = hex::decode(
                "128e0120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )
            .unwrap();
            Message::from(Bytes::from(raw))
        };

        let h = FilteredHandler::builder()
            .append(MockFilter::new(1))
            .append(MockFilter::new(2))
            .append(MockFilter::new(3))
            .build()
            .unwrap();

        let res = h.handle(&mut req).await;
        assert!(res.is_ok_and(|it| it.is_none()));
    }
}
