use std::collections::VecDeque;

use async_trait::async_trait;

use crate::filter::{Context, Filter, Options};
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
        let mut res = self.filter.on_request(&mut ctx, req).await?;
        self.filter.on_response(&mut ctx, &mut res).await?;
        Ok(res)
    }
}

pub(crate) struct FilteredHandlerBuilder {
    filters: VecDeque<Box<dyn Filter>>,
}

impl FilteredHandlerBuilder {
    pub(crate) fn append<T>(self, next: T) -> Self
    where
        T: Filter,
    {
        self.append_boxed(Box::new(next))
    }

    pub(crate) fn append_with<S>(self, name: S, opts: &Options) -> Self
    where
        S: AsRef<str>,
    {
        let name = name.as_ref();
        match crate::filter::load(name, opts) {
            Ok(f) => match f.get_boxed() {
                Ok(v) => self.append_boxed(v),
                Err(e) => {
                    error!("failed to append filter '{}': {:?}", name, e);
                    self
                }
            },
            Err(e) => {
                error!("failed to append filter '{}': {:?}", name, e);
                self
            }
        }
    }

    pub(crate) fn append_boxed(mut self, next: Box<dyn Filter>) -> Self {
        self.filters.push_back(next);
        self
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
        async fn on_request(
            &self,
            ctx: &mut Context,
            req: &mut Message,
        ) -> Result<Option<Message>> {
            info!("{} on_request called", self.id);
            match &self.next {
                None => Ok(None),
                Some(f) => f.on_request(ctx, req).await,
            }
        }

        async fn on_response(&self, ctx: &mut Context, res: &mut Option<Message>) -> Result<()> {
            info!("{} on_response called", self.id);
            match &self.next {
                None => Ok(()),
                Some(f) => f.on_response(ctx, res).await,
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
