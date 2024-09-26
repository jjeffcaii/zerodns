use async_trait::async_trait;

use crate::protocol::Message;
use crate::Result;

#[derive(Debug, Default)]
pub struct Context {}

#[async_trait]
pub trait Filter: Send + Sync + 'static {
    /// handle request
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> Result<()>;

    /// set next filter
    fn set_next(&mut self, next: Box<dyn Filter>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct AlwaysNoneFilter;

    #[async_trait]
    impl Filter for AlwaysNoneFilter {
        async fn handle(
            &self,
            ctx: &mut Context,
            req: &mut Message,
            res: &mut Option<Message>,
        ) -> Result<()> {
            Ok(())
        }

        fn set_next(&mut self, next: Box<dyn Filter>) {}
    }

    #[tokio::test]
    async fn test_filter() {
        let mut ctx = Context::default();
        let f = AlwaysNoneFilter::default();
        let mut req = Message::builder().build().unwrap();
        let mut res = None;

        {
            assert!(f.handle(&mut ctx, &mut req, &mut res).await.is_ok());
        }

        {
            let mut res = None;
            assert!(f.handle(&mut ctx, &mut req, &mut res).await.is_ok());
        }
    }
}
