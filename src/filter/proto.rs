use crate::protocol::Message;
use crate::Result;
use std::net::SocketAddr;

#[derive(Debug, Copy, Clone, Default, Hash, PartialEq, Eq)]
pub struct ContextFlags(u64);

bitflags! {
    impl ContextFlags: u64 {
        const NO_CACHE = 1 << 0;
    }
}

#[derive(Debug, Default)]
pub struct Context {
    pub flags: ContextFlags,
    pub(crate) peer: Option<SocketAddr>,
}

impl Context {
    pub fn client_addr(&self) -> SocketAddr {
        self.peer.unwrap()
    }
}

#[async_trait::async_trait]
pub trait Filter: Send + Sync + 'static {
    /// handle the request
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> Result<()>;

    /// set next filter
    fn set_next(&mut self, next: Box<dyn Filter>);
}

#[inline(always)]
pub(crate) async fn handle_next(
    next: Option<&dyn Filter>,
    ctx: &mut Context,
    req: &mut Message,
    res: &mut Option<Message>,
) -> Result<()> {
    match next {
        None => Ok(()),
        Some(next) => next.handle(ctx, req, res).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct AlwaysNoneFilter;

    #[async_trait::async_trait]
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
