use async_trait::async_trait;

use crate::protocol::Message;
use crate::Result;

#[derive(Debug, Default)]
pub struct Context {}

#[async_trait]
pub trait Filter: Send + Sync + 'static {
    /// handle request
    async fn on_request(&self, ctx: &mut Context, req: &mut Message) -> Result<Option<Message>>;

    /// handle response
    async fn on_response(&self, ctx: &mut Context, res: &mut Option<Message>) -> Result<()>;

    /// set next filter
    fn set_next(&mut self, next: Box<dyn Filter>);
}
