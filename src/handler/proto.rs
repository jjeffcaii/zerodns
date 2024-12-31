use crate::filter::Context;
use crate::protocol::Message;
use crate::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, ctx: &mut Context, request: &mut Message) -> Result<Option<Message>>;
}
