use crate::Result;
use crate::filter::Context;
use crate::protocol::Message;
use async_trait::async_trait;

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, ctx: &mut Context, request: &mut Message) -> Result<Option<Message>>;
}
