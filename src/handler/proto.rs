use async_trait::async_trait;

use crate::protocol::Message;
use crate::Result;

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: &mut Message) -> Result<Option<Message>>;
}
