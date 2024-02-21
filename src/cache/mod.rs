use std::time::Instant;

use async_trait::async_trait;

pub(crate) use memory::InMemoryCache;

use crate::protocol::Message;

mod memory;

#[async_trait]
pub trait CacheStore: Send + Sync + 'static {
    async fn get(&self, req: &Message) -> Option<(Instant, Message)>;

    async fn set(&self, req: &Message, resp: &Message);
}
