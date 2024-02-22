use std::time::Instant;

use async_trait::async_trait;
use moka::future::Cache;

use crate::protocol::Message;

use super::CacheStore;

#[derive(Clone)]
pub(crate) struct InMemoryCache {
    cache: Cache<Message, (Instant, Message)>,
}

impl InMemoryCache {
    pub(crate) fn builder() -> CacheStoreBuilder {
        CacheStoreBuilder { capacity: 1000 }
    }
}

#[async_trait]
impl CacheStore for InMemoryCache {
    async fn get(&self, req: &Message) -> Option<(Instant, Message)> {
        self.cache.get(req).await
    }

    async fn set(&self, req: &Message, resp: &Message) {
        let key = Clone::clone(req);
        let val = Clone::clone(resp);
        self.cache.insert(key, (Instant::now(), val)).await;
    }

    async fn remove(&self, req: &Message) {
        let _ = self.cache.remove(req).await;
    }
}

pub(crate) struct CacheStoreBuilder {
    capacity: usize,
}

impl CacheStoreBuilder {
    pub(crate) fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub(crate) fn build(self) -> InMemoryCache {
        let Self { capacity } = self;
        let cache = Cache::builder().max_capacity(capacity as u64).build();

        InMemoryCache { cache }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_get_and_set() {
        init();

        let req = {
            let raw = hex::decode(
                "f2500120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )
            .unwrap();
            Message::from(raw)
        };

        let res = {
            let raw = hex::decode("f2508180000100020000000105626169647503636f6d0000010001c00c00010001000000b70004279c420ac00c00010001000000b700046ef244420000290580000000000000").unwrap();
            Message::from(raw)
        };

        let cs = InMemoryCache::builder().capacity(100).build();
        assert!(cs.get(&req).await.is_none());

        cs.set(&req, &res).await;

        assert!(cs.get(&req).await.is_some_and(|(created_at, msg)| {
            let elapsed = Instant::now().duration_since(created_at);
            info!("elapsed: {:?}", elapsed);
            &res == &msg
        }));
    }
}
