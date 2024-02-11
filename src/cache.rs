use std::ops::Add;
use std::time::{Duration, Instant};

use moka::future::Cache;

use crate::protocol::Message;

#[derive(Clone)]
pub(crate) struct CacheStore {
    ttl: Duration,
    cache: Cache<Message, (Instant, Message)>,
}

impl CacheStore {
    pub(crate) fn builder() -> CacheStoreBuilder {
        CacheStoreBuilder {
            ttl: Duration::from_secs(3600),
            capacity: 1000,
        }
    }

    pub(crate) async fn get(&self, req: &Message) -> Option<(Instant, Message)> {
        self.cache.get(req).await
    }

    pub(crate) async fn set(&self, req: &Message, resp: &Message) {
        let mut key = Clone::clone(req);
        key.set_id(0);
        let mut val = Clone::clone(resp);
        val.set_id(0);

        let mut expired_at = Instant::now().add(self.ttl);

        for next in val.answers() {
            let t = Instant::now().add(Duration::from_secs(next.time_to_live() as u64));
            expired_at = expired_at.min(t);
        }

        self.cache.insert(key, (expired_at, val)).await;
    }
}

pub(crate) struct CacheStoreBuilder {
    ttl: Duration,
    capacity: usize,
}

impl CacheStoreBuilder {
    pub(crate) fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub(crate) fn ttl(mut self, ttl_secs: usize) -> Self {
        self.ttl = Duration::from_secs(ttl_secs as u64);
        self
    }

    pub(crate) fn build(self) -> CacheStore {
        let Self { ttl, capacity } = self;
        let cache = Cache::builder().max_capacity(capacity as u64).build();

        CacheStore { ttl, cache }
    }
}
