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
        let key = Clone::clone(req);
        let val = Clone::clone(resp);

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

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

        let cs = CacheStore::builder().ttl(2).capacity(100).build();
        assert!(cs.get(&req).await.is_none());

        cs.set(&req, &res).await;

        let is_expired = |expired_at: Instant| {
            let ttl = expired_at.duration_since(Instant::now());
            info!("ttl: {:?}", ttl);
            ttl <= Duration::ZERO
        };

        assert!(cs.get(&req).await.is_some_and(|(expired_at, msg)| {
            assert_eq!(&res, &msg);
            !is_expired(expired_at)
        }));

        sleep(Duration::from_secs(2)).await;

        assert!(cs.get(&req).await.is_some_and(|(expired_at, msg)| {
            assert_eq!(&res, &msg);
            is_expired(expired_at)
        }));
    }
}
