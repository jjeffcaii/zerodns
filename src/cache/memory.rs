use crate::cache::{Loader, LoadingCache};
use crate::protocol::Message;
use crate::Result;
use async_trait::async_trait;
use moka::future::Cache;
use std::time::{Duration, Instant};

type Key = [u8; 32];

pub(crate) struct MemoryLoadingCacheBuilder {
    capacity: usize,
    ttl: Option<Duration>,
}

impl MemoryLoadingCacheBuilder {
    pub(crate) fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub(crate) fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl.replace(ttl);
        self
    }

    pub(crate) fn build(self) -> MemoryLoadingCache {
        let Self { ttl, capacity } = self;

        let mut bu = Cache::builder().max_capacity(capacity as u64);

        if let Some(ttl) = ttl {
            bu = bu.time_to_live(ttl);
        }

        MemoryLoadingCache(bu.build())
    }
}

pub(crate) struct MemoryLoadingCache(Cache<Key, (Instant, Message)>);

impl Default for MemoryLoadingCache {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl MemoryLoadingCache {
    pub(crate) const DEFAULT_CAPACITY: usize = 1000;

    pub(crate) fn builder() -> MemoryLoadingCacheBuilder {
        MemoryLoadingCacheBuilder {
            capacity: Self::DEFAULT_CAPACITY,
            ttl: None,
        }
    }

    #[inline(always)]
    fn generate_key(req: &Message) -> Key {
        use sha2::{Digest, Sha256};

        let mut h = Sha256::new();
        h.update(&req.0[2..]);
        h.finalize().into()
    }
}

#[async_trait]
impl LoadingCache for MemoryLoadingCache {
    async fn load<L>(&self, req: Message, fut: L) -> Result<(Instant, Message)>
    where
        L: Loader,
    {
        let id = req.id();
        let key = Self::generate_key(&req);
        let (created_at, mut res) = self
            .0
            .try_get_with(key, async {
                fut.load(req).await.map(|it| (Instant::now(), it))
            })
            .await
            .map_err(|e| anyhow!("failed to loading result from cache: {:?}", e))?;

        // reset id
        res.set_id(id);

        Ok((created_at, res))
    }

    async fn remove(&self, req: &Message) {
        let key = Self::generate_key(req);
        self.0.invalidate(&key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Class, Flags, Kind, RCode};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_load() {
        let id = 0x3344u16;

        let req = Message::builder()
            .flags(Flags::request())
            .id(id)
            .question("www.youtube.com", Kind::A, Class::IN)
            .build()
            .unwrap();

        let cache = MemoryLoadingCache::builder().build();

        let calls: Arc<AtomicUsize> = Default::default();

        let fut = || {
            let calls = Clone::clone(&calls);
            let req = Clone::clone(&req);
            move |req| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let flags = Flags::builder()
                    .response()
                    .rcode(RCode::NotImplemented)
                    .build();
                Message::builder().flags(flags).build()
            }
        };

        // call twice
        for _ in 0..2 {
            let req = Clone::clone(&req);
            let result = cache.load(req, fut()).await;
            assert!(result.is_ok_and(|(created_at, msg)| {
                RCode::NotImplemented == msg.flags().response_code() && id == msg.id()
            }));
        }

        // but calls only one time
        assert_eq!(1, calls.load(Ordering::SeqCst));

        cache.remove(&req).await;

        // call again
        {
            let req = Clone::clone(&req);
            let result = cache.load(req, fut()).await;
            assert!(result.is_ok_and(|(created_at, msg)| {
                RCode::NotImplemented == msg.flags().response_code() && id == msg.id()
            }));
        }

        // should be twice because cache item has been removed already
        assert_eq!(2, calls.load(Ordering::SeqCst));
    }
}
