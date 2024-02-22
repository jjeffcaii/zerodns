use std::time::Instant;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use smallvec::SmallVec;

pub(crate) use memory::InMemoryCache;

use crate::protocol::Message;

mod memory;

#[async_trait]
pub trait CacheStore: Send + Sync + 'static {
    async fn get(&self, req: &Message) -> Option<(Instant, Message)>;

    async fn set(&self, req: &Message, resp: &Message);

    async fn remove(&self, req: &Message);
}

#[async_trait]
pub(crate) trait CacheStoreExt {
    async fn get_fixed(&self, req: &Message) -> Option<Message>;
}

#[async_trait]
impl<A> CacheStoreExt for A
where
    A: CacheStore,
{
    async fn get_fixed(&self, req: &Message) -> Option<Message> {
        match self.get(req).await {
            Some((created_at, mut msg)) => {
                let elapsed = Instant::now().duration_since(created_at).as_secs();

                let mut rewrites = SmallVec::<[(u16, u32); 4]>::new();

                for next in msg.answers() {
                    let ttl = next.time_to_live();
                    let ttl = (ttl as i64) - (elapsed as i64);
                    if ttl <= 0 {
                        self.remove(req).await;
                        return None;
                    }
                    rewrites.push((next.time_to_live_pos() as u16, ttl as u32));
                }

                // rewrite ttl
                for (pos, ttl) in rewrites {
                    BigEndian::write_u32(&mut msg.0[pos as usize..], ttl);
                }

                Some(msg)
            }
            None => None,
        }
    }
}
