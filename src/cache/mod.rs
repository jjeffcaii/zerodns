use std::time::Instant;

use crate::Result;
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
pub(crate) use memory::MemoryLoadingCache;
use smallvec::SmallVec;
use std::future::Future;

use crate::protocol::Message;

mod memory;

pub trait Loader: Send {
    fn load(self, req: Message) -> impl Future<Output = Result<Message>> + Send;
}

impl<A, T> Loader for A
where
    A: Send + FnOnce(Message) -> T,
    T: Send + Future<Output = Result<Message>>,
{
    fn load(self, req: Message) -> impl Future<Output = Result<Message>> + Send {
        self(req)
    }
}

#[async_trait]
pub trait LoadingCache: Send + Sync + 'static {
    async fn load<L>(&self, req: Message, fut: L) -> Result<(Instant, Message)>
    where
        L: Loader;

    async fn remove(&self, req: &Message);
}

#[async_trait]
pub(crate) trait LoadingCacheExt: Send + Sync + 'static {
    async fn try_get_with_fixed<L>(&self, req: Message, fut: L) -> Result<Message>
    where
        L: Loader;
}

#[async_trait]
impl<A> LoadingCacheExt for A
where
    A: LoadingCache,
{
    async fn try_get_with_fixed<L>(&self, req: Message, fut: L) -> Result<Message>
    where
        L: Loader,
    {
        // 1. compute the original cached value
        let (created_at, mut value) = self.load(Clone::clone(&req), fut).await?;

        // 2. compute the newest list of time-to-live
        let mut rewrites = SmallVec::<[(u16, u32); 4]>::new();
        let mut remove = false;
        let elapsed = Instant::now().duration_since(created_at).as_secs();
        for next in value.answers() {
            let mut ttl = (next.time_to_live() as i64) - (elapsed as i64);
            if ttl <= 0 {
                remove = true;
                ttl = 1; // 1s at least
            }
            rewrites.push((next.time_to_live_pos() as u16, ttl as u32));
        }

        // 3. remove expired cache
        if remove {
            self.remove(&req).await;
        }

        // 4. rewrite ttl
        for (pos, ttl) in rewrites {
            BigEndian::write_u32(&mut value.0[pos as usize..], ttl);
        }

        Ok(value)
    }
}
