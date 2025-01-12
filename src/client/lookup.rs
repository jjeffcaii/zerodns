use super::Client;
use super::SYSTEM_CLIENT;
use crate::cachestr::Cachestr;
use crate::protocol::{Class, Flags, Kind, Message, OpCode, RData};
use crate::{Error, Result};
use hashbrown::HashMap;
use moka::future::Cache;
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use std::net::Ipv4Addr;
use std::time::Duration;

pub(super) type LookupIpv4Addrs = SmallVec<[Ipv4Addr; 2]>;

static PRESENT_HOSTS_V4: Lazy<HashMap<Cachestr, LookupIpv4Addrs>> = Lazy::new(|| {
    let mut all = HashMap::<Cachestr, LookupIpv4Addrs>::new();

    for (k, v) in [
        ("dns.google", "8.8.8.8,8.8.4.4"),
        ("one.one.one.one", "1.1.1.1,1.0.0.1"),
        ("dot.pub", "1.12.12.12,120.53.53.53"),
        ("dns.alidns.com", "223.5.5.5,223.6.6.6"),
        ("dns.quad9.net", "9.9.9.9,149.112.112.112"),
    ] {
        let mut vals = LookupIpv4Addrs::new();
        for it in v.split(',') {
            if let Ok(addr) = it.trim().parse::<Ipv4Addr>() {
                vals.push(addr);
            }
        }
        all.insert(Cachestr::from(k), vals);
    }

    all
});

impl From<Cache<Cachestr, LookupIpv4Addrs>> for LookupCache {
    fn from(value: Cache<Cachestr, LookupIpv4Addrs>) -> Self {
        Self(value)
    }
}

pub(super) struct LookupCache(Cache<Cachestr, LookupIpv4Addrs>);

impl LookupCache {
    pub(super) async fn lookup(&self, host: &str, timeout: Duration) -> Result<Ipv4Addr> {
        let key = Cachestr::from(host);

        let res = match PRESENT_HOSTS_V4.get(&key) {
            None => self
                .0
                .try_get_with(key, Self::lookup_(host, timeout))
                .await
                .map_err(|e| anyhow!("lookup failed: {}", e))?,
            Some(it) => Clone::clone(it),
        };

        if let Some(first) = res.first() {
            return Ok(Clone::clone(first));
        }

        bail!(Error::ResolveNothing)
    }

    #[inline]
    async fn lookup_(host: &str, timeout: Duration) -> Result<SmallVec<[Ipv4Addr; 2]>> {
        let flags = Flags::builder()
            .request()
            .recursive_query(true)
            .opcode(OpCode::StandardQuery)
            .build();

        let id = {
            use rand::prelude::*;

            let mut rng = thread_rng();
            rng.gen_range(1..u16::MAX)
        };

        let req0 = Message::builder()
            .id(id)
            .flags(flags)
            .question(host, Kind::A, Class::IN)
            .build()?;

        let mut ret = LookupIpv4Addrs::new();

        let sys = SYSTEM_CLIENT.load();
        let v = sys.request(&req0).await?;
        for next in v.answers() {
            if let Ok(RData::A(a)) = next.rdata() {
                ret.push(a.ipaddr());
            }
        }

        if !ret.is_empty() {
            return Ok(ret);
        }

        bail!(Error::ResolveNothing)
    }
}
