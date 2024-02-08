use crate::filter::{register, ChinaDNSFilterFactory, Options, ProxyByFilterFactory};

pub(crate) fn init() {
    register("proxyby", |opts: &Options| ProxyByFilterFactory::new(opts));
    register("chinadns", |opts: &Options| {
        Ok(ChinaDNSFilterFactory::new(opts))
    });
}
