use crate::filter::{register, ChinaDNSFilterFactory, Options, ProxyByFilterFactory};

pub(crate) fn init() {
    register("proxyby", |opts: &Options| {
        ProxyByFilterFactory::try_from(opts)
    });
    register("chinadns", |opts: &Options| {
        ChinaDNSFilterFactory::try_from(opts)
    });
}
