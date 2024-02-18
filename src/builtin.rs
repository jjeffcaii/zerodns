use crate::filter::{
    register, ChinaDNSFilterFactory, NoopFilter, NoopFilterFactory, Options, ProxyByFilterFactory,
};

pub(crate) fn init() {
    register("noop", |opts: &Options| {
        NoopFilter::reset();
        Ok(NoopFilterFactory::try_from(opts).unwrap())
    });
    register("proxyby", |opts: &Options| {
        ProxyByFilterFactory::try_from(opts)
    });
    register("chinadns", |opts: &Options| {
        ChinaDNSFilterFactory::try_from(opts)
    });
}
