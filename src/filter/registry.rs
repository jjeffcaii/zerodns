use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;

use crate::filter::Filter;
use crate::Result;

// TODO: define options structure
pub type Options = HashMap<String, toml::Value>;

type Generator = Arc<dyn Send + Sync + Fn(&Options) -> Result<Box<dyn FilterFactoryExt>>>;

static FILTERS: Lazy<RwLock<HashMap<String, Generator>>> = Lazy::new(Default::default);

pub trait FilterFactory: Send + Sync + 'static {
    type Item;

    fn get(&self) -> Result<Self::Item>;
}

pub(crate) trait FilterFactoryExt: Send + Sync + 'static {
    fn get_boxed(&self) -> Result<Box<dyn Filter>>;
}

impl<T, F> FilterFactoryExt for F
where
    T: Filter,
    F: FilterFactory<Item = T>,
{
    fn get_boxed(&self) -> Result<Box<dyn Filter>> {
        Ok(Box::new(self.get()?))
    }
}

pub fn register<S, G, F, T>(name: S, gen: G)
where
    S: Into<String>,
    G: 'static + Sync + Send + Fn(&Options) -> Result<F>,
    F: FilterFactory<Item = T>,
    T: Filter,
{
    let name = name.into();

    // wrap into generator function
    let wrapper = move |opts: &Options| -> Result<Box<dyn FilterFactoryExt>> {
        let f = gen(opts)?;
        // convert to boxed trait
        let f: Box<dyn FilterFactoryExt> = Box::new(f);
        Ok(f)
    };

    let mut w = FILTERS.write();
    w.insert(name, Arc::new(wrapper));
}

pub(crate) fn load<S>(name: S, opts: &Options) -> Result<Box<dyn FilterFactoryExt>>
where
    S: AsRef<str>,
{
    let name = name.as_ref();
    let g = {
        let r = FILTERS.read();
        r.get(name).cloned()
    };

    match g {
        None => bail!("no filter '{}' found", name),
        Some(f) => f(opts),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use crate::filter::Context;
    use crate::protocol::Message;

    use super::*;

    struct MockFilter {}

    #[async_trait]
    impl Filter for MockFilter {
        async fn on_request(
            &self,
            ctx: &mut Context,
            req: &mut Message,
        ) -> Result<Option<Message>> {
            Ok(None)
        }

        async fn on_response(&self, ctx: &mut Context, res: &mut Option<Message>) -> Result<()> {
            Ok(())
        }

        fn set_next(&mut self, _: Box<dyn Filter>) {}
    }

    struct MockFilterFactory {}

    impl FilterFactory for MockFilterFactory {
        type Item = MockFilter;

        fn get(&self) -> Result<Self::Item> {
            Ok(MockFilter {})
        }
    }

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[test]
    fn test_register() {
        init();

        register("foobar", |opts: &Options| Ok(MockFilterFactory {}));
        let res = load("foobar", &Default::default());
        assert!(res.is_ok_and(|g| g.get_boxed().is_ok()));
    }
}
