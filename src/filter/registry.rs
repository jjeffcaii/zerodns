use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;

use crate::filter::Filter;
use crate::Result;

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
    use super::*;
    use crate::filter::Context;
    use crate::protocol::Message;
    use async_trait::async_trait;

    #[derive(Default)]
    struct MockFilter {
        next: Option<Box<dyn Filter>>,
    }

    #[async_trait]
    impl Filter for MockFilter {
        async fn handle(
            &self,
            ctx: &mut Context,
            req: &mut Message,
            res: &mut Option<Message>,
        ) -> Result<()> {
            match &self.next {
                None => Ok(()),
                Some(next) => next.handle(ctx, req, res).await,
            }
        }

        fn set_next(&mut self, next: Box<dyn Filter>) {
            self.next.replace(next);
        }
    }

    struct MockFilterFactory {}

    impl FilterFactory for MockFilterFactory {
        type Item = MockFilter;

        fn get(&self) -> Result<Self::Item> {
            Ok(Default::default())
        }
    }

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[test]
    fn test_register() {
        init();

        assert!(load("foobar", &Default::default()).is_err());

        register("foobar", |opts: &Options| Ok(MockFilterFactory {}));

        let res = load("foobar", &Default::default());
        assert!(res.is_ok_and(|g| g.get_boxed().is_ok()));
    }
}
