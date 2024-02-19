use async_trait::async_trait;

use crate::filter::{FilterFactory, Options};

use super::proto::Filter;

#[derive(Default)]
pub(crate) struct LuaFilter {
    next: Option<Box<dyn Filter>>,
}

#[async_trait]
impl Filter for LuaFilter {
    fn next(&self) -> Option<&dyn Filter> {
        self.next.as_deref()
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub(crate) struct LuaFilterFactory {}

impl FilterFactory for LuaFilterFactory {
    type Item = LuaFilter;

    fn get(&self) -> crate::Result<Self::Item> {
        Ok(LuaFilter::default())
    }
}

impl TryFrom<&Options> for LuaFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> Result<Self, Self::Error> {
        Ok(LuaFilterFactory {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lua() {
        let opts = Options::default();
        let factory = LuaFilterFactory::try_from(&opts).unwrap();
        let f = factory.get();
        assert!(f.is_ok());
    }
}
