use std::collections::HashMap;

use std::sync::Arc;

use async_trait::async_trait;
use glob::Pattern;
use smallvec::SmallVec;

use config::{Filter as FilterConf, Rule as RuleConf};

use crate::filter::{load as load_filter, FilterFactoryExt};
use crate::handler::filtered::FilteredHandlerBuilder;
use crate::protocol::Message;
use crate::{config, Result};

use super::{FilteredHandler, Handler};

#[derive(Debug, Clone)]
struct Rule {
    pattern: Option<Pattern>,
    filter: String,
}

impl Rule {
    fn new(domain: &str, filter: String) -> Result<Self> {
        let pattern = match domain {
            "*" => None,
            other => Some(Pattern::new(domain)?),
        };

        Ok(Self { pattern, filter })
    }

    fn is_match(&self, domain: &str) -> bool {
        match &self.pattern {
            Some(pattern) => pattern.matches(domain),
            None => true,
        }
    }
}

enum FilterKind {
    Factory(Box<dyn FilterFactoryExt>),
    Chain(Vec<String>),
}

pub(crate) struct RuledHandlerBuilder {
    filters: HashMap<String, FilterKind, ahash::RandomState>,
    rules: Vec<Rule>,
}

impl RuledHandlerBuilder {
    pub(crate) fn filter<K>(mut self, key: K, value: &FilterConf) -> Result<Self>
    where
        K: Into<String>,
    {
        let f = match value.kind.as_str() {
            "chain" => {
                let mut chains = vec![];
                if let Some(refs) = value.props.get("refs") {
                    if let Some(arr) = refs.as_array() {
                        for next in arr {
                            if let Some(s) = next.as_str() {
                                chains.push(s.to_string());
                            }
                        }
                    }
                }
                if chains.is_empty() {
                    bail!("invalid filter chain props: refs is empty!");
                }
                FilterKind::Chain(chains)
            }
            kind => {
                let factory = load_filter(kind, &value.props)?;
                FilterKind::Factory(factory)
            }
        };

        self.filters.insert(key.into(), f);
        Ok(self)
    }

    pub(crate) fn rule(mut self, rule: &RuleConf) -> Result<Self> {
        let r = Rule::new(&rule.domain, Clone::clone(&rule.filter))?;
        self.rules.push(r);
        Ok(self)
    }

    pub(crate) fn build(self) -> RuledHandler {
        let Self { rules, filters } = self;
        RuledHandler {
            rules: Arc::new(rules),
            filters: Arc::new(filters),
        }
    }
}

#[derive(Default, Clone)]
pub(crate) struct RuledHandler {
    filters: Arc<HashMap<String, FilterKind, ahash::RandomState>>,
    rules: Arc<Vec<Rule>>,
}

impl RuledHandler {
    pub(crate) fn builder() -> RuledHandlerBuilder {
        RuledHandlerBuilder {
            filters: Default::default(),
            rules: Default::default(),
        }
    }

    fn get_rule(&self, req: &Message) -> Option<&Rule> {
        let mut v = SmallVec::<[u8; 64]>::new();

        use std::panic::{self, AssertUnwindSafe};

        if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| {
            for (i, next) in req.questions().next().unwrap().name().enumerate() {
                if i != 0 {
                    v.push(b'.');
                }
                v.extend_from_slice(next);
            }
        })) {
            error!("fuck: {:?}", e);
            error!("fuck222: {}", hex::encode(req.as_ref()));
        }

        let domain = unsafe { std::str::from_utf8_unchecked(&v[..]) };

        self.rules.iter().find(|r| r.is_match(domain))
    }

    fn add_next_filter(&self, b: &mut FilteredHandlerBuilder, name: &String) -> Result<()> {
        if let Some(k) = self.filters.get(name) {
            match k {
                FilterKind::Factory(factory) => {
                    let f = factory.get_boxed()?;
                    b.append_boxed(f);
                }
                FilterKind::Chain(refs) => {
                    for name in refs {
                        self.add_next_filter(b, name)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Handler for RuledHandler {
    async fn handle(&self, req: &mut Message) -> Result<Option<Message>> {
        if let Some(rule) = self.get_rule(req) {
            let mut b = FilteredHandler::builder();
            self.add_next_filter(&mut b, &rule.filter)?;

            if let Some(h) = b.build() {
                return h.handle(req).await;
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::filter::NoopFilter;

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
        crate::builtin::init();
    }

    #[tokio::test]
    async fn test_ruled() -> anyhow::Result<()> {
        init();

        let c: Config = {
            toml::from_str(
                r#"
            [server]
            listen = "127.0.0.1:5454"

            [filters.a]
            kind = "noop"

            [filters.b]
            kind = "noop"

            [filters.c]
            kind = "noop"

            [filters.foobar]
            kind = "chain"
            props = { refs = ["a","b","c"] }

            [[rules]]
            domain = "*"
            filter = "foobar"

            "#,
            )
        }?;

        let mut b = RuledHandler::builder();

        for next in &c.rules {
            b = b.rule(next)?;
        }

        for (k, v) in &c.filters {
            b = b.filter(k, v)?;
        }

        let h = b.build();
        let mut req = {
            let raw = hex::decode(
                "f2500120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )
            .unwrap();
            Message::from(raw)
        };

        let x = NoopFilter::requests();
        let y = NoopFilter::responses();

        let res = h.handle(&mut req).await;

        assert!(res.is_ok());

        assert_eq!(3, NoopFilter::requests() - x);
        assert_eq!(3, NoopFilter::responses() - y);

        Ok(())
    }
}
