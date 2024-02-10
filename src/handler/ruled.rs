use std::collections::HashMap;

use async_trait::async_trait;
use glob::Pattern;
use smallvec::SmallVec;

use config::{Filter as FilterConf, Rule as RuleConf};

use crate::protocol::Message;
use crate::{config, Result};

use super::{FilteredHandler, Handler};

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

pub(crate) struct RuledHandlerBuilder {
    inner: RuledHandler,
}

impl RuledHandlerBuilder {
    pub(crate) fn filter<K>(mut self, key: K, value: &FilterConf) -> Result<Self>
    where
        K: Into<String>,
    {
        self.inner.filters.insert(key.into(), Clone::clone(value));
        Ok(self)
    }

    pub(crate) fn rule(mut self, rule: &RuleConf) -> Result<Self> {
        let r = Rule::new(&rule.domain, Clone::clone(&rule.filter))?;
        self.inner.rules.push(r);
        Ok(self)
    }

    pub(crate) fn build(self) -> RuledHandler {
        self.inner
    }
}

#[derive(Default)]
pub(crate) struct RuledHandler {
    filters: HashMap<String, FilterConf, ahash::RandomState>,
    rules: Vec<Rule>,
}

impl RuledHandler {
    pub(crate) fn builder() -> RuledHandlerBuilder {
        RuledHandlerBuilder {
            inner: Default::default(),
        }
    }

    fn get_rule(&self, req: &Message) -> Option<&Rule> {
        let mut v = SmallVec::<[u8; 64]>::new();
        for (i, next) in req.questions().next().unwrap().name().enumerate() {
            if i != 0 {
                v.push(b'.');
            }
            v.extend_from_slice(next);
        }
        let domain = unsafe { std::str::from_utf8_unchecked(&v[..]) };

        self.rules.iter().find(|r| r.is_match(domain))
    }
}

#[async_trait]
impl Handler for RuledHandler {
    async fn handle(&self, req: &mut Message) -> Result<Option<Message>> {
        if let Some(rule) = self.get_rule(req) {
            if let Some(f) = self.filters.get(&rule.filter) {
                let mut b = FilteredHandler::builder();
                match &*f.kind {
                    "chain" => {
                        // TODO: chain
                    }
                    kind => {
                        b = b.append_with(kind, &f.props);
                    }
                }

                if let Some(h) = b.build() {
                    return h.handle(req).await;
                }
            }
        }

        Ok(None)
    }
}
