use super::{handle_next, Context, Filter, FilterFactory, Options};
use crate::{protocol::*, Result};
use hashbrown::HashMap;
use smallvec::SmallVec;
use std::net::IpAddr;
use std::sync::Arc;
use toml::Value;

#[derive(Debug, Default, Clone)]
struct Record {
    data: Vec<IpAddr>,
}

pub(crate) struct HostsFilter {
    hosts: Arc<HashMap<String, Record>>,
    next: Option<Box<dyn Filter>>,
}

#[async_trait::async_trait]
impl Filter for HostsFilter {
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> Result<()> {
        if res.is_none()
            && req.questions().all(|question| {
                matches!(question.class(), Class::IN)
                    && matches!(question.kind(), Kind::A | Kind::AAAA)
            })
        {
            let lookup = |question: &Question| {
                let mut sb = SmallVec::<[u8; 128]>::new();
                for name in question.name() {
                    sb.extend_from_slice(name);
                    sb.push(b'.');
                }
                let k = unsafe { std::str::from_utf8_unchecked(&sb[..]) };

                let mut ips = vec![];

                if let Some(v) = self.hosts.get(k) {
                    for ip in &v.data {
                        match question.kind() {
                            Kind::A => {
                                if let IpAddr::V4(v4) = ip {
                                    let octets = v4.octets();
                                    let mut x = SmallVec::<[u8; 16]>::new();
                                    x.extend_from_slice(&octets[..]);
                                    ips.push(x);
                                }
                            }
                            Kind::AAAA => {
                                if let IpAddr::V6(v6) = ip {
                                    let octets = v6.octets();
                                    let mut x = SmallVec::<[u8; 16]>::new();
                                    x.extend_from_slice(&octets[..]);
                                    ips.push(x);
                                }
                            }
                            _ => {
                                return None;
                            }
                        }
                    }
                }

                if ips.is_empty() {
                    None
                } else {
                    Some((sb, ips))
                }
            };

            let answers = req
                .questions()
                .map(|question| {
                    let answer = lookup(&question);
                    (question, answer)
                })
                .collect::<Vec<_>>();

            if !answers.is_empty() && answers.iter().any(|(_, answer)| answer.is_some()) {
                let f = Flags::builder()
                    .response()
                    .recursive_query(true)
                    .recursive_available(true);

                let mut bu = Message::builder().flags(f.build()).id(req.id());

                for (question, answer) in &answers {
                    if let Some((k, v)) = answer {
                        for ip in v {
                            bu = bu.answer(
                                unsafe { std::str::from_utf8_unchecked(&k[..]) },
                                question.kind(),
                                question.class(),
                                300,
                                &ip[..],
                            );
                        }
                    }
                }

                let answer = bu.build()?;
                res.replace(answer);
            }
        }
        handle_next(self.next.as_deref(), ctx, req, res).await
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct HostsFilterFactory {
    hosts: Arc<HashMap<String, Record>>,
}

impl HostsFilterFactory {
    #[inline]
    fn read_hosts(src: &Value, dst: &mut HashMap<String, Record>) -> Result<()> {
        if let Some(tbl) = src.as_table() {
            for (k, v) in tbl.iter() {
                let mut record = Record::default();
                match v {
                    Value::String(vv) => {
                        record.data.push(vv.parse::<IpAddr>()?);
                    }
                    Value::Array(arr) => {
                        for next in arr {
                            if let Some(ss) = next.as_str() {
                                record.data.push(ss.parse::<IpAddr>()?);
                            }
                        }
                    }
                    _ => bail!("invalid config"),
                }

                let trimmed = k.trim_matches('.');
                if trimmed.is_empty() {
                    continue;
                }
                dst.insert(format!("{}.", trimmed), record);
            }
        }

        Ok(())
    }
}

impl TryFrom<&Options> for HostsFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> std::result::Result<Self, Self::Error> {
        let mut hosts: HashMap<String, Record> = Default::default();
        if let Some(it) = value.get("hosts") {
            Self::read_hosts(it, &mut hosts)?;
        }

        Ok(Self {
            hosts: Arc::new(hosts),
        })
    }
}

impl FilterFactory for HostsFilterFactory {
    type Item = HostsFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(Self::Item {
            hosts: Arc::clone(&self.hosts),
            next: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_hosts_filter() -> anyhow::Result<()> {
        init();

        let mut ctx = Context::default();

        let opts = toml::from_str::<Options>(
            r#"
        hosts = { "one.one.one.one" = ["1.1.1.1", "1.0.0.1"] }
        "#,
        )?;

        let factory = HostsFilterFactory::try_from(&opts)?;
        info!("factory: {:?}", factory);
        let f = factory.get()?;

        for (search, is_some) in [("one.one.one.one.", true), ("google.com.", false)] {
            let mut req = Message::builder()
                .id(1234)
                .question(search, Kind::A, Class::IN)
                .build()?;
            let mut res = None;

            let result = f.handle(&mut ctx, &mut req, &mut res).await;
            info!("{} -> {:?}", search, &res);
            assert!(result.is_ok());
            assert_eq!(is_some, res.is_some());
        }

        Ok(())
    }
}
