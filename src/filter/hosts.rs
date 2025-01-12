use super::{handle_next, Context, Filter, FilterFactory, Options};
use crate::{cachestr::Cachestr, protocol::*, Result};
use hashbrown::HashMap;
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use toml::Value;

type HostValue = SmallVec<[IpAddr; 1]>;
type HostMap = HashMap<Cachestr, HostValue>;

#[derive(Debug, Copy, Clone)]
enum IpOctets {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl AsRef<[u8]> for IpOctets {
    fn as_ref(&self) -> &[u8] {
        match self {
            IpOctets::V4(b) => &b[..],
            IpOctets::V6(b) => &b[..],
        }
    }
}

pub(crate) struct HostsFilter {
    hosts: Arc<HostMap>,
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
                let k = Cachestr::from(unsafe { std::str::from_utf8_unchecked(&sb[..]) });

                let mut ips = SmallVec::<[IpOctets; 1]>::new();

                if let Some(v) = self.hosts.get(&k) {
                    for ip in v.iter() {
                        match question.kind() {
                            Kind::A => {
                                if let IpAddr::V4(v4) = ip {
                                    ips.push(IpOctets::V4(v4.octets()));
                                }
                            }
                            Kind::AAAA => {
                                if let IpAddr::V6(v6) = ip {
                                    ips.push(IpOctets::V6(v6.octets()));
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
                    let name = question.name().to_string();
                    bu = bu.question(name, question.kind(), question.class());
                    if let Some((k, v)) = answer {
                        for ip in v {
                            bu = bu.answer(
                                unsafe { std::str::from_utf8_unchecked(&k[..]) },
                                question.kind(),
                                question.class(),
                                300,
                                ip.as_ref(),
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
pub(crate) struct HostsFilterFactory(Arc<HostMap>);

impl HostsFilterFactory {
    fn read_hosts_file(path: &PathBuf, dst: &mut HostMap) -> Result<()> {
        let f = std::fs::File::open(path)?;

        let mut r = BufReader::new(f);

        let mut s = String::new();

        loop {
            s.clear();

            let n = r.read_line(&mut s)?;
            if n == 0 {
                break;
            }

            let line = s.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            static REGEX_SP: Lazy<regex::Regex> =
                Lazy::new(|| regex::Regex::new(r"[\t ]+").unwrap());

            let mut sp = REGEX_SP.split(line);

            if let Some(first) = sp.next() {
                let ip = first.parse::<IpAddr>()?;

                for host in sp {
                    Self::push_into(host, ip, dst);
                }
            }
        }

        Ok(())
    }

    #[inline]
    fn push_into(host: &str, ip: IpAddr, dst: &mut HostMap) {
        let host = host.trim();
        let host = if host.ends_with('.') {
            Cachestr::from(host)
        } else {
            Cachestr::from(format!("{}.", host))
        };
        let ent = dst.entry(Clone::clone(&host)).or_default();
        if !ent.contains(&ip) {
            ent.push(ip);
            debug!("detect new host: {}\t{}", ip, host);
        }
    }

    #[inline]
    fn read_hosts(src: &Value, dst: &mut HostMap) -> Result<()> {
        if let Some(tbl) = src.as_table() {
            for (k, v) in tbl.iter() {
                let ip = k.parse::<IpAddr>()?;
                match v {
                    Value::String(host) => {
                        Self::push_into(host, ip, dst);
                    }
                    Value::Array(arr) => {
                        for next in arr {
                            let host = next.as_str().ok_or_else(|| anyhow!("invalid config"))?;
                            Self::push_into(host, ip, dst);
                        }
                    }
                    _ => bail!("invalid config"),
                }
            }
        }

        Ok(())
    }
}

impl TryFrom<&Options> for HostsFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> std::result::Result<Self, Self::Error> {
        let mut dst = HostMap::new();

        // 1. read property of 'hosts'
        if let Some(it) = value.get("hosts") {
            Self::read_hosts(it, &mut dst)?;
        }

        // 2. read property of 'include/includes'
        for field in ["include", "includes"] {
            if let Some(files) = value.get(field) {
                match files {
                    Value::String(file) => {
                        Self::read_hosts_file(&PathBuf::from(file), &mut dst)?;
                    }
                    Value::Array(arr) => {
                        for item in arr {
                            let file = item.as_str().ok_or_else(|| anyhow!("invalid config"))?;
                            Self::read_hosts_file(&PathBuf::from(file), &mut dst)?;
                        }
                    }
                    _ => bail!("invalid config"),
                }
            }
        }

        Ok(Self(Arc::new(dst)))
    }
}

impl FilterFactory for HostsFilterFactory {
    type Item = HostsFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(Self::Item {
            hosts: Clone::clone(&self.0),
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
        hosts = { "1.1.1.1" = "one.one.one.one", "1.0.0.1" = ["one.one.one.one"] }
        includes = ["/etc/hosts"]
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
