use std::str::FromStr;

use crate::protocol::DNS;
use crate::Result;

use super::Options;

pub struct OptionsReader<'a>(&'a Options);

impl OptionsReader<'_> {
    pub fn get_addrs<A>(&self, k: A) -> Result<Option<Vec<DNS>>>
    where
        A: AsRef<str>,
    {
        match self.0.get(k.as_ref()) {
            None => Ok(None),
            Some(v) => match v.as_array() {
                None => {
                    bail!("invalid dns urls: '{}'", v.to_string());
                }
                Some(arr) => {
                    let mut servers = vec![];
                    for next in arr {
                        match next.as_str() {
                            None => {
                                bail!("invalid dns urls: '{}'", v.to_string());
                            }
                            Some(s) => {
                                servers.push(DNS::from_str(s)?);
                            }
                        }
                    }
                    Ok(Some(servers))
                }
            },
        }
    }
}

impl<'a> From<&'a Options> for OptionsReader<'a> {
    fn from(value: &'a Options) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[test]
    fn test_options() {
        init();

        let opts: Options = toml::from_str(
            r#"
        servers = ["8.8.8.8","8.8.4.4"]
        "#,
        )
        .unwrap();

        let r = OptionsReader::from(&opts);

        let servers = r.get_addrs("servers");
        info!("servers: {:?}", servers);

        assert!(servers.is_ok_and(|servers| servers.is_some_and(|servers| !servers.is_empty())));
    }
}
