use std::collections::HashMap;
use std::path::PathBuf;

use crate::logger;
use serde::{Deserialize, Serialize};
use toml::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    pub logger: Option<LoggerConfig>,
    pub server: ServerConfig,
    pub filters: HashMap<String, Filter>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    pub main: Option<logger::Config>,
    pub access: Option<logger::Config>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default)]
    pub nameservers: Vec<String>,
    pub resolv_file: Option<String>,
    pub hosts_file: Option<String>,
    pub cache_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub kind: String,
    #[serde(default)]
    pub props: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub domain: String,
    pub filters: Vec<String>,
}

pub fn read_from_toml(pt: &PathBuf) -> anyhow::Result<Config> {
    let b = std::fs::read(pt)?;
    let s = String::from_utf8(b)?;
    let c: Config = toml::from_str(&s)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_from_toml() {
        let pt = PathBuf::from("config.toml");
        let c = read_from_toml(&pt);

        assert!(c.is_ok_and(|c| {
            !c.server.listen.is_empty() && !c.rules.is_empty() && !c.filters.is_empty()
        }));
    }
}
