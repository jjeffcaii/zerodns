use std::collections::HashMap;
use std::path::PathBuf;

use crate::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use toml::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub logger: Option<LoggerConfig>,
    pub server: ServerConfig,
    pub filters: HashMap<String, Filter>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub cache_size: Option<usize>,
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
