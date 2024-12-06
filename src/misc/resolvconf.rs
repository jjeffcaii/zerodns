use resolv_conf::Config;
use std::path::Path;

pub async fn read(path: impl AsRef<Path>) -> anyhow::Result<Config> {
    let b = tokio::fs::read(path).await?;
    let parsed_config = Config::parse(&b[..])?;
    Ok(parsed_config)
}
