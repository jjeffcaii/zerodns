use resolv_conf::Config;
use std::path::Path;

use tokio::sync::OnceCell;

pub static GLOBAL_CONFIG: OnceCell<Config> = OnceCell::const_new();

pub async fn read<A>(path: A) -> anyhow::Result<Config>
where
    A: AsRef<Path>,
{
    let b = tokio::fs::read(path).await?;
    let parsed_config = Config::parse(&b[..])?;
    Ok(parsed_config)
}
