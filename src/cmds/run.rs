use anyhow::Result;
use clap::ArgMatches;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

pub(crate) async fn execute(sm: &ArgMatches) -> Result<()> {
    // read config file
    let c = {
        let path = {
            let path = sm.get_one::<String>("config").unwrap();
            PathBuf::from(path)
        };
        zerodns::config::read_from_toml(&path)?
    };

    // initialize logger
    match &c.logger {
        Some(lc) => zerodns::setup_logger(lc)?,
        None => {
            let lc = zerodns::logger::Config::default();
            zerodns::setup_logger(&lc)?;
        }
    }

    // set global resolv file
    if let Some(resolv) = &c.global.resolv.clone().filter(|it| !it.is_empty()) {
        let path = PathBuf::from(resolv);
        let _ = zerodns::GLOBAL_CONFIG
            .get_or_try_init(|| zerodns::read_resolvconf(&path))
            .await?;
    }

    // initialize built-in modules
    zerodns::setup();

    // starting...
    let closer = Arc::new(Notify::new());
    let stopped = Arc::new(Notify::new());
    {
        let closer = Clone::clone(&closer);
        let stopped = Clone::clone(&stopped);
        tokio::spawn(async move {
            if let Err(e) = zerodns::bootstrap::run(c, closer).await {
                error!("zerodns server is stopped: {:?}", e);
            }
            stopped.notify_one();
        });
    }

    tokio::signal::ctrl_c().await?;

    closer.notify_waiters();

    stopped.notified().await;

    Ok(())
}
