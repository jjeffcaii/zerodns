use anyhow::Result;
use clap::ArgMatches;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;
use zerodns::client::SystemClient;

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
    let mut is_main_logger_ok = false;
    if let Some(lc) = &c.logger {
        if let Some(lc) = &lc.main {
            zerodns::setup_logger(lc)?;
            is_main_logger_ok = true;
        }
    }

    if !is_main_logger_ok {
        let lc = zerodns::logger::Config::default();
        zerodns::setup_logger(&lc)?;
    }

    // set default nameservers
    if !c.global.nameservers.is_empty() {
        let mut bu = SystemClient::builder();

        for ns in &c.global.nameservers {
            if let Ok(addr) = ns.parse::<IpAddr>() {
                bu = bu.nameserver(SocketAddr::new(addr, zerodns::DEFAULT_UDP_PORT), false);
                continue;
            }
            if let Ok(addr) = ns.parse::<SocketAddr>() {
                bu = bu.nameserver(addr, false);
                continue;
            }
        }
        zerodns::client::set_default_resolver(bu.build()?);
    } else if let Some(path) = &c.global.resolv_file {
        if path != "/etc/resolv.conf" {
            let sc = SystemClient::from_resolv_file(&PathBuf::from(path));
            zerodns::client::set_default_resolver(sc);
        }
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
