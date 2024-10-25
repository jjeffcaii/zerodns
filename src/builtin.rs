use crate::filter::{
    register, ChinaDNSFilterFactory, LuaFilterFactory, NoopFilterFactory, Options,
    ProxyByFilterFactory,
};
use crate::logger::{self, Config as LoggerConfig};

pub fn setup() {
    register("noop", |opts: &Options| NoopFilterFactory::try_from(opts));
    register("proxyby", |opts: &Options| {
        ProxyByFilterFactory::try_from(opts)
    });
    register("chinadns", |opts: &Options| {
        ChinaDNSFilterFactory::try_from(opts)
    });
    register("lua", |opts: &Options| LuaFilterFactory::try_from(opts))
}

pub fn setup_logger(c: &LoggerConfig) -> crate::Result<()> {
    logger::init_global(c)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::filter::{load, Options};

    use super::*;

    #[test]
    fn test_init() {
        pretty_env_logger::try_init_timed().ok();

        setup();

        // noop
        {
            let opts = Options::default();
            assert!(load("noop", &opts).is_ok());
        }

        // proxyby
        {
            let opts: Options = toml::from_str(
                r#"
            servers = ["8.8.8.8","8.8.4.4"]
            "#,
            )
            .unwrap();
            assert!(load("proxyby", &opts).is_ok());
        }

        // chinadns
        {
            let opts: Options = toml::from_str(
                r#"
            trusted = ["8.8.8.8","8.8.4.4"]
            mistrusted = ["223.5.5.5","223.6.6.6"]
            geoip_database = "GeoLite2-Country.mmdb"
            "#,
            )
            .unwrap();
            assert!(load("chinadns", &opts).is_ok());
        }

        // lua
        {
            let opts: Options = toml::from_str(
                r#"
            script = """
            function handle(ctx,req)
            end
            """
            "#,
            )
            .unwrap();
            assert!(load("lua", &opts).is_ok());
        }
    }
}
