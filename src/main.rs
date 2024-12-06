#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;

use chrono::{DateTime, Local};
use clap::{arg, command, value_parser, ArgAction, ArgMatches, Command};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use zerodns::client::request as resolve;
use zerodns::protocol::DNS;
use zerodns::protocol::{Class, Flags, Kind, Message};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cmds = command!() // requires `cargo` feature
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("run")
                .about("Run a ZeroDNS server")
                .arg(arg!(-c --config <FILE> "a config file path").required(true)),
        )
        .subcommand(
            Command::new("resolve")
                .about("Resolve an address")
                .arg(arg!(-s --server <DNS> "the dns server address"))
                .arg(arg!(-c --class <CLASS> "class of resolve").value_parser(value_parser!(Class)))
                .arg(
                    arg!(-t --type <TYPE> "type of resolve")
                        .action(ArgAction::Append)
                        .value_parser(value_parser!(Kind)),
                )
                .arg(arg!(--timeout <TIMEOUT> "timeout seconds for the DNS request"))
                .arg(arg!(--short "display nothing except short form of answer"))
                .arg(arg!([DOMAIN] "the domain to be resolved")),
        )
        .get_matches();

    match cmds.subcommand() {
        Some(("run", sm)) => {
            subcommand_run(sm).await?;
        }
        Some(("resolve", sm)) => {
            subcommand_resolve(sm).await?;
        }
        _ => unreachable!("no sub-command"),
    }

    // RUN:
    // dig @127.0.0.1 -p5454 www.youtube.com

    Ok(())
}

async fn subcommand_resolve(sm: &ArgMatches) -> anyhow::Result<()> {
    // --timeout 5
    let mut timeout = Duration::from_secs(5);

    let domain = sm.get_one::<String>("DOMAIN").cloned().unwrap_or_default();
    let short = sm.get_one::<bool>("short").cloned().unwrap_or(false);
    let mut class = sm.get_one::<Class>("class").cloned().unwrap_or(Class::IN);
    let mut types = vec![];
    if domain.is_empty() {
        types.push(Kind::NS);
        class = Class::IN;
    } else {
        if let Some(vals) = sm.get_many::<Kind>("type") {
            for next in vals {
                types.push(*next);
            }
        }
        if types.is_empty() {
            types.push(Kind::A);
        }
    }

    // arg: --server
    let dns = {
        match sm.get_one::<String>("server") {
            None => {
                use resolv_conf::ScopedIp;

                let c = zerodns::read_resolvconf(zerodns::DEFAULT_RESOLV_CONF_PATH).await?;
                let first = c.nameservers.first().ok_or_else(|| {
                    anyhow!(
                        "no nameserver found in {}!",
                        zerodns::DEFAULT_RESOLV_CONF_PATH
                    )
                })?;

                if c.timeout > 0 {
                    timeout = Duration::from_secs(c.timeout as u64);
                }

                let ipaddr = match first {
                    ScopedIp::V4(v4) => IpAddr::V4(*v4),
                    ScopedIp::V6(v6, _) => IpAddr::V6(*v6),
                };
                DNS::UDP(SocketAddr::new(ipaddr, zerodns::DEFAULT_UDP_PORT))
            }
            Some(s) => s.parse::<DNS>()?,
        }
    };

    if let Some(n) = sm.get_one::<String>("timeout") {
        timeout = Duration::from_secs(n.parse::<u64>()?);
    }

    let flags = Flags::builder().request().recursive_query(true).build();
    let req = {
        let mut bu = Message::builder()
            .id({
                use rand::Rng;
                let mut rng = rand::thread_rng();
                rng.gen_range(1024..u16::MAX)
            })
            .flags(flags);

        for next in types {
            bu = bu.question(&domain, next, class);
        }

        bu.build()?
    };

    let begin = Local::now();
    let res = resolve(&dns, &req, timeout).await?;

    if short {
        for next in res.answers() {
            println!("{}", next.rdata()?);
        }
    } else {
        print_resolve_result(&domain, &dns, &req, &res, begin)?;
    }

    println!();

    Ok(())
}

#[inline]
fn print_resolve_result(
    domain: &str,
    dns: &DNS,
    req: &Message,
    res: &Message,
    begin: DateTime<Local>,
) -> anyhow::Result<()> {
    let cost = Local::now() - begin;

    println!();
    println!(
        "; <<>> ZeroDNS {} <<>> @{} {}",
        env!("CARGO_PKG_VERSION"),
        &dns,
        domain
    );
    println!("; (1 server found)");
    println!(";; global options: +cmd");
    println!(";; Got answer:");
    println!(
        ";; ->>HEADER<<- opcode: {:?}, status: {:?}, id: {}",
        res.flags().opcode(),
        res.flags().response_code(),
        res.id()
    );

    println!();
    println!(";; OPT PSEUDOSECTION:");
    println!("; EDNS: version: 0, flags:; udp: 512");
    println!(";; QUESTION SECTION:");
    for question in req.questions() {
        println!(
            ";{}.\t\t{}\t{}",
            question.name(),
            question.class(),
            question.kind()
        );
    }

    println!();
    println!(";; ANSWER SECTION:");

    for answer in res.answers() {
        println!(
            "{}.\t{}\t{}\t{}\t{}",
            answer.name(),
            answer.time_to_live(),
            answer.class(),
            answer.kind(),
            answer.rdata()?
        );
    }

    println!();
    println!(";; Query time: {} msec", cost.num_milliseconds());
    println!(";; SERVER: {}", &dns);
    println!(";; WHEN: {}", &begin);
    println!(";; MSG SIZE\trcvd: {}", res.len());

    Ok(())
}

async fn subcommand_run(sm: &ArgMatches) -> anyhow::Result<()> {
    let path = sm.get_one::<PathBuf>("config").unwrap();
    let c = zerodns::config::read_from_toml(path)?;

    match &c.logger {
        Some(lc) => zerodns::setup_logger(lc)?,
        None => {
            let lc = zerodns::logger::Config::default();
            zerodns::setup_logger(&lc)?;
        }
    }

    zerodns::setup();

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
