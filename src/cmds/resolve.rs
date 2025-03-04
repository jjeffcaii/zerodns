use anyhow::Result;
use chrono::{DateTime, Local};
use clap::ArgMatches;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use zerodns::client::request;
use zerodns::protocol::{AdditionalRR, Class, Flags, Kind, Message, DNS};

pub(crate) async fn execute(sm: &ArgMatches) -> Result<()> {
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
                use resolv_conf::{Config, ScopedIp};

                let c = {
                    let b = std::fs::read("/etc/resolv.conf")?;
                    Config::parse(&b[..])?
                };

                if c.timeout > 0 {
                    timeout = Duration::from_secs(c.timeout as u64);
                }

                let first = c
                    .nameservers
                    .first()
                    .ok_or_else(|| anyhow!("no available nameserver!"))?;

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

    let noedns = sm.get_one::<bool>("noedns").cloned().unwrap_or(false);

    let flags = Flags::builder()
        .request()
        .edns(!noedns)
        .recursive_query(true)
        .build();
    let req = {
        let mut bu = Message::builder()
            .id({
                use rand::prelude::*;
                rand::rng().random_range(1024..u16::MAX)
            })
            .flags(flags);

        for next in types {
            bu = bu.question(&domain, next, class);
        }

        if !noedns {
            bu = bu.additional_pseudo(4096, 0, 0, 0, None::<&[u8]>);
        }

        bu.build()?
    };

    let begin = Local::now();
    let res = request(&dns, &req, timeout).await?;

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
) -> Result<()> {
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
        ";; ->>HEADER<<- opcode: {}, status: {}, id: {}",
        res.flags().opcode(),
        res.flags().response_code(),
        res.id()
    );

    println!();
    println!(";; OPT PSEUDOSECTION:");
    for next in res
        .additionals()
        .filter(|it| matches!(it, AdditionalRR::PseudoRR(_)))
    {
        if let AdditionalRR::PseudoRR(pseude) = next {
            println!(
                "; EDNS: version: {}, flags: {:#x}; udp: {}",
                pseude.version(),
                pseude.extended_rcode(),
                pseude.udp_payload_size()
            );
            // TODO: print pseude data pairs
        }
    }

    println!();
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
    println!(";; ADDITIONAL SECTION:");
    for next in res
        .additionals()
        .filter(|it| matches!(it, AdditionalRR::RR(_)))
    {
        if let AdditionalRR::RR(rr) = next {
            println!(
                "{}.\t{}\t{}\t{}\t{}",
                rr.name(),
                rr.time_to_live(),
                rr.class(),
                rr.kind(),
                rr.rdata()?
            );
        }
    }

    println!();
    println!(";; Query time: {} msec", cost.num_milliseconds());
    println!(";; SERVER: {}", &dns);
    println!(";; WHEN: {}", begin.to_rfc2822());
    println!(";; MSG SIZE\trcvd: {}", res.len());

    Ok(())
}
