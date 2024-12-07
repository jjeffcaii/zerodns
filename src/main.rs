#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;

use clap::{arg, command, value_parser, ArgAction, Command};
use zerodns::protocol::{Class, Kind};

mod cmds;

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
        Some(("run", sm)) => cmds::run(sm).await?,
        Some(("resolve", sm)) => cmds::resolve(sm).await?,
        _ => unreachable!("no sub-command"),
    }

    // RUN:
    // dig @127.0.0.1 -p5454 www.youtube.com

    Ok(())
}
