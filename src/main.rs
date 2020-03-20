
// #[macro_use]
extern crate clap;
#[macro_use]
extern crate log;

use clap::{App, Arg, SubCommand};

mod dhcp;
mod server;
mod client;
mod storage;

fn main() {
    let app = App::new("rusdhcp")
        .version("0.0.1")
        .about("dhcp server or client for learning implemented with Rust")
        .help("DHCP Server/Client")
        .subcommand(SubCommand::with_name("server")
        .about("server use")
        .arg(Arg::with_name("pool")
            .short("p")
            .long("pool")
            )
        )
        .subcommand(SubCommand::with_name("client")
        .about("client use")
        );
        let matches = app.get_matches();
        match matches.subcommand_matches("server") {
            Some(_) => {
                println!("server use");
            },
            None => {}
        }
        match matches.subcommand_matches("client") {
            Some(_) => {
                println!("client use");
            },
            None => {
                println!("mode is not specified.");
                std::process::exit(1);
            }
        }

}
