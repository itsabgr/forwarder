extern crate core;

use std::net;
use std::net::SocketAddr;

use clap::Parser;
use rand::random;

use crate::forwarder::Server;

mod forwarder;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(version = "1.0", about = None)]
struct Args {
    ///listening addr
    #[clap(long, value_parser)]
    addr: SocketAddr,

}

fn main() {
    let args = Args::parse();
    let socket = net::UdpSocket::bind(args.addr).expect("failed to listen");
    println!("addr {}", socket.local_addr().expect("failed to take local_addr"));
    let server = Server::new(random());
    let err = server.serve(socket);
    eprintln!("{}", err);
}