extern crate core;

use std::{net, thread};
use std::net::SocketAddr;
use std::process::exit;

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

    ///number of workers (default number of cpu cores)
    #[clap(short, long, value_parser, default_value_t = 0)]
    n: u8,
}

fn main() {
    let args = Args::parse();
    let key: [u8; 32] = random();
    assert_ne!(key, [0; 32]);
    let number_of_workers: u8 = match args.n {
        0 => num_cpus::get() as u8,
        _ => args.n,
    };
    assert!(number_of_workers > 0);
    //
    let socket = net::UdpSocket::bind(args.addr).expect("failed to listen");
    println!(
        "addr: {}",
        socket.local_addr().expect("failed to take local_addr")
    );
    println!("workers: {}", number_of_workers);
    for i in 0..number_of_workers - 1 {
        let socket_clone = socket.try_clone().expect("failed to clone socket");
        thread::spawn(move || {
            match core_affinity::get_core_ids() {
                Some(cores) => core_affinity::set_for_current(cores[(i % (cores.len() as u8)) as usize]),
                _ => {}
            }
            let server = Server::new(key);
            let err = server.serve(&socket_clone);
            eprintln!("{}", err);
            exit(1);
        });
    };
    match core_affinity::get_core_ids() {
        Some(cores) => core_affinity::set_for_current(cores[(number_of_workers % (cores.len() as u8)) as usize]),
        _ => {}
    }
    let socket_ptr = &socket;
    let server = Server::new(key);
    let err = server.serve(socket_ptr);
    eprintln!("{}", err);
    drop(socket);
    exit(1);
}
