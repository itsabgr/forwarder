extern crate core;

use std::io;
use std::net::SocketAddr;
use std::net::{IpAddr, UdpSocket};

pub struct Server {
    key: [u8; 32],
}

impl Server {
    pub fn new(key: [u8; 32]) -> Server {
        Server { key }
    }

    pub fn serve(&self, socket: UdpSocket) -> io::Error {
        let mut b = [0 as u8; 512];
        loop {
            match socket.recv_from(&mut b) {
                Err(e) => return e,
                Ok((n, from)) => {
                    match Packet::decode(&b[..n], &self.key) {
                        Some(input) => {
                            match input.addr {
                                Some(target) => {
                                    let output = Packet::new(Some(from), input.data);
                                    let _ =
                                        socket.send_to(output.encode(&self.key).as_slice(), target);
                                }
                                None => {
                                    let crypto_addr = from.encrypt(&self.key);
                                    let output = Packet::new(None, crypto_addr.as_slice());
                                    let _ =
                                        socket.send_to(output.encode(&self.key).as_slice(), from);
                                }
                            };
                        }
                        _ => {}
                    };
                }
            };
        }
    }
}

#[test]
fn test_with_addr() {
    let rand_msg: [u8; 16] = rand::random();
    let rand_key: [u8; 32] = rand::random();
    let addr: SocketAddr = "1.1.1.1:65000".parse().expect("failed");
    let packet = Packet::new(Some(addr), &rand_msg);
    let cipher = packet.encode(&rand_key);
    println!("{:?}", cipher);
    let decrypted = Packet::decode(cipher.as_slice(), &rand_key).expect("packet failed");
    assert_eq!(decrypted.addr, packet.addr);
    assert_eq!(decrypted.data, packet.data);
}

#[test]
fn test_no_addr() {
    let rand_msg: [u8; 16] = rand::random();
    let rand_key: [u8; 32] = rand::random();
    let packet = Packet::new(None, &rand_msg);
    let cipher = packet.encode(&rand_key);
    let decrypted = Packet::decode(cipher.as_slice(), &rand_key).expect("packet failed");
    assert_eq!(decrypted.addr, packet.addr);
    assert_eq!(decrypted.data, packet.data);
}

trait ISocketAddr {
    fn encrypt(&self, key: &[u8; 32]) -> Vec<u8>;
    fn decrypt(b: &[u8], key: &[u8; 32]) -> Option<SocketAddr>;
    fn encode(&self) -> Vec<u8>;
    fn decode(b: &[u8]) -> Option<SocketAddr>;
}

pub struct Packet<'a> {
    pub addr: Option<SocketAddr>,
    pub data: &'a [u8],
}

impl Packet<'_> {
    pub fn new<'a>(addr: Option<SocketAddr>, data: &'a [u8]) -> Packet<'a> {
        return Packet {
            addr: addr,
            data: data,
        };
    }
    pub fn encode(&self, key: &[u8; 32]) -> Vec<u8> {
        let addr: Vec<u8> = match self.addr {
            None => vec![],
            Some(addr) => addr.encrypt(key),
        };
        let mut v = Vec::with_capacity(1 + addr.len() + self.data.len());
        v.push(addr.len() as u8);
        v.extend(addr);
        v.extend(self.data);
        return v;
    }

    pub fn decode<'a>(b: &'a [u8], key: &[u8; 32]) -> Option<Packet<'a>> {
        if b.len() <= 1 {
            return None;
        }
        let addr_end = b[0] as usize + 1;
        if addr_end <= 1 {
            return Some(Packet {
                addr: None,
                data: &b[1..],
            });
        }
        if b.len() < addr_end {
            return None;
        }
        let addr = SocketAddr::decrypt(&b[1..addr_end], key);
        match addr {
            None => None,
            Some(addr) => Some(Packet {
                addr: Some(addr),
                data: &b[addr_end..],
            }),
        }
    }
}

impl ISocketAddr for SocketAddr {
    fn encrypt(&self, key: &[u8; 32]) -> Vec<u8> {
        crypto::encrypt(self.encode(), key)
    }
    fn decrypt(b: &[u8], key: &[u8; 32]) -> Option<SocketAddr> {
        match crypto::decrypt(b, key) {
            Err(_) => None,
            Ok(plain) => SocketAddr::decode(plain.as_slice()),
        }
    }
    fn encode(&self) -> Vec<u8> {
        match self {
            SocketAddr::V4(ip) => [
                self.port().to_be_bytes().as_ref(),
                ip.ip().octets().as_ref(),
            ]
            .concat(),
            SocketAddr::V6(ip) => [
                self.port().to_be_bytes().as_ref(),
                ip.ip().octets().as_ref(),
            ]
            .concat(),
        }
    }
    fn decode(b: &[u8]) -> Option<SocketAddr> {
        match b.len() {
            6 => {
                let saddr = SocketAddr::new(
                    IpAddr::from([b[2], b[3], b[4], b[5]]),
                    u16::from_be_bytes([b[0], b[1]]),
                );
                return Some(saddr);
            }
            18 => {
                let saddr = SocketAddr::new(
                    IpAddr::from([
                        b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
                        b[14], b[15], b[16], b[17],
                    ]),
                    u16::from_be_bytes([b[0], b[1]]),
                );
                return Some(saddr);
            }
            _ => None,
        }
    }
}

mod crypto {
    use chacha20poly1305::aead::{Aead, NewAead};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    pub fn encrypt(addr: Vec<u8>, key: &[u8; 32]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("failed");
        let nonce = Nonce::from_slice(&[0; 12]);
        cipher.encrypt(nonce, addr.as_ref()).expect("failed")
    }

    pub fn decrypt(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ()> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("failed");
        let nonce = Nonce::from_slice(&[0; 12]);
        match cipher.decrypt(nonce, encrypted.as_ref()) {
            Err(_) => Err(()),
            Ok(addr) => Ok(addr),
        }
    }
}
