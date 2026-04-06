use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::str::FromStr;

pub mod api;
pub mod icmp;
pub mod packet;
pub mod smoltcp;
pub mod socks5;
pub mod tcp;
pub mod udp;
pub mod userspace;
pub mod wireguard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
}

impl FromStr for TransportProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(TransportProtocol::Tcp),
            "udp" => Ok(TransportProtocol::Udp),
            "icmp" => Ok(TransportProtocol::Icmp),
            _ => Err(anyhow!("unknown protocol")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}
