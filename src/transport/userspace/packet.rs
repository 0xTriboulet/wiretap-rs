use crate::transport::{FlowTuple, TransportProtocol};
use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpHeader {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: TransportProtocol,
}

pub fn parse_ip_header(packet: &[u8]) -> Result<IpHeader> {
    if packet.is_empty() {
        return Err(anyhow!("empty packet"));
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_header(packet),
        6 => parse_ipv6_header(packet),
        _ => Err(anyhow!("unknown ip version")),
    }
}

fn parse_ipv4_header(packet: &[u8]) -> Result<IpHeader> {
    if packet.len() < 20 {
        return Err(anyhow!("ipv4 header too short"));
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let protocol = match packet[9] {
        1 => TransportProtocol::Icmp,
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return Err(anyhow!("unknown ipv4 protocol")),
    };
    Ok(IpHeader {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
    })
}

fn parse_ipv6_header(packet: &[u8]) -> Result<IpHeader> {
    if packet.len() < 40 {
        return Err(anyhow!("ipv6 header too short"));
    }
    let src = Ipv6Addr::from([
        packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
        packet[15], packet[16], packet[17], packet[18], packet[19], packet[20], packet[21],
        packet[22], packet[23],
    ]);
    let dst = Ipv6Addr::from([
        packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30],
        packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37],
        packet[38], packet[39],
    ]);
    let protocol = match packet[6] {
        58 => TransportProtocol::Icmp,
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return Err(anyhow!("unknown ipv6 next header")),
    };
    Ok(IpHeader {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        protocol,
    })
}

pub fn ip_header_len(packet: &[u8]) -> Result<usize> {
    if packet.is_empty() {
        return Err(anyhow!("empty packet"));
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            if packet.is_empty() {
                return Err(anyhow!("ipv4 header too short"));
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 {
                return Err(anyhow!("invalid ipv4 header length"));
            }
            Ok(ihl)
        }
        6 => Ok(40),
        _ => Err(anyhow!("unknown ip version")),
    }
}

pub fn packet_to_flow(packet: &[u8]) -> Result<FlowTuple> {
    let header = parse_ip_header(packet)?;
    let src = SocketAddr::new(header.src, 0);
    let dst = SocketAddr::new(header.dst, 0);
    Ok(FlowTuple { src, dst })
}
