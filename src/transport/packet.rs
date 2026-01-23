use crate::transport::TransportProtocol;
use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIpPacket {
    pub version: u8,
    pub header_len: usize,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: TransportProtocol,
}

pub fn parse_ip_packet(packet: &[u8]) -> Result<ParsedIpPacket> {
    if packet.is_empty() {
        return Err(anyhow!("empty packet"));
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => Err(anyhow!("unknown ip version")),
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Result<ParsedIpPacket> {
    if packet.len() < 20 {
        return Err(anyhow!("ipv4 header too short"));
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Err(anyhow!("invalid ipv4 header length"));
    }
    let protocol = match packet[9] {
        1 => TransportProtocol::Icmp,
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return Err(anyhow!("unknown ipv4 protocol")),
    };
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok(ParsedIpPacket {
        version: 4,
        header_len,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
    })
}

fn parse_ipv6_packet(packet: &[u8]) -> Result<ParsedIpPacket> {
    if packet.len() < 40 {
        return Err(anyhow!("ipv6 header too short"));
    }
    let header_len = 40;
    let protocol = match packet[6] {
        58 => TransportProtocol::Icmp,
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return Err(anyhow!("unknown ipv6 next header")),
    };
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
    Ok(ParsedIpPacket {
        version: 6,
        header_len,
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        protocol,
    })
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    payload_len: usize,
) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[1] = 0;
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    header[4..6].copy_from_slice(&0u16.to_be_bytes());
    header[6..8].copy_from_slice(&0u16.to_be_bytes());
    header[8] = 64;
    header[9] = protocol;
    header[10..12].copy_from_slice(&0u16.to_be_bytes());
    header[12..16].copy_from_slice(&src.octets());
    header[16..20].copy_from_slice(&dst.octets());
    let csum = checksum(&header);
    header[10..12].copy_from_slice(&csum.to_be_bytes());
    header.to_vec()
}

pub fn build_udp_header(
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    checksum_value: u16,
) -> [u8; 8] {
    let mut header = [0u8; 8];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    let len = 8 + payload_len;
    header[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    header[6..8].copy_from_slice(&checksum_value.to_be_bytes());
    header
}

pub fn build_tcp_header(
    src_port: u16,
    dst_port: u16,
    flags: u16,
    window: u16,
    checksum_value: u16,
) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..8].copy_from_slice(&0u32.to_be_bytes());
    header[8..12].copy_from_slice(&0u32.to_be_bytes());
    header[12] = 0x50;
    header[13] = (flags & 0xff) as u8;
    header[14..16].copy_from_slice(&window.to_be_bytes());
    header[16..18].copy_from_slice(&checksum_value.to_be_bytes());
    header[18..20].copy_from_slice(&0u16.to_be_bytes());
    header
}

pub struct ParsedTcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u16,
    pub data_offset: usize,
}

pub fn parse_tcp_header(packet: &[u8], ip_header_len: usize) -> Result<ParsedTcpHeader> {
    if packet.len() < ip_header_len + 20 {
        return Err(anyhow!("tcp header too short"));
    }
    let offset = ip_header_len;
    let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let data_offset = ((packet[offset + 12] >> 4) as usize) * 4;
    if packet.len() < ip_header_len + data_offset {
        return Err(anyhow!("tcp data offset out of bounds"));
    }
    let flags = packet[offset + 13] as u16;
    Ok(ParsedTcpHeader {
        src_port,
        dst_port,
        flags,
        data_offset,
    })
}

pub struct ParsedUdpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

pub fn parse_udp_packet(packet: &[u8], ip_header_len: usize) -> Result<ParsedUdpPacket> {
    if packet.len() < ip_header_len + 8 {
        return Err(anyhow!("udp header too short"));
    }
    let offset = ip_header_len;
    let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let length = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]) as usize;
    if length < 8 {
        return Err(anyhow!("udp length too short"));
    }
    let payload_offset = offset + 8;
    let payload_len = length.saturating_sub(8);
    if packet.len() < payload_offset + payload_len {
        return Err(anyhow!("udp payload out of bounds"));
    }
    Ok(ParsedUdpPacket {
        src_port,
        dst_port,
        payload_offset,
        payload_len,
    })
}

pub fn build_udp_packet(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut udp_header = build_udp_header(src_port, dst_port, payload.len(), 0);
    let mut segment = Vec::with_capacity(udp_header.len() + payload.len());
    segment.extend_from_slice(&udp_header);
    segment.extend_from_slice(payload);

    let checksum_value = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => udp_checksum_ipv4(src, dst, &segment),
        (IpAddr::V6(src), IpAddr::V6(dst)) => udp_checksum_ipv6(src, dst, &segment),
        _ => return Err(anyhow!("udp ip version mismatch")),
    };
    udp_header[6..8].copy_from_slice(&checksum_value.to_be_bytes());
    segment[..8].copy_from_slice(&udp_header);

    let ip_header = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_ipv4_header(src, dst, 17, segment.len()),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_ipv6_header(src, dst, 17, segment.len()),
        _ => return Err(anyhow!("udp ip version mismatch")),
    };

    let mut packet = Vec::with_capacity(ip_header.len() + segment.len());
    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&segment);
    Ok(packet)
}

pub fn tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    checksum(&pseudo)
}

pub fn udp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    checksum(&pseudo)
}

pub fn build_ipv6_header(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    payload_len: usize,
) -> Vec<u8> {
    let mut header = [0u8; 40];
    header[0] = 0x60;
    header[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    header[6] = next_header;
    header[7] = 64;
    header[8..24].copy_from_slice(&src.octets());
    header[24..40].copy_from_slice(&dst.octets());
    header.to_vec()
}

pub fn udp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0u8; 3]);
    pseudo.push(17);
    pseudo.extend_from_slice(segment);
    checksum(&pseudo)
}

pub fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0u8; 3]);
    pseudo.push(58);
    pseudo.extend_from_slice(payload);
    checksum(&pseudo)
}
