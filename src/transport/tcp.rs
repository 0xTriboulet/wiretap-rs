use crate::transport::packet::{
    build_ipv4_header, build_tcp_header, parse_ip_packet, tcp_checksum_ipv4,
};
use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub fn handle_tcp_packet(packet: &[u8]) -> Result<Option<Vec<u8>>> {
    let parsed = parse_ip_packet(packet)?;
    if parsed.protocol != crate::transport::TransportProtocol::Tcp {
        return Err(anyhow!("not a tcp packet"));
    }
    let offset = parsed.header_len;
    if packet.len() < offset + 20 {
        return Err(anyhow!("tcp header too short"));
    }
    let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let data_offset = ((packet[offset + 12] >> 4) as usize) * 4;
    if packet.len() < offset + data_offset {
        return Err(anyhow!("tcp data offset out of bounds"));
    }
    let payload = &packet[offset + data_offset..];
    if payload.is_empty() {
        return Ok(None);
    }

    let dest = SocketAddr::new(parsed.dst, dst_port);
    let mut stream = TcpStream::connect_timeout(&dest, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.write_all(payload)?;

    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(_) => return Ok(None),
    };
    buf.truncate(n);

    let (src_v4, dst_v4) = match (parsed.src, parsed.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
        _ => return Ok(None),
    };

    let flags = 0x18u16;
    let mut segment = Vec::with_capacity(20 + buf.len());
    let tcp_header = build_tcp_header(dst_port, src_port, flags, 65535, 0);
    segment.extend_from_slice(&tcp_header);
    segment.extend_from_slice(&buf);
    let checksum = tcp_checksum_ipv4(dst_v4, src_v4, &segment);
    let tcp_header = build_tcp_header(dst_port, src_port, flags, 65535, checksum);

    let mut response = build_ipv4_header(dst_v4, src_v4, 6, 20 + buf.len());
    response.extend_from_slice(&tcp_header);
    response.extend_from_slice(&buf);

    Ok(Some(response))
}
