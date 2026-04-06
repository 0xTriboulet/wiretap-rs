use crate::transport::packet::{
    build_ipv4_header, build_ipv6_header, checksum, icmpv6_checksum, parse_ip_packet,
};
use anyhow::{anyhow, Result};
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

pub trait Ping {
    fn ping(&self, dst: IpAddr) -> bool;
}

#[derive(Debug, Clone, Copy)]
pub struct SystemPing {
    timeout: Duration,
}

impl SystemPing {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn with_default_timeout() -> Self {
        Self {
            timeout: Duration::from_secs(1),
        }
    }
}

impl Ping for SystemPing {
    fn ping(&self, dst: IpAddr) -> bool {
        let timeout_secs = self.timeout.as_secs().max(1);
        let dst_str = dst.to_string();

        if cfg!(windows) {
            let timeout_ms = (self.timeout.as_millis().min(i32::MAX as u128)) as i32;
            let mut cmd = Command::new("ping");
            cmd.arg("-n")
                .arg("1")
                .arg("-w")
                .arg(timeout_ms.to_string())
                .arg(dst_str);
            return cmd.status().map(|s| s.success()).unwrap_or(false);
        }

        let timeout_str = timeout_secs.to_string();
        let args = match dst {
            IpAddr::V4(_) => vec!["-c", "1", "-W", timeout_str.as_str(), dst_str.as_str()],
            IpAddr::V6(_) => vec![
                "-c",
                "1",
                "-W",
                timeout_str.as_str(),
                "-6",
                dst_str.as_str(),
            ],
        };
        let status = Command::new("ping").args(&args).status();
        match status {
            Ok(status) if status.success() => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && dst.is_ipv6() => {
                Command::new("ping6")
                    .arg("-c")
                    .arg("1")
                    .arg("-W")
                    .arg(timeout_secs.to_string())
                    .arg(dst_str)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AlwaysPing;

impl Ping for AlwaysPing {
    fn ping(&self, _dst: IpAddr) -> bool {
        true
    }
}

pub fn handle_icmp_packet(packet: &[u8]) -> Result<Option<Vec<u8>>> {
    handle_icmp_packet_with_ping(packet, &AlwaysPing)
}

pub fn handle_icmp_packet_with_ping<P: Ping>(packet: &[u8], ping: &P) -> Result<Option<Vec<u8>>> {
    let parsed = parse_ip_packet(packet)?;
    if parsed.protocol != crate::transport::TransportProtocol::Icmp {
        return Err(anyhow!("not an icmp packet"));
    }
    let offset = parsed.header_len;
    if packet.len() < offset + 4 {
        return Err(anyhow!("icmp header too short"));
    }

    match (parsed.version, parsed.src, parsed.dst) {
        (4, IpAddr::V4(src), IpAddr::V4(dst)) => {
            let icmp_type = packet[offset];
            if icmp_type != 8 {
                return Ok(None);
            }
            if !ping.ping(IpAddr::V4(dst)) {
                return Ok(None);
            }
            let mut icmp = packet[offset..].to_vec();
            icmp[0] = 0;
            icmp[2] = 0;
            icmp[3] = 0;
            let csum = checksum(&icmp);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());

            let mut response = build_ipv4_header(dst, src, 1, icmp.len());
            response.extend_from_slice(&icmp);
            Ok(Some(response))
        }
        (6, IpAddr::V6(src), IpAddr::V6(dst)) => {
            let icmp_type = packet[offset];
            if icmp_type != 128 {
                return Ok(None);
            }
            if !ping.ping(IpAddr::V6(dst)) {
                return Ok(None);
            }
            let mut icmp = packet[offset..].to_vec();
            icmp[0] = 129;
            icmp[2] = 0;
            icmp[3] = 0;
            let csum = icmpv6_checksum(dst, src, &icmp);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());

            let mut response = build_ipv6_header(dst, src, 58, icmp.len());
            response.extend_from_slice(&icmp);
            Ok(Some(response))
        }
        _ => Ok(None),
    }
}

pub fn build_icmpv4_port_unreachable(packet: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse_ip_packet(packet)?;
    let (src, dst) = match (parsed.src, parsed.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
        _ => return Err(anyhow!("icmpv4 unreachable requires ipv4 packet")),
    };

    let header_len = parsed.header_len;
    if packet.len() < header_len {
        return Err(anyhow!("invalid ip header length"));
    }
    let payload_end = (header_len + 8).min(packet.len());
    let original = &packet[..payload_end];

    let mut icmp = Vec::with_capacity(8 + original.len());
    icmp.push(3);
    icmp.push(3);
    icmp.extend_from_slice(&0u16.to_be_bytes());
    icmp.extend_from_slice(&0u32.to_be_bytes());
    icmp.extend_from_slice(original);

    let csum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut response = build_ipv4_header(dst, src, 1, icmp.len());
    response.extend_from_slice(&icmp);
    Ok(response)
}

pub fn build_icmpv6_port_unreachable(packet: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse_ip_packet(packet)?;
    let (src, dst) = match (parsed.src, parsed.dst) {
        (IpAddr::V6(src), IpAddr::V6(dst)) => (src, dst),
        _ => return Err(anyhow!("icmpv6 unreachable requires ipv6 packet")),
    };

    let header_len = parsed.header_len;
    if packet.len() < header_len {
        return Err(anyhow!("invalid ip header length"));
    }
    let payload_end = (header_len + 8).min(packet.len());
    let original = &packet[..payload_end];

    let mut icmp = Vec::with_capacity(8 + original.len());
    icmp.push(1);
    icmp.push(4);
    icmp.extend_from_slice(&0u16.to_be_bytes());
    icmp.extend_from_slice(&0u32.to_be_bytes());
    icmp.extend_from_slice(original);

    let csum = icmpv6_checksum(dst, src, &icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut response = build_ipv6_header(dst, src, 58, icmp.len());
    response.extend_from_slice(&icmp);
    Ok(response)
}
