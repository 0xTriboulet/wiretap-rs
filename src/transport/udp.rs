use crate::transport::icmp::{build_icmpv4_port_unreachable, build_icmpv6_port_unreachable};
use crate::transport::packet::{
    build_ipv4_header, build_ipv6_header, build_udp_header, parse_ip_packet, udp_checksum_ipv4,
    udp_checksum_ipv6,
};
use anyhow::{Result, anyhow};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: SocketAddr,
    dst: SocketAddr,
}

#[derive(Debug)]
struct UdpConn {
    socket: UdpSocket,
    flow: FlowKey,
    last_used: Instant,
    last_packet: Vec<u8>,
}

impl UdpConn {
    fn new(flow: FlowKey) -> Result<Self> {
        let bind_addr = match flow.dst.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(flow.dst)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            flow,
            last_used: Instant::now(),
            last_packet: Vec::new(),
        })
    }
}

#[derive(Debug)]
pub struct UdpProxy {
    conns: HashMap<FlowKey, UdpConn>,
    pending: VecDeque<Vec<u8>>,
    idle_timeout: Duration,
    last_cleanup: Instant,
}

impl Default for UdpProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpProxy {
    pub fn new() -> Self {
        Self::with_idle_timeout(Duration::from_secs(60))
    }

    pub fn with_idle_timeout(idle_timeout: Duration) -> Self {
        Self {
            conns: HashMap::new(),
            pending: VecDeque::new(),
            idle_timeout,
            last_cleanup: Instant::now(),
        }
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        let parsed = parse_ip_packet(packet)?;
        if parsed.protocol != crate::transport::TransportProtocol::Udp {
            return Err(anyhow!("not a udp packet"));
        }
        let (src_port, dst_port, payload) = parse_udp_segment(packet, parsed.header_len)?;
        let flow = FlowKey {
            src: SocketAddr::new(parsed.src, src_port),
            dst: SocketAddr::new(parsed.dst, dst_port),
        };

        if !self.conns.contains_key(&flow) {
            let conn = UdpConn::new(flow)?;
            self.conns.insert(flow, conn);
        }

        if let Some(conn) = self.conns.get_mut(&flow) {
            conn.last_used = Instant::now();
            let trunc = (parsed.header_len + 8).min(packet.len());
            conn.last_packet = packet[..trunc].to_vec();
            conn.socket.send(payload)?;
        }

        self.read_from_conn(&flow)?;
        self.cleanup_idle();
        Ok(self.drain_pending())
    }

    pub fn poll(&mut self) -> Result<Vec<Vec<u8>>> {
        let keys = self.conns.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            self.read_from_conn(&key)?;
        }
        self.cleanup_idle();
        Ok(self.drain_pending())
    }

    fn read_from_conn(&mut self, key: &FlowKey) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        let mut buf = vec![0u8; 4096];
        loop {
            match conn.socket.recv(&mut buf) {
                Ok(n) => {
                    let payload = &buf[..n];
                    let response = build_udp_response(conn.flow, payload)?;
                    self.pending.push_back(response);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                    if let Ok(resp) = build_icmpv4_port_unreachable(&conn.last_packet) {
                        self.pending.push_back(resp);
                    } else if let Ok(resp) = build_icmpv6_port_unreachable(&conn.last_packet) {
                        self.pending.push_back(resp);
                    }
                    break;
                }
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn cleanup_idle(&mut self) {
        if self.last_cleanup.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.last_cleanup = Instant::now();
        let cutoff = Instant::now() - self.idle_timeout;
        let stale = self
            .conns
            .iter()
            .filter(|(_, conn)| conn.last_used < cutoff)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in stale {
            self.conns.remove(&key);
        }
    }

    fn drain_pending(&mut self) -> Vec<Vec<u8>> {
        self.pending.drain(..).collect()
    }
}

pub fn handle_udp_packet(packet: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut proxy = UdpProxy::new();
    let mut responses = proxy.handle_packet(packet)?;
    for _ in 0..5 {
        if !responses.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        responses = proxy.poll()?;
    }
    Ok(responses.pop())
}

fn parse_udp_segment(packet: &[u8], offset: usize) -> Result<(u16, u16, &[u8])> {
    if packet.len() < offset + 8 {
        return Err(anyhow!("udp header too short"));
    }
    let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let payload = &packet[offset + 8..];
    Ok((src_port, dst_port, payload))
}

fn build_udp_response(flow: FlowKey, payload: &[u8]) -> Result<Vec<u8>> {
    match (flow.src.ip(), flow.dst.ip()) {
        (IpAddr::V4(client_ip), IpAddr::V4(server_ip)) => {
            let udp_header = build_udp_header(flow.dst.port(), flow.src.port(), payload.len(), 0);
            let mut segment = Vec::with_capacity(8 + payload.len());
            segment.extend_from_slice(&udp_header);
            segment.extend_from_slice(payload);
            let checksum = udp_checksum_ipv4(server_ip, client_ip, &segment);
            let udp_header =
                build_udp_header(flow.dst.port(), flow.src.port(), payload.len(), checksum);

            let mut response = build_ipv4_header(server_ip, client_ip, 17, 8 + payload.len());
            response.extend_from_slice(&udp_header);
            response.extend_from_slice(payload);
            Ok(response)
        }
        (IpAddr::V6(client_ip), IpAddr::V6(server_ip)) => {
            let udp_header = build_udp_header(flow.dst.port(), flow.src.port(), payload.len(), 0);
            let mut segment = Vec::with_capacity(8 + payload.len());
            segment.extend_from_slice(&udp_header);
            segment.extend_from_slice(payload);
            let checksum = udp_checksum_ipv6(server_ip, client_ip, &segment);
            let udp_header =
                build_udp_header(flow.dst.port(), flow.src.port(), payload.len(), checksum);

            let mut response = build_ipv6_header(server_ip, client_ip, 17, 8 + payload.len());
            response.extend_from_slice(&udp_header);
            response.extend_from_slice(payload);
            Ok(response)
        }
        _ => Err(anyhow!("mismatched ip versions")),
    }
}
