use crate::peer::Key;
use anyhow::{anyhow, Result};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use rand_core::{OsRng, RngCore};
use std::net::{IpAddr, SocketAddr, UdpSocket};

pub struct WireguardTunnel {
    tunnel: Tunn,
    socket: UdpSocket,
    peer_addr: SocketAddr,
    rx_buf: Vec<u8>,
    tx_buf: Vec<u8>,
}

impl WireguardTunnel {
    pub fn new(
        private_key: &Key,
        peer_public: &Key,
        preshared: Option<&Key>,
        keepalive: Option<u16>,
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Result<Self> {
        let mut index_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut index_bytes);
        let index = u32::from_le_bytes(index_bytes);

        let static_private = StaticSecret::from(private_key.to_bytes());
        let peer_public = PublicKey::from(peer_public.to_bytes());
        let preshared_key = preshared.map(|k| k.to_bytes());

        let tunnel = Tunn::new(
            static_private,
            peer_public,
            preshared_key,
            keepalive,
            index,
            None,
        )
        .map_err(|e| anyhow!("tunnel init failed: {e}"))?;

        let socket = UdpSocket::bind(listen_addr)?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            tunnel,
            socket,
            peer_addr,
            rx_buf: vec![0u8; 65535],
            tx_buf: vec![0u8; 65535],
        })
    }

    pub fn recv_packets(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        loop {
            match self.socket.recv_from(&mut self.rx_buf) {
                Ok((len, src)) => {
                    if src != self.peer_addr {
                        continue;
                    }
                    let datagram = self.rx_buf[..len].to_vec();
                    self.decapsulate(Some(src.ip()), &datagram, &mut packets)?;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            }
        }

        self.handle_timers(&mut packets)?;
        Ok(packets)
    }

    pub fn send_ip_packet(&mut self, packet: &[u8]) -> Result<()> {
        let result = {
            let buf = &mut self.tx_buf;
            self.tunnel.encapsulate(packet, buf)
        };
        match result {
            TunnResult::Done => Ok(()),
            TunnResult::Err(err) => Err(anyhow!("encapsulate: {err:?}")),
            TunnResult::WriteToNetwork(packet) => {
                self.socket.send_to(packet, self.peer_addr)?;
                Ok(())
            }
            _ => Err(anyhow!("unexpected encapsulate result")),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn set_peer_addr(&mut self, addr: SocketAddr) {
        self.peer_addr = addr;
    }

    fn decapsulate(
        &mut self,
        src: Option<IpAddr>,
        datagram: &[u8],
        packets: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        let result = {
            let buf = &mut self.tx_buf;
            self.tunnel.decapsulate(src, datagram, buf)
        };
        match result {
            TunnResult::Done => {}
            TunnResult::Err(err) => return Err(anyhow!("decapsulate: {err:?}")),
            TunnResult::WriteToNetwork(packet) => {
                self.socket.send_to(packet, self.peer_addr)?;
                self.flush_queued()?;
            }
            TunnResult::WriteToTunnelV4(packet, _) => packets.push(packet.to_vec()),
            TunnResult::WriteToTunnelV6(packet, _) => packets.push(packet.to_vec()),
        }
        Ok(())
    }

    fn flush_queued(&mut self) -> Result<()> {
        loop {
            let result = {
                let buf = &mut self.tx_buf;
                self.tunnel.decapsulate(None, &[], buf)
            };
            match result {
                TunnResult::WriteToNetwork(packet) => {
                    self.socket.send_to(packet, self.peer_addr)?;
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn handle_timers(&mut self, packets: &mut Vec<Vec<u8>>) -> Result<()> {
        let result = {
            let buf = &mut self.tx_buf;
            self.tunnel.update_timers(buf)
        };
        match result {
            TunnResult::WriteToNetwork(packet) => {
                self.socket.send_to(packet, self.peer_addr)?;
            }
            TunnResult::WriteToTunnelV4(packet, _) => packets.push(packet.to_vec()),
            TunnResult::WriteToTunnelV6(packet, _) => packets.push(packet.to_vec()),
            TunnResult::Done => {}
            TunnResult::Err(err) => {
                if is_connection_expired(&err) {
                    return Ok(());
                }
                return Err(anyhow!("update timers: {err:?}"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub keepalive: Option<u16>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
}

struct PeerState {
    public_key: Key,
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<IpNet>,
    tx_buf: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OutboundDatagram {
    pub endpoint: SocketAddr,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct RouteEntry {
    cidr: IpNet,
    peer_index: usize,
}

pub struct MultiPeerTunnel {
    private_key: Key,
    socket: UdpSocket,
    peers: Vec<PeerState>,
    routes: Vec<RouteEntry>,
    rx_buf: Vec<u8>,
}

impl MultiPeerTunnel {
    pub fn new(private_key: &Key, listen_addr: SocketAddr, peers: Vec<PeerConfig>) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr)?;
        socket.set_nonblocking(true)?;

        let mut states = Vec::new();
        let mut routes = Vec::new();
        for (idx, peer) in peers.into_iter().enumerate() {
            let mut index_bytes = [0u8; 4];
            OsRng.fill_bytes(&mut index_bytes);
            let index = u32::from_le_bytes(index_bytes);

            let static_private = StaticSecret::from(private_key.to_bytes());
            let peer_public = PublicKey::from(peer.public_key.to_bytes());
            let preshared_key = peer.preshared_key.map(|k| k.to_bytes());
            let tunnel = Tunn::new(
                static_private,
                peer_public,
                preshared_key,
                peer.keepalive,
                index,
                None,
            )
            .map_err(|e| anyhow!("tunnel init failed: {e}"))?;

            for cidr in &peer.allowed_ips {
                routes.push(RouteEntry {
                    cidr: *cidr,
                    peer_index: idx,
                });
            }

            states.push(PeerState {
                public_key: peer.public_key,
                tunnel,
                endpoint: peer.endpoint,
                allowed_ips: peer.allowed_ips,
                tx_buf: vec![0u8; 65535],
            });
        }

        Ok(Self {
            private_key: *private_key,
            socket,
            peers: states,
            routes,
            rx_buf: vec![0u8; 65535],
        })
    }

    pub fn recv_packets(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        loop {
            match self.socket.recv_from(&mut self.rx_buf) {
                Ok((len, src)) => {
                    let datagram = self.rx_buf[..len].to_vec();
                    if !self.decapsulate_from(src, &datagram, &mut packets)? {
                        continue;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            }
        }

        self.handle_timers(&mut packets)?;
        Ok(packets)
    }

    pub fn send_ip_packet(&mut self, packet: &[u8]) -> Result<()> {
        let parsed = crate::transport::packet::parse_ip_packet(packet)?;
        let peer_index = select_peer_index(&self.routes, parsed.dst)
            .ok_or_else(|| anyhow!("no route for packet"))?;
        let peer = self
            .peers
            .get_mut(peer_index)
            .ok_or_else(|| anyhow!("peer missing"))?;
        let endpoint = peer
            .endpoint
            .ok_or_else(|| anyhow!("peer endpoint missing"))?;
        match peer.tunnel.encapsulate(packet, &mut peer.tx_buf) {
            TunnResult::Done => Ok(()),
            TunnResult::Err(err) => Err(anyhow!("encapsulate: {err:?}")),
            TunnResult::WriteToNetwork(packet) => {
                self.socket.send_to(packet, endpoint)?;
                Ok(())
            }
            _ => Err(anyhow!("unexpected encapsulate result")),
        }
    }

    pub fn add_peer(&mut self, peer: PeerConfig) -> Result<()> {
        if let Some(existing_index) = self
            .peers
            .iter()
            .position(|p| p.public_key == peer.public_key)
        {
            if let Some(endpoint) = peer.endpoint {
                self.peers[existing_index].endpoint = Some(endpoint);
            }
            self.add_allowed_ips(&peer.public_key, &peer.allowed_ips)?;
            return Ok(());
        }

        let mut index_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut index_bytes);
        let index = u32::from_le_bytes(index_bytes);

        let static_private = StaticSecret::from(self.private_key.to_bytes());
        let peer_public = PublicKey::from(peer.public_key.to_bytes());
        let preshared_key = peer.preshared_key.map(|k| k.to_bytes());
        let tunnel = Tunn::new(
            static_private,
            peer_public,
            preshared_key,
            peer.keepalive,
            index,
            None,
        )
        .map_err(|e| anyhow!("tunnel init failed: {e}"))?;

        let peer_index = self.peers.len();
        for cidr in &peer.allowed_ips {
            self.routes.push(RouteEntry {
                cidr: *cidr,
                peer_index,
            });
        }

        self.peers.push(PeerState {
            public_key: peer.public_key,
            tunnel,
            endpoint: peer.endpoint,
            allowed_ips: peer.allowed_ips,
            tx_buf: vec![0u8; 65535],
        });

        Ok(())
    }

    pub fn add_allowed_ips(&mut self, public_key: &Key, allowed_ips: &[IpNet]) -> Result<()> {
        let peer_index = self
            .peers
            .iter()
            .position(|p| p.public_key == *public_key)
            .ok_or_else(|| anyhow!("peer not found"))?;

        for cidr in allowed_ips {
            if self.peers[peer_index].allowed_ips.contains(cidr) {
                continue;
            }
            self.peers[peer_index].allowed_ips.push(*cidr);
            self.routes.push(RouteEntry {
                cidr: *cidr,
                peer_index,
            });
        }

        Ok(())
    }

    fn decapsulate_from(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        packets: &mut Vec<Vec<u8>>,
    ) -> Result<bool> {
        for peer in &mut self.peers {
            match peer
                .tunnel
                .decapsulate(Some(src.ip()), datagram, &mut peer.tx_buf)
            {
                TunnResult::Done => {
                    peer.endpoint = Some(src);
                    return Ok(true);
                }
                TunnResult::Err(err) => {
                    if is_ignorable_decapsulate_error(&err) {
                        continue;
                    }
                    return Err(anyhow!("decapsulate: {err:?}"));
                }
                TunnResult::WriteToNetwork(packet) => {
                    peer.endpoint = Some(src);
                    self.socket.send_to(packet, src)?;
                    flush_queued(&self.socket, peer, packets)?;
                    return Ok(true);
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    peer.endpoint = Some(src);
                    packets.push(packet.to_vec());
                    return Ok(true);
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    peer.endpoint = Some(src);
                    packets.push(packet.to_vec());
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

pub struct MultiPeerSession {
    private_key: Key,
    peers: Vec<PeerState>,
    routes: Vec<RouteEntry>,
}

#[derive(Default)]
pub struct SessionOutput {
    pub packets: Vec<Vec<u8>>,
    pub datagrams: Vec<OutboundDatagram>,
}

impl MultiPeerSession {
    pub fn new(private_key: &Key, peers: Vec<PeerConfig>) -> Result<Self> {
        let mut states = Vec::new();
        let mut routes = Vec::new();
        for (idx, peer) in peers.into_iter().enumerate() {
            let mut index_bytes = [0u8; 4];
            OsRng.fill_bytes(&mut index_bytes);
            let index = u32::from_le_bytes(index_bytes);

            let static_private = StaticSecret::from(private_key.to_bytes());
            let peer_public = PublicKey::from(peer.public_key.to_bytes());
            let preshared_key = peer.preshared_key.map(|k| k.to_bytes());
            let tunnel = Tunn::new(
                static_private,
                peer_public,
                preshared_key,
                peer.keepalive,
                index,
                None,
            )
            .map_err(|e| anyhow!("tunnel init failed: {e}"))?;

            for cidr in &peer.allowed_ips {
                routes.push(RouteEntry {
                    cidr: *cidr,
                    peer_index: idx,
                });
            }

            states.push(PeerState {
                public_key: peer.public_key,
                tunnel,
                endpoint: peer.endpoint,
                allowed_ips: peer.allowed_ips,
                tx_buf: vec![0u8; 65535],
            });
        }

        Ok(Self {
            private_key: *private_key,
            peers: states,
            routes,
        })
    }

    pub fn decapsulate_from(&mut self, src: SocketAddr, datagram: &[u8]) -> Result<SessionOutput> {
        let mut output = SessionOutput::default();
        let matched = self.decapsulate_inner(src, datagram, &mut output)?;
        if !matched {
            return Ok(output);
        }
        Ok(output)
    }

    pub fn send_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<OutboundDatagram>> {
        let parsed = crate::transport::packet::parse_ip_packet(packet)?;
        let peer_index = select_peer_index(&self.routes, parsed.dst)
            .ok_or_else(|| anyhow!("no route for packet"))?;
        let peer = self
            .peers
            .get_mut(peer_index)
            .ok_or_else(|| anyhow!("peer missing"))?;
        let endpoint = peer
            .endpoint
            .ok_or_else(|| anyhow!("peer endpoint missing"))?;
        let mut datagrams = Vec::new();
        match peer.tunnel.encapsulate(packet, &mut peer.tx_buf) {
            TunnResult::Done => {}
            TunnResult::Err(err) => return Err(anyhow!("encapsulate: {err:?}")),
            TunnResult::WriteToNetwork(packet) => {
                datagrams.push(OutboundDatagram {
                    endpoint,
                    bytes: packet.to_vec(),
                });
            }
            _ => return Err(anyhow!("unexpected encapsulate result")),
        }
        Ok(datagrams)
    }

    pub fn update_timers(&mut self) -> Result<SessionOutput> {
        let mut output = SessionOutput::default();
        for peer in &mut self.peers {
            match peer.tunnel.update_timers(&mut peer.tx_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    if let Some(endpoint) = peer.endpoint {
                        output.datagrams.push(OutboundDatagram {
                            endpoint,
                            bytes: packet.to_vec(),
                        });
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) => output.packets.push(packet.to_vec()),
                TunnResult::WriteToTunnelV6(packet, _) => output.packets.push(packet.to_vec()),
                TunnResult::Done => {}
                TunnResult::Err(err) => {
                    if is_connection_expired(&err) {
                        continue;
                    }
                    return Err(anyhow!("update timers: {err:?}"));
                }
            }
        }
        Ok(output)
    }

    pub fn add_peer(&mut self, peer: PeerConfig) -> Result<()> {
        if let Some(existing_index) = self
            .peers
            .iter()
            .position(|p| p.public_key == peer.public_key)
        {
            if let Some(endpoint) = peer.endpoint {
                self.peers[existing_index].endpoint = Some(endpoint);
            }
            self.add_allowed_ips(&peer.public_key, &peer.allowed_ips)?;
            return Ok(());
        }

        let mut index_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut index_bytes);
        let index = u32::from_le_bytes(index_bytes);

        let static_private = StaticSecret::from(self.private_key.to_bytes());
        let peer_public = PublicKey::from(peer.public_key.to_bytes());
        let preshared_key = peer.preshared_key.map(|k| k.to_bytes());
        let tunnel = Tunn::new(
            static_private,
            peer_public,
            preshared_key,
            peer.keepalive,
            index,
            None,
        )
        .map_err(|e| anyhow!("tunnel init failed: {e}"))?;

        let peer_index = self.peers.len();
        for cidr in &peer.allowed_ips {
            self.routes.push(RouteEntry {
                cidr: *cidr,
                peer_index,
            });
        }

        self.peers.push(PeerState {
            public_key: peer.public_key,
            tunnel,
            endpoint: peer.endpoint,
            allowed_ips: peer.allowed_ips,
            tx_buf: vec![0u8; 65535],
        });

        Ok(())
    }

    pub fn add_allowed_ips(&mut self, public_key: &Key, allowed_ips: &[IpNet]) -> Result<()> {
        let peer_index = self
            .peers
            .iter()
            .position(|p| p.public_key == *public_key)
            .ok_or_else(|| anyhow!("peer not found"))?;

        for cidr in allowed_ips {
            if self.peers[peer_index].allowed_ips.contains(cidr) {
                continue;
            }
            self.peers[peer_index].allowed_ips.push(*cidr);
            self.routes.push(RouteEntry {
                cidr: *cidr,
                peer_index,
            });
        }

        Ok(())
    }

    fn decapsulate_inner(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        output: &mut SessionOutput,
    ) -> Result<bool> {
        for peer in &mut self.peers {
            match peer
                .tunnel
                .decapsulate(Some(src.ip()), datagram, &mut peer.tx_buf)
            {
                TunnResult::Done => {
                    peer.endpoint = Some(src);
                    return Ok(true);
                }
                TunnResult::Err(err) => {
                    if is_ignorable_decapsulate_error(&err) {
                        continue;
                    }
                    return Err(anyhow!("decapsulate: {err:?}"));
                }
                TunnResult::WriteToNetwork(packet) => {
                    peer.endpoint = Some(src);
                    output.datagrams.push(OutboundDatagram {
                        endpoint: src,
                        bytes: packet.to_vec(),
                    });
                    flush_queued_session(peer, output)?;
                    return Ok(true);
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    peer.endpoint = Some(src);
                    output.packets.push(packet.to_vec());
                    return Ok(true);
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    peer.endpoint = Some(src);
                    output.packets.push(packet.to_vec());
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

fn flush_queued(
    socket: &UdpSocket,
    peer: &mut PeerState,
    packets: &mut Vec<Vec<u8>>,
) -> Result<()> {
    loop {
        match peer.tunnel.decapsulate(None, &[], &mut peer.tx_buf) {
            TunnResult::WriteToNetwork(packet) => {
                if let Some(endpoint) = peer.endpoint {
                    socket.send_to(packet, endpoint)?;
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) => packets.push(packet.to_vec()),
            TunnResult::WriteToTunnelV6(packet, _) => packets.push(packet.to_vec()),
            _ => break,
        }
    }
    Ok(())
}

fn flush_queued_session(peer: &mut PeerState, output: &mut SessionOutput) -> Result<()> {
    loop {
        match peer.tunnel.decapsulate(None, &[], &mut peer.tx_buf) {
            TunnResult::WriteToNetwork(packet) => {
                if let Some(endpoint) = peer.endpoint {
                    output.datagrams.push(OutboundDatagram {
                        endpoint,
                        bytes: packet.to_vec(),
                    });
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) => output.packets.push(packet.to_vec()),
            TunnResult::WriteToTunnelV6(packet, _) => output.packets.push(packet.to_vec()),
            _ => break,
        }
    }
    Ok(())
}

impl MultiPeerTunnel {
    fn handle_timers(&mut self, packets: &mut Vec<Vec<u8>>) -> Result<()> {
        for peer in &mut self.peers {
            match peer.tunnel.update_timers(&mut peer.tx_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    if let Some(endpoint) = peer.endpoint {
                        self.socket.send_to(packet, endpoint)?;
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) => packets.push(packet.to_vec()),
                TunnResult::WriteToTunnelV6(packet, _) => packets.push(packet.to_vec()),
                TunnResult::Done => {}
                TunnResult::Err(err) => {
                    if is_connection_expired(&err) {
                        continue;
                    }
                    return Err(anyhow!("update timers: {err:?}"));
                }
            }
        }
        Ok(())
    }
}

fn select_peer_index(routes: &[RouteEntry], dst: IpAddr) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut best_prefix = 0u8;
    for route in routes {
        if route.cidr.contains(&dst) {
            let prefix = route.cidr.prefix_len();
            if prefix >= best_prefix {
                best_prefix = prefix;
                best = Some(route.peer_index);
            }
        }
    }
    best
}

fn is_connection_expired(err: &WireGuardError) -> bool {
    matches!(err, WireGuardError::ConnectionExpired)
}

fn is_ignorable_decapsulate_error(err: &WireGuardError) -> bool {
    matches!(
        err,
        WireGuardError::WrongIndex | WireGuardError::WrongKey | WireGuardError::InvalidMac
    )
}

#[cfg(test)]
mod tests {
    use super::{is_ignorable_decapsulate_error, select_peer_index, RouteEntry};
    use boringtun::noise::errors::WireGuardError;
    use ipnet::IpNet;
    use std::net::IpAddr;

    #[test]
    fn select_peer_uses_longest_prefix() {
        let routes = vec![
            RouteEntry {
                cidr: "10.0.0.0/8".parse::<IpNet>().unwrap(),
                peer_index: 0,
            },
            RouteEntry {
                cidr: "10.1.0.0/16".parse::<IpNet>().unwrap(),
                peer_index: 1,
            },
        ];
        let dst = IpAddr::from([10, 1, 2, 3]);
        assert_eq!(select_peer_index(&routes, dst), Some(1));
    }

    #[test]
    fn select_peer_returns_none_on_miss() {
        let routes = vec![RouteEntry {
            cidr: "10.0.0.0/8".parse::<IpNet>().unwrap(),
            peer_index: 0,
        }];
        let dst = IpAddr::from([192, 0, 2, 1]);
        assert!(select_peer_index(&routes, dst).is_none());
    }

    #[test]
    fn ignorable_decapsulate_errors() {
        assert!(is_ignorable_decapsulate_error(&WireGuardError::WrongIndex));
        assert!(is_ignorable_decapsulate_error(&WireGuardError::WrongKey));
        assert!(is_ignorable_decapsulate_error(&WireGuardError::InvalidMac));
    }
}
