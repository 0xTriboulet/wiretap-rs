use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};

mod bind;
mod packet;
mod router;

pub use bind::{NullBind, UdpBind, WireguardBind, WireguardPacket};
pub use packet::{IpHeader, ip_header_len, packet_to_flow, parse_ip_header};
pub use router::{Packet, PacketRouter, Route};

#[derive(Debug)]
pub struct UserspaceStack<B: WireguardBind> {
    bind: B,
    router: PacketRouter,
    udp_proxy: crate::transport::udp::UdpProxy,
    udp_peers: HashMap<UdpFlowKey, SocketAddr>,
}

impl<B: WireguardBind> UserspaceStack<B> {
    pub fn new(bind: B) -> Result<Self> {
        Ok(Self {
            bind,
            router: PacketRouter::new(),
            udp_proxy: crate::transport::udp::UdpProxy::new(),
            udp_peers: HashMap::new(),
        })
    }

    pub fn bind(&self) -> &B {
        &self.bind
    }

    pub fn router(&self) -> &PacketRouter {
        &self.router
    }

    pub fn router_mut(&mut self) -> &mut PacketRouter {
        &mut self.router
    }

    pub fn sync_routes_from_allowed(&mut self, allowed: &[String]) -> Result<()> {
        self.router.add_routes_from_allowed(allowed)
    }

    pub fn sync_routes_from_peers(
        &mut self,
        peers: &[crate::peer::PeerConfig],
    ) -> Result<Vec<SocketAddr>> {
        let mut endpoints = Vec::new();
        for peer in peers {
            let endpoint = resolve_peer_endpoint(peer);
            if let Some(addr) = endpoint {
                endpoints.push(addr);
            }
            for allowed in peer.allowed_ips() {
                self.router.add_route(Route {
                    destination: allowed.clone(),
                    next_hop: None,
                    peer_endpoint: endpoint,
                });
            }
        }
        Ok(endpoints)
    }

    pub fn process_packet(&self, raw: &[u8]) -> Result<Packet> {
        let header = packet::parse_ip_header(raw)?;
        let flow = packet::packet_to_flow(raw)?;
        Ok(Packet {
            flow,
            protocol: header.protocol,
            payload: raw.to_vec(),
        })
    }

    pub fn route_packet(&self, packet: &Packet) -> Option<&Route> {
        self.router.route(packet.flow.dst.ip())
    }

    pub fn route_packet_to_peer(&self, raw: &[u8]) -> Result<WireguardPacket> {
        let packet = self.process_packet(raw)?;
        let route = self
            .route_packet(&packet)
            .ok_or_else(|| anyhow!("no route for packet"))?;
        let mut wg = WireguardPacket::from_bytes(raw.to_vec());
        wg.dst = route.peer_endpoint;
        Ok(wg)
    }

    pub fn send_packet(&mut self, raw: &[u8]) -> Result<()> {
        let packet = self.route_packet_to_peer(raw)?;
        self.bind.send(packet)?;
        Ok(())
    }

    pub fn process_next(&mut self) -> Result<Option<Route>> {
        let packet = self.bind.recv()?;
        let parsed = self.process_packet(&packet.bytes)?;
        let route = self.route_packet(&parsed).cloned();
        if let Some(route) = route.as_ref() {
            let response = match parsed.protocol {
                crate::transport::TransportProtocol::Tcp => {
                    crate::transport::tcp::handle_tcp_packet(&parsed.payload)?
                }
                crate::transport::TransportProtocol::Udp => {
                    let peer = packet.src.or(route.peer_endpoint);
                    if let Ok(flow_key) = udp_flow_key_from_packet(&parsed.payload) {
                        if let Some(peer) = peer {
                            self.udp_peers.insert(flow_key, peer);
                        }
                    }
                    for resp in self.udp_proxy.handle_packet(&parsed.payload)? {
                        self.send_udp_response(resp, peer)?;
                    }
                    None
                }
                crate::transport::TransportProtocol::Icmp => {
                    crate::transport::icmp::handle_icmp_packet(&parsed.payload)?
                }
            };
            if let Some(response) = response {
                let dest = packet.src.or(route.peer_endpoint);
                if let Some(dest) = dest {
                    let mut outbound = WireguardPacket::with_dst(response, dest);
                    outbound.src = None;
                    self.bind.send(outbound)?;
                }
            }

            if matches!(parsed.protocol, crate::transport::TransportProtocol::Udp) {
                let peer = packet.src.or(route.peer_endpoint);
                for resp in self.udp_proxy.poll()? {
                    self.send_udp_response(resp, peer)?;
                }
            }
        }
        Ok(route)
    }

    fn send_udp_response(&mut self, response: Vec<u8>, fallback: Option<SocketAddr>) -> Result<()> {
        let mut dest = fallback;
        if let Ok(flow_key) = udp_flow_key_from_response(&response) {
            if let Some(peer) = self.udp_peers.get(&flow_key) {
                dest = Some(*peer);
            }
        }
        if let Some(dest) = dest {
            let mut outbound = WireguardPacket::with_dst(response, dest);
            outbound.src = None;
            self.bind.send(outbound)?;
        }
        Ok(())
    }
}

pub(crate) fn resolve_peer_endpoint(peer: &crate::peer::PeerConfig) -> Option<SocketAddr> {
    if let Some(addr) = peer.endpoint() {
        return Some(addr);
    }
    let endpoint = peer.endpoint_dns()?;
    endpoint.to_socket_addrs().ok()?.next()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    src: SocketAddr,
    dst: SocketAddr,
}

fn udp_flow_key_from_packet(packet: &[u8]) -> Result<UdpFlowKey> {
    let header = packet::parse_ip_header(packet)?;
    let header_len = packet::ip_header_len(packet)?;
    if packet.len() < header_len + 8 {
        return Err(anyhow!("udp header too short"));
    }
    let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
    let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    Ok(UdpFlowKey {
        src: SocketAddr::new(header.src, src_port),
        dst: SocketAddr::new(header.dst, dst_port),
    })
}

fn udp_flow_key_from_response(packet: &[u8]) -> Result<UdpFlowKey> {
    let header = packet::parse_ip_header(packet)?;
    let header_len = packet::ip_header_len(packet)?;
    if packet.len() < header_len + 8 {
        return Err(anyhow!("udp header too short"));
    }
    let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
    let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    Ok(UdpFlowKey {
        src: SocketAddr::new(header.dst, dst_port),
        dst: SocketAddr::new(header.src, src_port),
    })
}
