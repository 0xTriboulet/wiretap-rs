use anyhow::{anyhow, Result};
use std::net::{SocketAddr, UdpSocket};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WireguardPacket {
    pub bytes: Vec<u8>,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
}

impl WireguardPacket {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            ..Default::default()
        }
    }

    pub fn with_dst(bytes: Vec<u8>, dst: SocketAddr) -> Self {
        Self {
            bytes,
            src: None,
            dst: Some(dst),
        }
    }

    pub fn with_src_dst(bytes: Vec<u8>, src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            bytes,
            src: Some(src),
            dst: Some(dst),
        }
    }
}

pub trait WireguardBind {
    fn recv(&mut self) -> Result<WireguardPacket>;
    fn send(&mut self, packet: WireguardPacket) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct NullBind {
    queued: Vec<WireguardPacket>,
    sent: Vec<WireguardPacket>,
}

impl NullBind {
    pub fn with_packets(packets: Vec<WireguardPacket>) -> Self {
        Self {
            queued: packets,
            sent: Vec::new(),
        }
    }

    pub fn sent(&self) -> &[WireguardPacket] {
        &self.sent
    }
}

impl WireguardBind for NullBind {
    fn recv(&mut self) -> Result<WireguardPacket> {
        if self.queued.is_empty() {
            return Err(anyhow!("bind recv queue empty"));
        }
        Ok(self.queued.remove(0))
    }

    fn send(&mut self, packet: WireguardPacket) -> Result<()> {
        self.sent.push(packet);
        Ok(())
    }
}

#[derive(Debug)]
pub struct UdpBind {
    socket: UdpSocket,
    default_peer: Option<SocketAddr>,
}

impl UdpBind {
    pub fn bind(local: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(local)?;
        Ok(Self {
            socket,
            default_peer: None,
        })
    }

    pub fn with_peer(local: SocketAddr, peer: SocketAddr) -> Result<Self> {
        let mut bind = Self::bind(local)?;
        bind.default_peer = Some(peer);
        Ok(bind)
    }

    pub fn set_default_peer(&mut self, peer: Option<SocketAddr>) {
        self.default_peer = peer;
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

impl WireguardBind for UdpBind {
    fn recv(&mut self) -> Result<WireguardPacket> {
        let mut buf = vec![0u8; 65535];
        let (len, src) = self.socket.recv_from(&mut buf)?;
        buf.truncate(len);
        Ok(WireguardPacket {
            bytes: buf,
            src: Some(src),
            dst: None,
        })
    }

    fn send(&mut self, packet: WireguardPacket) -> Result<()> {
        let dest = packet
            .dst
            .or(self.default_peer)
            .ok_or_else(|| anyhow!("udp bind send missing destination"))?;
        self.socket.send_to(&packet.bytes, dest)?;
        Ok(())
    }
}
