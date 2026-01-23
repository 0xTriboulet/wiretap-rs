use crate::transport::api::{ApiResponse, ApiService, handle_http_request};
use crate::transport::icmp::{build_icmpv4_port_unreachable, build_icmpv6_port_unreachable};
use crate::transport::packet::{
    build_ipv4_header, build_ipv6_header, build_udp_header, parse_ip_packet, parse_tcp_header,
    udp_checksum_ipv4, udp_checksum_ipv6,
};
use anyhow::{Result, anyhow};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::socket::tcp::State;
use smoltcp::socket::udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src: SocketAddr,
    dst: SocketAddr,
}

#[derive(Debug)]
struct TcpConnection {
    handle: SocketHandle,
    dst: SocketAddr,
    stream: Option<TcpStream>,
    api_state: Option<ApiConnState>,
    created_at: StdInstant,
    last_activity: StdInstant,
}

#[derive(Debug)]
struct HostTcpBridge {
    handle: SocketHandle,
    stream: TcpStream,
    local_port: u16,
    created_at: StdInstant,
    last_activity: StdInstant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    src: SocketAddr,
    dst: SocketAddr,
}

#[derive(Debug)]
struct UdpConnection {
    peer: IpEndpoint,
    socket: UdpSocket,
    last_used: StdInstant,
    last_packet: Vec<u8>,
}

#[derive(Debug)]
struct HostUdpExpose {
    handle: SocketHandle,
    socket: UdpSocket,
    remote: SocketAddr,
    local_port: u16,
    last_client: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct TcpProxyConfig {
    pub completion_timeout: Duration,
    pub connect_timeout: Duration,
    pub keepalive_idle: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_count: u32,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            completion_timeout: Duration::from_millis(5_000),
            connect_timeout: Duration::from_millis(5_000),
            keepalive_idle: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(60),
            keepalive_count: 3,
        }
    }
}

impl TcpProxyConfig {
    fn idle_timeout(&self) -> Duration {
        self.keepalive_idle
            + self
                .keepalive_interval
                .saturating_mul(self.keepalive_count)
    }
}

#[derive(Debug, Default)]
struct ApiConnState {
    buffer: Vec<u8>,
    response: Option<Vec<u8>>,
    sent: usize,
}

#[derive(Debug)]
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    caps: DeviceCapabilities,
}

impl QueueDevice {
    fn new() -> Self {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ip;
        let mut checksum = ChecksumCapabilities::default();
        checksum.ipv4 = Checksum::Tx;
        checksum.udp = Checksum::Tx;
        checksum.tcp = Checksum::Tx;
        checksum.icmpv4 = Checksum::Tx;
        checksum.icmpv6 = Checksum::Tx;
        caps.checksum = checksum;
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            caps,
        }
    }

    fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    fn push_tx(&mut self, packet: Vec<u8>) {
        self.tx.push_back(packet);
    }

    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain(..).collect()
    }
}

struct QueueRxToken {
    buffer: Vec<u8>,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.buffer;
        f(&mut buf)
    }
}

struct QueueTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for QueueTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let res = f(&mut buffer);
        self.queue.push_back(buffer);
        res
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = QueueRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(|buffer| {
            (
                QueueRxToken { buffer },
                QueueTxToken {
                    queue: &mut self.tx,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            queue: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

pub struct SmoltcpTcpProxy {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    conns: HashMap<TcpFlowKey, TcpConnection>,
    host_bridges: HashMap<usize, HostTcpBridge>,
    next_bridge_id: usize,
    next_ephemeral_port: u16,
    udp_listeners: HashMap<SocketAddr, SocketHandle>,
    udp_conns: HashMap<UdpFlowKey, UdpConnection>,
    host_udp_exposes: HashMap<crate::transport::api::ExposeTuple, HostUdpExpose>,
    rx_buffer: Vec<u8>,
    udp_buffer: Vec<u8>,
    udp_idle_timeout: Duration,
    udp_last_cleanup: StdInstant,
    localhost_ip: Option<Ipv4Addr>,
    api_service: Option<Arc<Mutex<ApiService>>>,
    api_bind: Option<SocketAddr>,
    tcp_config: TcpProxyConfig,
    local_addrs: Vec<IpAddr>,
}

impl SmoltcpTcpProxy {
    pub fn new(addresses: &[IpAddr], localhost_ip: Option<Ipv4Addr>) -> Result<Self> {
        let mut device = QueueDevice::new();
        let config = IfaceConfig::new(HardwareAddress::Ip);
        let now = SmolInstant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            for addr in addresses {
                let cidr = match addr {
                    IpAddr::V4(ip) => IpCidr::new(IpAddress::Ipv4((*ip).into()), 32),
                    IpAddr::V6(ip) => IpCidr::new(IpAddress::Ipv6((*ip).into()), 128),
                };
                let _ = addrs.push(cidr);
            }
        });
        if let Some(ipv4) = addresses.iter().find_map(|addr| match addr {
            IpAddr::V4(ip) => Some(*ip),
            _ => None,
        }) {
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(smoltcp::wire::Ipv4Address::from(ipv4));
        }
        if let Some(ipv6) = addresses.iter().find_map(|addr| match addr {
            IpAddr::V6(ip) => Some(*ip),
            _ => None,
        }) {
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(smoltcp::wire::Ipv6Address::from(ipv6));
        }

        Ok(Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            conns: HashMap::new(),
            host_bridges: HashMap::new(),
            next_bridge_id: 0,
            next_ephemeral_port: 49152,
            udp_listeners: HashMap::new(),
            udp_conns: HashMap::new(),
            host_udp_exposes: HashMap::new(),
            rx_buffer: vec![0u8; 4096],
            udp_buffer: vec![0u8; 4096],
            udp_idle_timeout: Duration::from_secs(60),
            udp_last_cleanup: StdInstant::now(),
            localhost_ip,
            api_service: None,
            api_bind: None,
            tcp_config: TcpProxyConfig::default(),
            local_addrs: addresses.to_vec(),
        })
    }

    pub fn new_with_config(
        addresses: &[IpAddr],
        localhost_ip: Option<Ipv4Addr>,
        tcp_config: TcpProxyConfig,
    ) -> Result<Self> {
        let mut proxy = Self::new(addresses, localhost_ip)?;
        proxy.tcp_config = tcp_config;
        Ok(proxy)
    }

    pub fn with_api(mut self, service: Arc<Mutex<ApiService>>, bind: SocketAddr) -> Self {
        self.api_service = Some(service);
        self.api_bind = Some(bind);
        self
    }

    pub fn register_host_tcp_bridge(
        &mut self,
        stream: TcpStream,
        remote: SocketAddr,
    ) -> Result<()> {
        stream.set_nonblocking(true)?;
        let local_ip = self
            .local_addrs
            .iter()
            .copied()
            .find(|addr| addr.is_ipv4() == remote.ip().is_ipv4())
            .ok_or_else(|| anyhow!("no local address for {}", remote.ip()))?;
        let local_port = self.allocate_ephemeral_port()?;
        let rx = tcp::SocketBuffer::new(vec![0; 65535]);
        let tx = tcp::SocketBuffer::new(vec![0; 65535]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::from(remote),
                IpListenEndpoint::from(SocketAddr::new(local_ip, local_port)),
            )
            .map_err(|err| anyhow!("smoltcp connect failed: {err:?}"))?;
        let handle = self.sockets.add(socket);
        let id = self.next_bridge_id;
        self.next_bridge_id = self.next_bridge_id.wrapping_add(1);
        let now = StdInstant::now();
        self.host_bridges.insert(
            id,
            HostTcpBridge {
                handle,
                stream,
                local_port,
                created_at: now,
                last_activity: now,
            },
        );
        Ok(())
    }

    pub fn add_udp_expose(&mut self, tuple: crate::transport::api::ExposeTuple) -> Result<()> {
        if tuple.protocol != "udp" {
            return Err(anyhow!("unsupported expose protocol"));
        }
        if self.host_udp_exposes.contains_key(&tuple) {
            return Err(anyhow!("port already exposed"));
        }

        let listen_addr = match tuple.remote_addr {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tuple.remote_port),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), tuple.remote_port),
        };
        let socket = UdpSocket::bind(listen_addr)
            .map_err(|err| anyhow!("udp bind failed: {err}"))?;
        socket.set_nonblocking(true)?;

        let local_ip = self
            .local_addrs
            .iter()
            .copied()
            .find(|addr| addr.is_ipv4() == tuple.remote_addr.is_ipv4())
            .ok_or_else(|| anyhow!("no local address for {}", tuple.remote_addr))?;
        let local_port = self.allocate_ephemeral_port()?;

        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 65535]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 65535]);
        let mut udp_socket = udp::Socket::new(rx, tx);
        udp_socket
            .bind(IpListenEndpoint::from(SocketAddr::new(local_ip, local_port)))
            .map_err(|err| anyhow!("udp bind failed: {err:?}"))?;
        let handle = self.sockets.add(udp_socket);

        let remote = SocketAddr::new(tuple.remote_addr, tuple.local_port);
        self.host_udp_exposes.insert(
            tuple,
            HostUdpExpose {
                handle,
                socket,
                remote,
                local_port,
                last_client: None,
            },
        );
        Ok(())
    }

    pub fn remove_udp_expose(&mut self, tuple: &crate::transport::api::ExposeTuple) -> Result<()> {
        if let Some(expose) = self.host_udp_exposes.remove(tuple) {
            self.sockets.remove(expose.handle);
            Ok(())
        } else {
            Err(anyhow!("not found"))
        }
    }

    pub fn handle_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        let parsed = parse_ip_packet(packet)?;
        match parsed.protocol {
            crate::transport::TransportProtocol::Tcp => {
                let tcp = parse_tcp_header(packet, parsed.header_len)?;
                let key = TcpFlowKey {
                    src: SocketAddr::new(parsed.src, tcp.src_port),
                    dst: SocketAddr::new(parsed.dst, tcp.dst_port),
                };

                if (tcp.flags & 0x02) != 0 && (tcp.flags & 0x10) == 0 {
                    if !self.conns.contains_key(&key) {
                        debug!(
                            src = %key.src,
                            dst = %key.dst,
                            "smoltcp tcp syn received"
                        );
                        self.listen_for_flow(key, parsed.dst, tcp.dst_port)?;
                    }
                }
            }
            crate::transport::TransportProtocol::Udp => {
                let (_, dst_port) = parse_udp_ports(packet, parsed.header_len)?;
                let local = SocketAddr::new(parsed.dst, dst_port);
                self.ensure_udp_listener(local)?;
            }
            crate::transport::TransportProtocol::Icmp => {}
        }

        self.device.push_rx(packet.to_vec());
        self.poll()?;
        let outbound = self.device.drain_tx();
        if !outbound.is_empty() {
            for packet in &outbound {
                match parse_ip_packet(packet) {
                    Ok(parsed) => {
                        if parsed.protocol == crate::transport::TransportProtocol::Tcp {
                            if let Ok(tcp) = parse_tcp_header(packet, parsed.header_len) {
                                debug!(
                                    src = %parsed.src,
                                    dst = %parsed.dst,
                                    flags = tcp.flags,
                                    "smoltcp outbound tcp"
                                );
                            } else {
                                debug!(
                                    src = %parsed.src,
                                    dst = %parsed.dst,
                                    "smoltcp outbound tcp (unparsed header)"
                                );
                            }
                        } else {
                            debug!(
                                src = %parsed.src,
                                dst = %parsed.dst,
                                proto = ?parsed.protocol,
                                "smoltcp outbound ip"
                            );
                        }
                    }
                    Err(err) => {
                        debug!(error = %err, len = packet.len(), "smoltcp outbound unparsed ip");
                    }
                }
            }
        }

        Ok(outbound)
    }

    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.device.drain_tx()
    }

    pub fn poll(&mut self) -> Result<()> {
        let now = SmolInstant::from_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );
        let std_now = StdInstant::now();
        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
        let localhost_ip = self.localhost_ip;

        let mut cleanup = Vec::new();
        let api_service = self.api_service.clone();
        let tcp_config = self.tcp_config.clone();
        for (key, conn) in self.conns.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            if let Some(api_state) = conn.api_state.as_mut() {
                let service = api_service
                    .as_ref()
                    .ok_or_else(|| anyhow!("api service missing"))?;
                let remote = key.src.ip();
                handle_api_socket(socket, api_state, remote, &mut self.rx_buffer, service)?;
                if socket.state() == State::Closed {
                    cleanup.push(*key);
                }
                continue;
            }
            if socket.state() != State::Established {
                if std_now.duration_since(conn.created_at) > tcp_config.completion_timeout {
                    socket.abort();
                    cleanup.push(*key);
                    continue;
                }
            }

            if socket.state() == State::Established && conn.stream.is_none() {
                let dst = map_localhost_addr(conn.dst, localhost_ip);
                debug!(
                    local = %conn.dst,
                    mapped = %dst,
                    "smoltcp tcp established; connecting to host"
                );
                match TcpStream::connect_timeout(&dst, tcp_config.connect_timeout) {
                    Ok(stream) => {
                        stream.set_nonblocking(true)?;
                        conn.stream = Some(stream);
                        conn.last_activity = std_now;
                        debug!(
                            local = %conn.dst,
                            mapped = %dst,
                            "smoltcp tcp host connection established"
                        );
                    }
                    Err(err) => {
                        debug!(
                            local = %conn.dst,
                            mapped = %dst,
                            error = %err,
                            "smoltcp tcp host connection failed"
                        );
                        if err.kind() == std::io::ErrorKind::ConnectionRefused {
                            socket.abort();
                        } else {
                            socket.close();
                        }
                        cleanup.push(*key);
                        continue;
                    }
                }
            }

            if let Some(stream) = conn.stream.as_mut() {
                while socket.can_recv() {
                    let n = socket.recv_slice(&mut self.rx_buffer).unwrap_or(0);
                    if n == 0 {
                        let _ = stream.shutdown(Shutdown::Write);
                        break;
                    }
                    let _ = stream.write_all(&self.rx_buffer[..n]);
                    conn.last_activity = std_now;
                }

                if socket.can_send() {
                    match stream.read(&mut self.rx_buffer) {
                        Ok(0) => {
                            socket.close();
                        }
                        Ok(n) => {
                            let _ = socket.send_slice(&self.rx_buffer[..n]);
                            conn.last_activity = std_now;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {}
                    }
                }
            }

            let idle_timeout = tcp_config.idle_timeout();
            if idle_timeout.as_secs() > 0
                && std_now.duration_since(conn.last_activity) > idle_timeout
            {
                socket.abort();
                cleanup.push(*key);
                continue;
            }

            if !socket.is_open() {
                cleanup.push(*key);
            }
        }

        for key in cleanup {
            if let Some(conn) = self.conns.remove(&key) {
                self.sockets.remove(conn.handle);
            }
        }

        self.poll_host_bridges(std_now, &tcp_config)?;
        self.poll_host_udp_exposes()?;
        self.handle_udp_sockets(now, std_now)?;
        self.cleanup_udp(std_now);

        Ok(())
    }

    fn listen_for_flow(&mut self, key: TcpFlowKey, dst_ip: IpAddr, dst_port: u16) -> Result<()> {
        let now = StdInstant::now();
        let rx = tcp::SocketBuffer::new(vec![0; 65535]);
        let tx = tcp::SocketBuffer::new(vec![0; 65535]);
        let mut socket = tcp::Socket::new(rx, tx);
        let endpoint = IpEndpoint::new(
            match dst_ip {
                IpAddr::V4(ip) => IpAddress::Ipv4(ip.into()),
                IpAddr::V6(ip) => IpAddress::Ipv6(ip.into()),
            },
            dst_port,
        );
        socket
            .listen(endpoint)
            .map_err(|e| anyhow!("listen failed: {e:?}"))?;
        let handle = self.sockets.add(socket);
        let api_state = match self.api_bind {
            Some(bind) if bind.ip() == dst_ip && bind.port() == dst_port => {
                Some(ApiConnState::default())
            }
            _ => None,
        };
        self.conns.insert(
            key,
            TcpConnection {
                handle,
                dst: key.dst,
                stream: None,
                api_state,
                created_at: now,
                last_activity: now,
            },
        );
        Ok(())
    }

    fn ensure_udp_listener(&mut self, local: SocketAddr) -> Result<SocketHandle> {
        if let Some(handle) = self.udp_listeners.get(&local) {
            return Ok(*handle);
        }
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 65535]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 65535]);
        let mut socket = udp::Socket::new(rx, tx);
        let listen = IpListenEndpoint::from(local);
        socket
            .bind(listen)
            .map_err(|err| anyhow!("udp bind failed: {err:?}"))?;
        let handle = self.sockets.add(socket);
        self.udp_listeners.insert(local, handle);
        Ok(handle)
    }

    fn handle_udp_sockets(&mut self, now: SmolInstant, std_now: StdInstant) -> Result<()> {
        let localhost_ip = self.localhost_ip;
        let listener_entries = self
            .udp_listeners
            .iter()
            .map(|(addr, handle)| (*addr, *handle))
            .collect::<Vec<_>>();
        for (local, handle) in listener_entries {
            let mut recv_items = Vec::new();
            {
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                while socket.can_recv() {
                    let (n, meta) = match socket.recv_slice(&mut self.udp_buffer) {
                        Ok((n, meta)) => (n, meta),
                        Err(_) => break,
                    };
                    recv_items.push((self.udp_buffer[..n].to_vec(), meta.endpoint));
                }
            }

            for (payload, endpoint) in recv_items {
                let src = ip_endpoint_to_socketaddr(endpoint)?;
                let key = UdpFlowKey { src, dst: local };
                if !self.udp_conns.contains_key(&key) {
                    let os_socket = make_os_udp_socket(map_localhost_addr(local, localhost_ip))?;
                    self.udp_conns.insert(
                        key,
                        UdpConnection {
                            peer: endpoint,
                            socket: os_socket,
                            last_used: std_now,
                            last_packet: Vec::new(),
                        },
                    );
                }
                if let Some(conn) = self.udp_conns.get_mut(&key) {
                    conn.peer = endpoint;
                    conn.last_used = std_now;
                    conn.last_packet = build_udp_probe_packet(src, local, &payload)?;
                    let _ = conn.socket.send(&payload);
                }
            }
        }

        let mut outbound = Vec::new();
        let mut unreachable = Vec::new();
        let keys = self.udp_conns.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            let Some(conn) = self.udp_conns.get_mut(&key) else {
                continue;
            };
            loop {
                match conn.socket.recv(&mut self.udp_buffer) {
                    Ok(n) => {
                        conn.last_used = std_now;
                        outbound.push((key.dst, conn.peer, self.udp_buffer[..n].to_vec()));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                        if let Ok(resp) = build_icmpv4_port_unreachable(&conn.last_packet) {
                            unreachable.push(resp);
                        } else if let Ok(resp) = build_icmpv6_port_unreachable(&conn.last_packet) {
                            unreachable.push(resp);
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
        }

        for packet in unreachable {
            self.device.push_tx(packet);
        }

        for (local, peer, payload) in outbound {
            let Some(handle) = self.udp_listeners.get(&local).copied() else {
                continue;
            };
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if socket.can_send() {
                let _ = socket.send_slice(&payload, peer);
            }
        }
        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
        Ok(())
    }

    fn poll_host_bridges(&mut self, std_now: StdInstant, tcp_config: &TcpProxyConfig) -> Result<()> {
        let ids = self.host_bridges.keys().cloned().collect::<Vec<_>>();
        let mut cleanup = Vec::new();
        for id in ids {
            let Some(bridge) = self.host_bridges.get_mut(&id) else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(bridge.handle);
            if socket.state() != State::Established
                && std_now.duration_since(bridge.created_at) > tcp_config.completion_timeout
            {
                socket.abort();
                cleanup.push(id);
                continue;
            }

            if socket.can_recv() {
                let n = socket.recv_slice(&mut self.rx_buffer).unwrap_or(0);
                if n > 0 {
                    let _ = bridge.stream.write_all(&self.rx_buffer[..n]);
                    bridge.last_activity = std_now;
                } else {
                    let _ = bridge.stream.shutdown(Shutdown::Write);
                }
            }

            if socket.can_send() {
                match bridge.stream.read(&mut self.rx_buffer) {
                    Ok(0) => {
                        socket.close();
                        cleanup.push(id);
                        continue;
                    }
                    Ok(n) => {
                        let _ = socket.send_slice(&self.rx_buffer[..n]);
                        bridge.last_activity = std_now;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        socket.abort();
                        cleanup.push(id);
                        continue;
                    }
                }
            }

            let idle_timeout = tcp_config.idle_timeout();
            if idle_timeout.as_secs() > 0
                && std_now.duration_since(bridge.last_activity) > idle_timeout
            {
                socket.abort();
                cleanup.push(id);
                continue;
            }

            if !socket.is_open() {
                cleanup.push(id);
            }
        }

        for id in cleanup {
            if let Some(bridge) = self.host_bridges.remove(&id) {
                self.sockets.remove(bridge.handle);
            }
        }
        Ok(())
    }

    fn poll_host_udp_exposes(&mut self) -> Result<()> {
        let tuples = self
            .host_udp_exposes
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for tuple in tuples {
            let mut pending = Vec::new();
            let (handle, last_client) = {
                let Some(expose) = self.host_udp_exposes.get_mut(&tuple) else {
                    continue;
                };
                loop {
                    match expose.socket.recv_from(&mut self.udp_buffer) {
                        Ok((len, src)) => {
                            expose.last_client = Some(src);
                            pending.push((expose.handle, expose.remote, self.udp_buffer[..len].to_vec()));
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
                (expose.handle, expose.last_client)
            };

            for (handle, remote, payload) in pending {
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                let _ = socket.send_slice(&payload, IpEndpoint::from(remote));
            }

            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            while socket.can_recv() {
                let (len, _) = match socket.recv_slice(&mut self.udp_buffer) {
                    Ok((len, meta)) => (len, meta),
                    Err(_) => break,
                };
                if let Some(client) = last_client {
                    let _ = self
                        .host_udp_exposes
                        .get(&tuple)
                        .map(|expose| expose.socket.send_to(&self.udp_buffer[..len], client));
                }
            }
        }
        Ok(())
    }

    fn allocate_ephemeral_port(&mut self) -> Result<u16> {
        for _ in 0..1024 {
            let port = self.next_ephemeral_port;
            self.next_ephemeral_port = if port == 65535 { 49152 } else { port + 1 };
            let used = self.host_bridges.values().any(|bridge| bridge.local_port == port)
                || self
                    .host_udp_exposes
                    .values()
                    .any(|expose| expose.local_port == port);
            if !used {
                return Ok(port);
            }
        }
        Err(anyhow!("no ephemeral ports available"))
    }

    fn cleanup_udp(&mut self, now: StdInstant) {
        if now.duration_since(self.udp_last_cleanup) < Duration::from_secs(5) {
            return;
        }
        self.udp_last_cleanup = now;
        let stale = self
            .udp_conns
            .iter()
            .filter(|(_, conn)| now.duration_since(conn.last_used) > self.udp_idle_timeout)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in stale {
            if let Some(conn) = self.udp_conns.remove(&key) {
                drop(conn);
            }
        }

        let active = self
            .udp_conns
            .keys()
            .map(|key| key.dst)
            .collect::<std::collections::HashSet<_>>();
        let listener_addrs = self.udp_listeners.keys().cloned().collect::<Vec<_>>();
        for addr in listener_addrs {
            if !active.contains(&addr) {
                if let Some(handle) = self.udp_listeners.remove(&addr) {
                    self.sockets.remove(handle);
                }
            }
        }
    }
}

fn map_localhost_addr(addr: SocketAddr, localhost_ip: Option<Ipv4Addr>) -> SocketAddr {
    if let Some(localhost) = localhost_ip {
        if addr.ip() == IpAddr::V4(localhost) {
            return SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
        }
    }
    addr
}

fn parse_udp_ports(packet: &[u8], header_len: usize) -> Result<(u16, u16)> {
    if packet.len() < header_len + 8 {
        return Err(anyhow!("udp header too short"));
    }
    let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
    let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    Ok((src_port, dst_port))
}

fn parse_http_request(buffer: &[u8]) -> Result<Option<(String, String, Vec<u8>, usize)>> {
    let Some(header_end) = find_subsequence(buffer, b"\r\n\r\n") else {
        return Ok(None);
    };
    let header = std::str::from_utf8(&buffer[..header_end])
        .map_err(|err| anyhow!("invalid http header: {err}"))?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("invalid http request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("invalid http method"))?
        .to_string();
    let url = parts
        .next()
        .ok_or_else(|| anyhow!("invalid http url"))?
        .to_string();
    let mut content_len = 0usize;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("content-length") {
            content_len = value.trim().parse::<usize>().unwrap_or(0);
        }
    }
    let total = header_end + 4 + content_len;
    if buffer.len() < total {
        return Ok(None);
    }
    let body = buffer[header_end + 4..total].to_vec();
    Ok(Some((method, url, body, total)))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn build_api_response(result: Result<ApiResponse>) -> Result<Vec<u8>> {
    match result {
        Ok(ApiResponse::Pong(body)) => Ok(http_response(200, body.as_bytes(), "text/plain")),
        Ok(ApiResponse::Ack) => Ok(http_response(200, b"ok", "text/plain")),
        Ok(ApiResponse::ExposeList(list)) => {
            let json = serde_json::to_vec(&list)?;
            Ok(http_response(200, &json, "application/json"))
        }
        Ok(ApiResponse::ServerInfo(configs)) => {
            let json = serde_json::to_vec(&configs)?;
            Ok(http_response(200, &json, "application/json"))
        }
        Ok(ApiResponse::ServerInterfaces(list)) => {
            let json = serde_json::to_vec(&list)?;
            Ok(http_response(200, &json, "application/json"))
        }
        Ok(ApiResponse::Allocated(state)) => {
            let json = serde_json::to_vec(&state)?;
            Ok(http_response(200, &json, "application/json"))
        }
        Err(err) => Ok(http_response(500, err.to_string().as_bytes(), "text/plain")),
    }
}

fn http_response(status: u16, body: &[u8], content_type: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len(),
        content_type
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn handle_api_socket(
    socket: &mut tcp::Socket,
    state: &mut ApiConnState,
    remote: IpAddr,
    rx_buffer: &mut Vec<u8>,
    service: &Arc<Mutex<ApiService>>,
) -> Result<()> {
    while socket.can_recv() {
        let n = socket.recv_slice(rx_buffer).unwrap_or(0);
        if n == 0 {
            break;
        }
        state.buffer.extend_from_slice(&rx_buffer[..n]);
    }

    if state.response.is_none() {
        if let Some((method, url, body, consumed)) = parse_http_request(&state.buffer)? {
            let response = build_api_response(handle_http_request(
                &method,
                &url,
                &body,
                Some(remote),
                service,
            ))?;
            state.response = Some(response);
            state.buffer.drain(..consumed);
        }
    }

    if let Some(response) = state.response.as_ref() {
        while socket.can_send() && state.sent < response.len() {
            let n = socket.send_slice(&response[state.sent..]).unwrap_or(0);
            if n == 0 {
                break;
            }
            state.sent += n;
        }
        if state.sent >= response.len() {
            socket.close();
        }
    }

    Ok(())
}

fn ip_endpoint_to_socketaddr(endpoint: IpEndpoint) -> Result<SocketAddr> {
    let ip: IpAddr = endpoint.addr.into();
    Ok(SocketAddr::new(ip, endpoint.port))
}

fn make_os_udp_socket(dst: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = match dst.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(dst)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn build_udp_probe_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
            let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), 0);
            let mut segment = Vec::with_capacity(8 + payload.len());
            segment.extend_from_slice(&udp_header);
            segment.extend_from_slice(payload);
            let checksum = udp_checksum_ipv4(src_ip, dst_ip, &segment);
            let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), checksum);

            let mut packet = build_ipv4_header(src_ip, dst_ip, 17, 8 + payload.len());
            packet.extend_from_slice(&udp_header);
            packet.extend_from_slice(payload);
            Ok(packet)
        }
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
            let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), 0);
            let mut segment = Vec::with_capacity(8 + payload.len());
            segment.extend_from_slice(&udp_header);
            segment.extend_from_slice(payload);
            let checksum = udp_checksum_ipv6(src_ip, dst_ip, &segment);
            let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), checksum);

            let mut packet = build_ipv6_header(src_ip, dst_ip, 17, 8 + payload.len());
            packet.extend_from_slice(&udp_header);
            packet.extend_from_slice(payload);
            Ok(packet)
        }
        _ => Err(anyhow!("mismatched ip versions")),
    }
}
