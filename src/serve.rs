use crate::constants;
use crate::peer::{Config, PeerConfigArgs, ServerConfig, parse_server_config};
use crate::transport::api::{ApiService, ExposeCommand, ExposeTuple, run_http_api};
use crate::transport::smoltcp::{SmoltcpTcpProxy, TcpProxyConfig};
use crate::transport::userspace::{UdpBind, UserspaceStack, WireguardBind, resolve_peer_endpoint};
use crate::transport::wireguard::{
    MultiPeerSession, MultiPeerTunnel, OutboundDatagram, PeerConfig as WgPeerConfig,
};
use crate::transport::{
    icmp,
    packet::{build_udp_packet, parse_ip_packet, parse_udp_packet},
};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

#[derive(Clone, Debug)]
pub struct ServeOptions {
    pub simple: bool,
    pub quiet: bool,
    pub api_addr: Option<IpAddr>,
    pub api_port: u16,
    pub disable_ipv6: bool,
    pub delete_config: bool,
    pub wireguard_keepalive_secs: u16,
    pub completion_timeout_ms: u64,
    pub conn_timeout_ms: u64,
    pub keepalive_idle_secs: u64,
    pub keepalive_interval_secs: u64,
    pub keepalive_count: u32,
    pub allocation_state_path: Option<PathBuf>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            simple: false,
            quiet: false,
            api_addr: None,
            api_port: constants::API_PORT,
            disable_ipv6: false,
            delete_config: false,
            wireguard_keepalive_secs: constants::DEFAULT_KEEPALIVE,
            completion_timeout_ms: constants::DEFAULT_COMPLETION_TIMEOUT_MS,
            conn_timeout_ms: constants::DEFAULT_CONN_TIMEOUT_MS,
            keepalive_idle_secs: constants::DEFAULT_KEEPALIVE_IDLE_SECS,
            keepalive_interval_secs: constants::DEFAULT_KEEPALIVE_INTERVAL_SECS,
            keepalive_count: constants::DEFAULT_KEEPALIVE_COUNT,
            allocation_state_path: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ServerEnv {
    values: HashMap<String, String>,
}

impl ServerEnv {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|v| v.as_str())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        let value = self.get(key)?.trim().to_ascii_lowercase();
        match value.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    }

    pub fn from_env() -> Self {
        let values = std::env::vars()
            .filter(|(key, _)| key.starts_with("WIRETAP_"))
            .collect();
        Self { values }
    }
}

impl From<HashMap<String, String>> for ServerEnv {
    fn from(values: HashMap<String, String>) -> Self {
        Self { values }
    }
}

pub(crate) fn resolve_allocation_state_path(
    env: &ServerEnv,
) -> Option<PathBuf> {
    if let Some(value) = env.get("WIRETAP_ALLOCATION_STATE") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
        return None;
    }
    None
}

pub fn load_server_config(file_contents: Option<&str>, env: &ServerEnv) -> Result<ServerConfig> {
    if let Some(contents) = file_contents {
        let mut config = parse_server_config(contents)?;
        apply_env_overrides(&mut config, env)?;
        return Ok(config);
    }

    let relay_private = env
        .get("WIRETAP_RELAY_INTERFACE_PRIVATEKEY")
        .ok_or_else(|| anyhow!("missing WIRETAP_RELAY_INTERFACE_PRIVATEKEY"))?;

    let mut relay = Config::new()?;
    relay.set_private_key(relay_private)?;

    if let Some(ipv4) = env.get("WIRETAP_RELAY_INTERFACE_IPV4") {
        relay.add_address(&format!("{}/32", ipv4))?;
    }
    if let Some(ipv6) = env.get("WIRETAP_RELAY_INTERFACE_IPV6") {
        relay.add_address(&format!("{}/128", ipv6))?;
    }
    if let Some(port) = env.get("WIRETAP_RELAY_INTERFACE_PORT") {
        relay.set_port(port.parse::<u16>()?)?;
    }
    if let Some(mtu) = env.get("WIRETAP_RELAY_INTERFACE_MTU") {
        relay.set_mtu(mtu.parse::<u16>()?)?;
    }
    if let Some(localhost) = env.get("WIRETAP_RELAY_INTERFACE_LOCALHOSTIP") {
        relay.set_localhost_ip(localhost)?;
    }

    let relay_peer_public = env
        .get("WIRETAP_RELAY_PEER_PUBLICKEY")
        .ok_or_else(|| anyhow!("missing WIRETAP_RELAY_PEER_PUBLICKEY"))?;
    let relay_peer_allowed = env
        .get("WIRETAP_RELAY_PEER_ALLOWED")
        .ok_or_else(|| anyhow!("missing WIRETAP_RELAY_PEER_ALLOWED"))?;

    let mut relay_peer_args = PeerConfigArgs::default();
    relay_peer_args.public_key = Some(relay_peer_public.to_string());
    relay_peer_args.allowed_ips = relay_peer_allowed
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    if let Some(endpoint) = env.get("WIRETAP_RELAY_PEER_ENDPOINT") {
        relay_peer_args.endpoint = Some(endpoint.to_string());
    }
    if let Some(preshared) = env.get("WIRETAP_RELAY_PEER_PRESHAREDKEY") {
        relay_peer_args.preshared_key = Some(preshared.to_string());
    }

    relay.add_peer(crate::peer::PeerConfig::from_args(relay_peer_args)?);

    let e2ee_private = env.get("WIRETAP_E2EE_INTERFACE_PRIVATEKEY");
    if e2ee_private.is_none() {
        return Ok(ServerConfig { relay, e2ee: None });
    }

    let mut e2ee = Config::new()?;
    e2ee.set_private_key(e2ee_private.unwrap())?;

    if let Some(api) = env.get("WIRETAP_E2EE_INTERFACE_API") {
        e2ee.add_address(&format!("{}/128", api))?;
    }

    let e2ee_peer_public = env
        .get("WIRETAP_E2EE_PEER_PUBLICKEY")
        .ok_or_else(|| anyhow!("missing WIRETAP_E2EE_PEER_PUBLICKEY"))?;
    let mut e2ee_peer_args = PeerConfigArgs::default();
    e2ee_peer_args.public_key = Some(e2ee_peer_public.to_string());
    if let Some(endpoint) = env.get("WIRETAP_E2EE_PEER_ENDPOINT") {
        e2ee_peer_args.endpoint = Some(endpoint.to_string());
    }
    e2ee.add_peer(crate::peer::PeerConfig::from_args(e2ee_peer_args)?);

    Ok(ServerConfig {
        relay,
        e2ee: Some(e2ee),
    })
}

fn apply_env_overrides(config: &mut ServerConfig, env: &ServerEnv) -> Result<()> {
    if let Some(key) = env.get("WIRETAP_RELAY_INTERFACE_PRIVATEKEY") {
        config.relay.set_private_key(key)?;
    }
    if let Some(port) = env.get("WIRETAP_RELAY_INTERFACE_PORT") {
        config.relay.set_port(port.parse::<u16>()?)?;
    }
    if let Some(mtu) = env.get("WIRETAP_RELAY_INTERFACE_MTU") {
        config.relay.set_mtu(mtu.parse::<u16>()?)?;
    }
    if let Some(localhost) = env.get("WIRETAP_RELAY_INTERFACE_LOCALHOSTIP") {
        config.relay.set_localhost_ip(localhost)?;
    }

    let relay_ipv4 = env.get("WIRETAP_RELAY_INTERFACE_IPV4");
    let relay_ipv6 = env.get("WIRETAP_RELAY_INTERFACE_IPV6");
    if relay_ipv4.is_some() || relay_ipv6.is_some() {
        let mut addrs = Vec::new();
        if let Some(ipv4) = relay_ipv4 {
            addrs.push(format!("{}/32", ipv4));
        } else {
            for net in config
                .relay
                .addresses()
                .iter()
                .filter(|net| net.addr().is_ipv4())
            {
                addrs.push(net.to_string());
            }
        }
        if let Some(ipv6) = relay_ipv6 {
            addrs.push(format!("{}/128", ipv6));
        } else {
            for net in config
                .relay
                .addresses()
                .iter()
                .filter(|net| net.addr().is_ipv6())
            {
                addrs.push(net.to_string());
            }
        }
        config.relay.set_addresses(&addrs)?;
    }

    let relay_peer_override = env.get("WIRETAP_RELAY_PEER_PUBLICKEY").is_some()
        || env.get("WIRETAP_RELAY_PEER_ALLOWED").is_some()
        || env.get("WIRETAP_RELAY_PEER_ENDPOINT").is_some()
        || env.get("WIRETAP_RELAY_PEER_PRESHAREDKEY").is_some();
    if relay_peer_override {
        if config.relay.peers().is_empty() {
            let mut args = PeerConfigArgs::default();
            if let Some(public_key) = env.get("WIRETAP_RELAY_PEER_PUBLICKEY") {
                args.public_key = Some(public_key.to_string());
            }
            if let Some(allowed) = env.get("WIRETAP_RELAY_PEER_ALLOWED") {
                args.allowed_ips = allowed
                    .split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect();
            }
            if let Some(endpoint) = env.get("WIRETAP_RELAY_PEER_ENDPOINT") {
                args.endpoint = Some(endpoint.to_string());
            }
            if let Some(preshared) = env.get("WIRETAP_RELAY_PEER_PRESHAREDKEY") {
                args.preshared_key = Some(preshared.to_string());
            }
            if args.public_key.is_some() {
                config
                    .relay
                    .add_peer(crate::peer::PeerConfig::from_args(args)?);
            }
        }
        if let Some(peer) = config.relay.peers_mut().first_mut() {
            if let Some(public_key) = env.get("WIRETAP_RELAY_PEER_PUBLICKEY") {
                peer.set_public_key(public_key)?;
            }
            if let Some(allowed) = env.get("WIRETAP_RELAY_PEER_ALLOWED") {
                let parts = allowed
                    .split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>();
                peer.set_allowed_ips(&parts)?;
            }
            if let Some(endpoint) = env.get("WIRETAP_RELAY_PEER_ENDPOINT") {
                peer.set_endpoint(endpoint)?;
            }
            if let Some(preshared) = env.get("WIRETAP_RELAY_PEER_PRESHAREDKEY") {
                peer.set_preshared_key(preshared)?;
            }
        }
    }

    let e2ee_override = env.get("WIRETAP_E2EE_INTERFACE_PRIVATEKEY").is_some()
        || env.get("WIRETAP_E2EE_INTERFACE_API").is_some()
        || env.get("WIRETAP_E2EE_PEER_PUBLICKEY").is_some()
        || env.get("WIRETAP_E2EE_PEER_ENDPOINT").is_some();
    if e2ee_override && config.e2ee.is_none() {
        if let Some(private_key) = env.get("WIRETAP_E2EE_INTERFACE_PRIVATEKEY") {
            let mut e2ee = Config::new()?;
            e2ee.set_private_key(private_key)?;
            config.e2ee = Some(e2ee);
        }
    }

    if let Some(e2ee) = config.e2ee.as_mut() {
        if let Some(private_key) = env.get("WIRETAP_E2EE_INTERFACE_PRIVATEKEY") {
            e2ee.set_private_key(private_key)?;
        }
        if let Some(api) = env.get("WIRETAP_E2EE_INTERFACE_API") {
            let addrs = vec![format!("{}/128", api)];
            e2ee.set_addresses(&addrs)?;
        }

        let e2ee_peer_override = env.get("WIRETAP_E2EE_PEER_PUBLICKEY").is_some()
            || env.get("WIRETAP_E2EE_PEER_ENDPOINT").is_some();
        if e2ee_peer_override && e2ee.peers().is_empty() {
            let mut args = PeerConfigArgs::default();
            if let Some(public_key) = env.get("WIRETAP_E2EE_PEER_PUBLICKEY") {
                args.public_key = Some(public_key.to_string());
            }
            if let Some(endpoint) = env.get("WIRETAP_E2EE_PEER_ENDPOINT") {
                args.endpoint = Some(endpoint.to_string());
            }
            if args.public_key.is_some() {
                e2ee.add_peer(crate::peer::PeerConfig::from_args(args)?);
            }
        }
        if let Some(peer) = e2ee.peers_mut().first_mut() {
            if let Some(public_key) = env.get("WIRETAP_E2EE_PEER_PUBLICKEY") {
                peer.set_public_key(public_key)?;
            }
            if let Some(endpoint) = env.get("WIRETAP_E2EE_PEER_ENDPOINT") {
                peer.set_endpoint(endpoint)?;
            }
        }
    }

    Ok(())
}

pub fn apply_serve_options(
    mut config: ServerConfig,
    options: ServeOptions,
) -> Result<ServerConfig> {
    if options.wireguard_keepalive_secs > 0 {
        for peer in config.relay.peers_mut() {
            if peer.keepalive().is_none() {
                peer.set_keepalive(options.wireguard_keepalive_secs)?;
            }
        }
        if let Some(e2ee) = config.e2ee.as_mut() {
            let relay_keepalive = config
                .relay
                .peers()
                .first()
                .and_then(|peer| peer.keepalive());
            if let Some(keepalive) = relay_keepalive {
                for peer in e2ee.peers_mut() {
                    if peer.keepalive().is_none() {
                        peer.set_keepalive(keepalive)?;
                    }
                }
            }
        }
    }

    if options.disable_ipv6 {
        config.relay = strip_ipv6(config.relay)?;
        if let Some(e2ee) = config.e2ee.take() {
            config.e2ee = Some(strip_ipv6(e2ee)?);
        }
    }

    if let Some(e2ee) = config.e2ee.as_mut() {
        let has_e2ee_v4 = e2ee.addresses().iter().any(|net| match net.addr() {
            IpAddr::V4(addr) => constants::e2ee_subnet_v4().contains(&addr),
            _ => false,
        });
        if !has_e2ee_v4 {
            e2ee.add_address(&format!(
                "{}/32",
                constants::default_server_e2ee_v4()
            ))?;
        }
        if !options.disable_ipv6 {
            let has_e2ee_v6 = e2ee.addresses().iter().any(|net| match net.addr() {
                IpAddr::V6(addr) => constants::e2ee_subnet_v6().contains(&addr),
                _ => false,
            });
            if !has_e2ee_v6 {
                e2ee.add_address(&format!(
                    "{}/128",
                    constants::default_server_e2ee_v6()
                ))?;
            }
        }
    }

    let default_relay_allowed = {
        let mut allowed = vec![format!("{}/32", constants::default_client_relay_v4())];
        if !options.disable_ipv6 {
            allowed.push(format!("{}/128", constants::default_client_relay_v6()));
        }
        allowed
    };
    for peer in config.relay.peers_mut() {
        if peer.allowed_ips().is_empty() {
            peer.set_allowed_ips(&default_relay_allowed)?;
        }
    }

    if let Some(e2ee) = config.e2ee.as_mut() {
        let default_e2ee_allowed = {
            let mut allowed = vec![format!("{}/32", constants::default_client_e2ee_v4())];
            if !options.disable_ipv6 {
                allowed.push(format!("{}/128", constants::default_client_e2ee_v6()));
            }
            allowed
        };
        for peer in e2ee.peers_mut() {
            if peer.allowed_ips().is_empty() {
                peer.set_allowed_ips(&default_e2ee_allowed)?;
            }
        }
    }

    if options.simple {
        config.e2ee = None;
    }

    if config
        .e2ee
        .as_ref()
        .is_some_and(|e2ee| e2ee.peers().is_empty())
    {
        if !options.quiet {
            println!("E2EE peer public key missing, running Wiretap in simple mode.");
        }
        config.e2ee = None;
    }

    Ok(config)
}

pub fn build_userspace_stack(
    config: &ServerConfig,
    bind_addr: Option<SocketAddr>,
) -> Result<UserspaceStack<UdpBind>> {
    let bind_addr = match bind_addr {
        Some(addr) => addr,
        None => default_bind_addr(config)?,
    };

    let peer_endpoints = collect_peer_endpoints(config.relay.peers());
    let bind = if peer_endpoints.len() == 1 {
        UdpBind::with_peer(bind_addr, peer_endpoints[0])?
    } else {
        UdpBind::bind(bind_addr)?
    };

    let mut stack = UserspaceStack::new(bind)?;
    stack.sync_routes_from_peers(config.relay.peers())?;
    Ok(stack)
}

pub fn run_loop(
    config: &ServerConfig,
    bind_addr: Option<SocketAddr>,
    options: &ServeOptions,
) -> Result<()> {
    if let Some(localhost) = config.relay.localhost_ip() {
        log_localhost_forwarding(localhost, options.quiet);
    }
    if config.e2ee.is_some() {
        run_e2ee_over_relay(config, bind_addr, options)
    } else {
        let tunnel = build_relay_tunnel(config, bind_addr)?;
        let service = build_api_service(config, Some(tunnel.clone()), None, options)?;
        run_wireguard_smoltcp_with_tunnel(config, tunnel, options, Some(service))
    }
}

/// Single-iteration userspace serve loop; consumes one packet if available.
pub fn run_once<B: WireguardBind>(
    stack: &mut UserspaceStack<B>,
) -> Result<Option<crate::transport::userspace::Route>> {
    stack.process_next()
}

pub fn delete_config_file(path: &str) -> Result<()> {
    std::fs::remove_file(path)?;
    Ok(())
}

fn strip_ipv6(config: Config) -> Result<Config> {
    let addresses = config
        .addresses()
        .iter()
        .filter(|net| net.addr().is_ipv4())
        .map(|net| net.to_string())
        .collect::<Vec<_>>();
    let peers = config.peers().to_vec();
    let preshared = config.preshared_key();
    let mut config = Config::from_args(crate::peer::ConfigArgs {
        private_key: Some(config.private_key().to_string()),
        listen_port: config.port(),
        mtu: config.mtu(),
        addresses,
        ..Default::default()
    })?;
    if let Some(key) = preshared {
        config.set_preshared_key(&key.to_string())?;
    }

    for peer in peers {
        let allowed = peer
            .allowed_ips()
            .iter()
            .filter(|net| net.addr().is_ipv4())
            .map(|net| net.to_string())
            .collect::<Vec<_>>();
        let mut args = PeerConfigArgs::default();
        args.public_key = Some(peer.public_key().to_string());
        if let Some(endpoint) = peer.endpoint() {
            args.endpoint = Some(endpoint.to_string());
        } else if let Some(endpoint) = peer.endpoint_dns() {
            args.endpoint = Some(endpoint.to_string());
        }
        args.allowed_ips = allowed;
        args.persistent_keepalive = peer.keepalive();
        args.nickname = peer.nickname().map(|v| v.to_string());
        if let Some(key) = peer.preshared_key() {
            args.preshared_key = Some(key.to_string());
        }

        config.add_peer(crate::peer::PeerConfig::from_args(args)?);
    }

    Ok(config)
}

fn default_bind_addr(config: &ServerConfig) -> Result<SocketAddr> {
    let port = config
        .relay
        .port()
        .ok_or_else(|| anyhow!("relay port missing"))?;
    let has_ipv6 = config
        .relay
        .addresses()
        .iter()
        .any(|net| net.addr().is_ipv6());
    let has_ipv4 = config
        .relay
        .addresses()
        .iter()
        .any(|net| net.addr().is_ipv4());
    let ip = if has_ipv6 && !has_ipv4 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    Ok(SocketAddr::new(ip, port))
}

fn collect_peer_endpoints(peers: &[crate::peer::PeerConfig]) -> Vec<SocketAddr> {
    let mut endpoints = Vec::new();
    for peer in peers {
        if let Some(addr) = resolve_peer_endpoint(peer) {
            endpoints.push(addr);
        }
    }
    endpoints
}

fn build_api_service(
    config: &ServerConfig,
    relay_tunnel: Option<Arc<Mutex<MultiPeerTunnel>>>,
    e2ee_tunnel: Option<Arc<Mutex<MultiPeerSession>>>,
    options: &ServeOptions,
) -> Result<Arc<Mutex<ApiService>>> {
    let mut service = ApiService::with_configs(Some(config.relay.clone()), config.e2ee.clone())
        .with_interfaces(crate::transport::api::collect_host_interfaces());
    if let Some(tunnel) = relay_tunnel {
        service = service.with_relay_tunnel(tunnel);
    }
    if let Some(tunnel) = e2ee_tunnel {
        service = service.with_e2ee_tunnel(tunnel);
    }
    if let Some(path) = options.allocation_state_path.as_ref() {
        service.set_allocation_state_path(path)?;
    }
    Ok(Arc::new(Mutex::new(service)))
}

#[allow(dead_code)]
fn start_api_server(
    config: &ServerConfig,
    options: &ServeOptions,
    service: Arc<Mutex<ApiService>>,
) -> Result<Option<JoinHandle<()>>> {
    let Some(bind) = api_bind_addr(config, options) else {
        return Ok(None);
    };

    let mut last_err = None;
    let mut candidates = vec![bind];
    if api_localhost_mapping(config, options).is_some() {
        candidates.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            options.api_port,
        ));
    }

    for candidate in candidates {
        match run_http_api(candidate, service.clone()) {
            Ok(handle) => {
                if !options.quiet {
                    println!("API server listening on {}", candidate);
                }
                return Ok(Some(handle));
            }
            Err(err) => {
                last_err = Some((candidate, err));
            }
        }
    }

    if let Some((candidate, err)) = last_err {
        if !options.quiet {
            eprintln!("API server failed to bind on {}: {}", candidate, err);
        }
    }
    Ok(None)
}

pub(crate) fn api_bind_addr(config: &ServerConfig, options: &ServeOptions) -> Option<SocketAddr> {
    if let Some(addr) = options.api_addr {
        let bind = if options.disable_ipv6 && addr.is_ipv6() {
            IpAddr::V4(constants::default_api_v4())
        } else {
            addr
        };
        return Some(SocketAddr::new(bind, options.api_port));
    }

    if let Some(e2ee) = config.e2ee.as_ref() {
        if let Some(net) = e2ee.addresses().first() {
            return Some(SocketAddr::new(net.addr(), options.api_port));
        }
    }

    let has_ipv6 = config
        .relay
        .addresses()
        .iter()
        .any(|net| net.addr().is_ipv6());
    let api_addr = if options.disable_ipv6 {
        IpAddr::V4(constants::default_api_v4())
    } else if has_ipv6 {
        IpAddr::V6(constants::default_api_v6())
    } else {
        IpAddr::V4(constants::default_api_v4())
    };
    Some(SocketAddr::new(api_addr, options.api_port))
}

pub fn run_wireguard_smoltcp(config: &ServerConfig, bind_addr: Option<SocketAddr>) -> Result<()> {
    let tunnel = build_relay_tunnel(config, bind_addr)?;
    run_wireguard_smoltcp_with_tunnel(config, tunnel, &ServeOptions::default(), None)
}

pub fn run_wireguard_smoltcp_with_tunnel(
    config: &ServerConfig,
    tunnel: Arc<Mutex<MultiPeerTunnel>>,
    options: &ServeOptions,
    api_service: Option<Arc<Mutex<ApiService>>>,
) -> Result<()> {
    let (expose_tx, expose_rx) = std::sync::mpsc::channel();
    let (bridge_tx, bridge_rx) = std::sync::mpsc::channel();
    let mut expose_manager = ExposeManager::new(expose_rx, bridge_tx);

    let addresses = collect_smoltcp_addresses(config, options);
    let localhost_ip = localhost_mapping(config, options);
    let tcp_config = tcp_proxy_config(options);
    let mut tcp_proxy = SmoltcpTcpProxy::new_with_config(&addresses, localhost_ip, tcp_config)?;
    if let Some(service) = api_service {
        if let Ok(mut svc) = service.lock() {
            svc.set_expose_tx(expose_tx);
        }
        if let Some(bind) = api_bind_addr(config, options) {
            tcp_proxy = tcp_proxy.with_api(service, bind);
        }
    }
    let ping = icmp::SystemPing::with_default_timeout();

    loop {
        let packets = {
            let mut tunnel = tunnel
                .lock()
                .map_err(|_| anyhow!("relay tunnel poisoned"))?;
            tunnel.recv_packets()?
        };
        let mut outbound = Vec::new();
        for packet in packets {
            let parsed = parse_ip_packet(&packet)?;
            match parsed.protocol {
                crate::transport::TransportProtocol::Tcp
                | crate::transport::TransportProtocol::Udp => {
                    let outgoing = tcp_proxy.handle_ip_packet(&packet)?;
                    outbound.extend(outgoing);
                }
                crate::transport::TransportProtocol::Icmp => {
                    if let Some(resp) = icmp::handle_icmp_packet_with_ping(&packet, &ping)? {
                        outbound.push(resp);
                    }
                }
            }
        }

        tcp_proxy.poll()?;
        for out in tcp_proxy.drain_outbound() {
            outbound.push(out);
        }

        if !outbound.is_empty() {
            let mut tunnel = tunnel
                .lock()
                .map_err(|_| anyhow!("relay tunnel poisoned"))?;
            for out in outbound {
                if let Err(err) = tunnel.send_ip_packet(&out) {
                    if is_peer_endpoint_missing(&err) {
                        tracing::warn!(error = %err, "peer endpoint missing; waiting for handshake");
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        expose_manager.poll(&mut tcp_proxy);
        while let Ok(req) = bridge_rx.try_recv() {
            let _ = tcp_proxy.register_host_tcp_bridge(req.stream, req.remote);
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn run_e2ee_over_relay(
    config: &ServerConfig,
    bind_addr: Option<SocketAddr>,
    options: &ServeOptions,
) -> Result<()> {
    let relay_tunnel = build_relay_tunnel(config, bind_addr)?;
    let e2ee_tunnel = build_e2ee_session(config)?;
    let e2ee_port = e2ee_listen_port(config);
    let service = build_api_service(
        config,
        Some(relay_tunnel.clone()),
        Some(e2ee_tunnel.clone()),
        options,
    )?;
    run_e2ee_smoltcp_with_tunnel(
        config,
        relay_tunnel,
        e2ee_tunnel,
        e2ee_port,
        options,
        Some(service),
    )
}

fn run_e2ee_smoltcp_with_tunnel(
    config: &ServerConfig,
    relay_tunnel: Arc<Mutex<MultiPeerTunnel>>,
    e2ee_tunnel: Arc<Mutex<MultiPeerSession>>,
    e2ee_port: u16,
    options: &ServeOptions,
    api_service: Option<Arc<Mutex<ApiService>>>,
) -> Result<()> {
    let (expose_tx, expose_rx) = std::sync::mpsc::channel();
    let (bridge_tx, bridge_rx) = std::sync::mpsc::channel();
    let mut expose_manager = ExposeManager::new(expose_rx, bridge_tx);

    let addresses = collect_smoltcp_addresses(config, options);
    let localhost_ip = localhost_mapping(config, options);
    let tcp_config = tcp_proxy_config(options);
    let mut tcp_proxy = SmoltcpTcpProxy::new_with_config(&addresses, localhost_ip, tcp_config)?;
    if let Some(service) = api_service {
        if let Ok(mut svc) = service.lock() {
            svc.set_expose_tx(expose_tx);
        }
        if let Some(bind) = api_bind_addr(config, options) {
            tcp_proxy = tcp_proxy.with_api(service, bind);
        }
    }
    let ping = icmp::SystemPing::with_default_timeout();

    loop {
        let relay_packets = {
            let mut tunnel = relay_tunnel
                .lock()
                .map_err(|_| anyhow!("relay tunnel poisoned"))?;
            tunnel.recv_packets()?
        };

        let mut e2ee_inbound = Vec::new();
        let mut e2ee_datagrams = Vec::new();
        {
            let mut tunnel = e2ee_tunnel
                .lock()
                .map_err(|_| anyhow!("e2ee tunnel poisoned"))?;
            for packet in relay_packets {
                if let Some((src, payload)) = extract_e2ee_datagram(&packet, e2ee_port)? {
                    let output = tunnel.decapsulate_from(src, &payload)?;
                    e2ee_inbound.extend(output.packets);
                    e2ee_datagrams.extend(output.datagrams);
                }
            }
            let timers = tunnel.update_timers()?;
            e2ee_inbound.extend(timers.packets);
            e2ee_datagrams.extend(timers.datagrams);
        }

        let mut outbound = Vec::new();
        for packet in e2ee_inbound {
            let parsed = parse_ip_packet(&packet)?;
            match parsed.protocol {
                crate::transport::TransportProtocol::Tcp
                | crate::transport::TransportProtocol::Udp => {
                    let outgoing = tcp_proxy.handle_ip_packet(&packet)?;
                    outbound.extend(outgoing);
                }
                crate::transport::TransportProtocol::Icmp => {
                    if let Some(resp) = icmp::handle_icmp_packet_with_ping(&packet, &ping)? {
                        outbound.push(resp);
                    }
                }
            }
        }

        tcp_proxy.poll()?;
        outbound.extend(tcp_proxy.drain_outbound());

        if !outbound.is_empty() {
            let mut tunnel = e2ee_tunnel
                .lock()
                .map_err(|_| anyhow!("e2ee tunnel poisoned"))?;
            for out in outbound {
                match tunnel.send_ip_packet(&out) {
                    Ok(datagrams) => e2ee_datagrams.extend(datagrams),
                    Err(err) => {
                        if is_peer_endpoint_missing(&err) {
                            tracing::warn!(
                                error = %err,
                                "peer endpoint missing; waiting for handshake"
                            );
                            continue;
                        }
                        return Err(err);
                    }
                }
            }
        }

        if !e2ee_datagrams.is_empty() {
            send_datagrams_over_relay(&relay_tunnel, &config.relay, e2ee_port, e2ee_datagrams)?;
        }

        expose_manager.poll(&mut tcp_proxy);
        while let Ok(req) = bridge_rx.try_recv() {
            let _ = tcp_proxy.register_host_tcp_bridge(req.stream, req.remote);
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn tcp_proxy_config(options: &ServeOptions) -> TcpProxyConfig {
    TcpProxyConfig {
        completion_timeout: std::time::Duration::from_millis(options.completion_timeout_ms),
        connect_timeout: std::time::Duration::from_millis(options.conn_timeout_ms),
        keepalive_idle: std::time::Duration::from_secs(options.keepalive_idle_secs),
        keepalive_interval: std::time::Duration::from_secs(options.keepalive_interval_secs),
        keepalive_count: options.keepalive_count,
    }
}

struct TcpBridgeRequest {
    stream: TcpStream,
    remote: SocketAddr,
}

struct ExposeListener {
    shutdown: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

struct ExposeManager {
    rx: Receiver<ExposeCommand>,
    bridge_tx: Sender<TcpBridgeRequest>,
    tcp_listeners: HashMap<ExposeTuple, ExposeListener>,
}

impl ExposeManager {
    fn new(rx: Receiver<ExposeCommand>, bridge_tx: Sender<TcpBridgeRequest>) -> Self {
        Self {
            rx,
            bridge_tx,
            tcp_listeners: HashMap::new(),
        }
    }

    fn poll(&mut self, tcp_proxy: &mut SmoltcpTcpProxy) {
        while let Ok(cmd) = self.rx.try_recv() {
            match cmd {
                ExposeCommand::Add {
                    tuple,
                    dynamic,
                    respond,
                } => {
                    let result = if tuple.protocol == "udp" {
                        tcp_proxy.add_udp_expose(tuple)
                    } else {
                        self.add_tcp_listener(tuple, dynamic)
                    };
                    let _ = respond.send(result);
                }
                ExposeCommand::Remove { tuple, respond } => {
                    let result = if tuple.protocol == "udp" {
                        tcp_proxy.remove_udp_expose(&tuple)
                    } else {
                        self.remove_tcp_listener(&tuple)
                    };
                    let _ = respond.send(result);
                }
            }
        }
    }

    fn add_tcp_listener(&mut self, tuple: ExposeTuple, dynamic: bool) -> Result<()> {
        if tuple.protocol != "tcp" {
            return Err(anyhow!("unsupported expose protocol"));
        }
        if self.tcp_listeners.contains_key(&tuple) {
            return Err(anyhow!("port already exposed"));
        }

        let listen_addr = match tuple.remote_addr {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tuple.remote_port),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), tuple.remote_port),
        };
        let listener =
            TcpListener::bind(listen_addr).map_err(|err| anyhow!("bind failed: {err}"))?;
        let _ = listener.set_nonblocking(true);

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_handle = shutdown.clone();
        let bridge_tx = self.bridge_tx.clone();
        let listener_tuple = tuple.clone();
        let thread = std::thread::spawn(move || {
            run_expose_tcp_listener(listener, listener_tuple, dynamic, bridge_tx, shutdown_handle);
        });

        self.tcp_listeners
            .insert(tuple, ExposeListener { shutdown, thread });
        Ok(())
    }

    fn remove_tcp_listener(&mut self, tuple: &ExposeTuple) -> Result<()> {
        if let Some(listener) = self.tcp_listeners.remove(tuple) {
            listener.shutdown.store(true, Ordering::Relaxed);
            let _ = listener.thread.join();
            Ok(())
        } else {
            Err(anyhow!("not found"))
        }
    }
}

fn run_expose_tcp_listener(
    listener: TcpListener,
    tuple: ExposeTuple,
    dynamic: bool,
    bridge_tx: Sender<TcpBridgeRequest>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                let remote = if dynamic {
                    match socks5_request_port(&mut stream) {
                        Some(port) => {
                            let _ = send_socks_reply(&mut stream, 0x00);
                            SocketAddr::new(tuple.remote_addr, port)
                        }
                        None => {
                            let _ = send_socks_reply(&mut stream, 0x01);
                            continue;
                        }
                    }
                } else {
                    SocketAddr::new(tuple.remote_addr, tuple.local_port)
                };
                let _ = stream.set_nonblocking(true);
                let _ = bridge_tx.send(TcpBridgeRequest { stream, remote });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

fn socks5_request_port(stream: &mut TcpStream) -> Option<u16> {
    let ver = read_u8(stream)?;
    if ver != 0x05 {
        return None;
    }
    let nmethods = read_u8(stream)?;
    let methods = read_exact(stream, nmethods as usize)?;
    if !methods.iter().any(|m| *m == 0x00) {
        let _ = stream.write_all(&[0x05, 0xFF]);
        return None;
    }
    if stream.write_all(&[0x05, 0x00]).is_err() {
        return None;
    }

    let ver = read_u8(stream)?;
    if ver != 0x05 {
        return None;
    }
    let cmd = read_u8(stream)?;
    let _rsv = read_u8(stream)?;
    let atyp = read_u8(stream)?;
    if cmd != 0x01 {
        let _ = send_socks_reply(stream, 0x07);
        return None;
    }
    if !discard_socks_addr(stream, atyp) {
        let _ = send_socks_reply(stream, 0x08);
        return None;
    }
    read_u16(stream)
}

fn discard_socks_addr(stream: &mut TcpStream, atyp: u8) -> bool {
    match atyp {
        0x01 => read_exact(stream, 4).is_some(),
        0x03 => match read_u8(stream) {
            Some(len) => read_exact(stream, len as usize).is_some(),
            None => false,
        },
        0x04 => read_exact(stream, 16).is_some(),
        _ => false,
    }
}

fn send_socks_reply(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    let reply = [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply)
}

fn read_u8(stream: &mut TcpStream) -> Option<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).ok()?;
    Some(buf[0])
}

fn read_u16(stream: &mut TcpStream) -> Option<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).ok()?;
    Some(u16::from_be_bytes(buf))
}

fn read_exact(stream: &mut TcpStream, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn collect_smoltcp_addresses(config: &ServerConfig, options: &ServeOptions) -> Vec<IpAddr> {
    let mut addresses = match config.e2ee.as_ref() {
        Some(e2ee) if !e2ee.addresses().is_empty() => e2ee
            .addresses()
            .iter()
            .map(|net| net.addr())
            .collect::<Vec<_>>(),
        _ => config
            .relay
            .addresses()
            .iter()
            .map(|net| net.addr())
            .collect::<Vec<_>>(),
    };

    if config.e2ee.is_none() {
        if let Some(bind) = api_bind_addr(config, options) {
            if !addresses.contains(&bind.ip()) {
                addresses.push(bind.ip());
            }
        }
    }

    if let Some(localhost) = config.relay.localhost_ip() {
        let localhost_ip = IpAddr::V4(localhost);
        if !addresses.contains(&localhost_ip) {
            addresses.push(localhost_ip);
        }
    }

    addresses
}

fn localhost_mapping(config: &ServerConfig, options: &ServeOptions) -> Option<Ipv4Addr> {
    if let Some(localhost) = config.relay.localhost_ip() {
        return Some(localhost);
    }
    api_localhost_mapping(config, options)
}

fn api_localhost_mapping(config: &ServerConfig, options: &ServeOptions) -> Option<Ipv4Addr> {
    if config.e2ee.is_none() {
        return None;
    }
    let bind = api_bind_addr(config, options)?;
    match bind.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn build_e2ee_session(config: &ServerConfig) -> Result<Arc<Mutex<MultiPeerSession>>> {
    let e2ee = config
        .e2ee
        .as_ref()
        .ok_or_else(|| anyhow!("e2ee config missing"))?;
    if e2ee.peers().is_empty() {
        return Err(anyhow!("e2ee peer missing"));
    }
    let peer_configs = e2ee
        .peers()
        .iter()
        .map(|peer| WgPeerConfig {
            public_key: peer.public_key(),
            preshared_key: peer.preshared_key(),
            keepalive: peer.keepalive(),
            endpoint: resolve_peer_endpoint(peer),
            allowed_ips: peer.allowed_ips().to_vec(),
        })
        .collect::<Vec<_>>();
    let tunnel = MultiPeerSession::new(&e2ee.private_key(), peer_configs)?;
    Ok(Arc::new(Mutex::new(tunnel)))
}

fn e2ee_listen_port(config: &ServerConfig) -> u16 {
    config
        .e2ee
        .as_ref()
        .and_then(|cfg| cfg.port())
        .unwrap_or(constants::DEFAULT_E2EE_PORT)
}

fn extract_e2ee_datagram(packet: &[u8], e2ee_port: u16) -> Result<Option<(SocketAddr, Vec<u8>)>> {
    let parsed = parse_ip_packet(packet)?;
    if parsed.protocol != crate::transport::TransportProtocol::Udp {
        return Ok(None);
    }
    let udp = parse_udp_packet(packet, parsed.header_len)?;
    if udp.dst_port != e2ee_port {
        return Ok(None);
    }
    let payload = packet[udp.payload_offset..udp.payload_offset + udp.payload_len].to_vec();
    let src = SocketAddr::new(parsed.src, udp.src_port);
    Ok(Some((src, payload)))
}

fn send_datagrams_over_relay(
    relay_tunnel: &Arc<Mutex<MultiPeerTunnel>>,
    relay: &Config,
    e2ee_port: u16,
    datagrams: Vec<OutboundDatagram>,
) -> Result<()> {
    if datagrams.is_empty() {
        return Ok(());
    }
    let mut tunnel = relay_tunnel
        .lock()
        .map_err(|_| anyhow!("relay tunnel poisoned"))?;
    for datagram in datagrams {
        let src_ip = relay_src_ip(relay, datagram.endpoint.ip())?;
        tracing::debug!(
            src = %src_ip,
            dst = %datagram.endpoint,
            bytes = datagram.bytes.len(),
            "e2ee datagram outbound"
        );
        let packet = build_udp_packet(
            src_ip,
            datagram.endpoint.ip(),
            e2ee_port,
            datagram.endpoint.port(),
            &datagram.bytes,
        )?;
        if let Err(err) = tunnel.send_ip_packet(&packet) {
            if is_peer_endpoint_missing(&err) {
                tracing::warn!(error = %err, "peer endpoint missing; waiting for handshake");
                continue;
            }
            return Err(err);
        }
    }
    Ok(())
}

fn relay_src_ip(relay: &Config, dst: IpAddr) -> Result<IpAddr> {
    let addr = relay
        .addresses()
        .iter()
        .map(|net| net.addr())
        .find(|addr| addr.is_ipv4() == dst.is_ipv4())
        .ok_or_else(|| anyhow!("relay address missing for {}", dst))?;
    Ok(addr)
}

fn is_peer_endpoint_missing(err: &anyhow::Error) -> bool {
    err.to_string().contains("peer endpoint missing")
}

fn log_localhost_forwarding(localhost: Ipv4Addr, quiet: bool) {
    if quiet {
        return;
    }
    if localhost.is_loopback() {
        println!(
            "=== WARNING: {} is a loopback IP. It will probably not work for Localhost Forwarding ===",
            localhost
        );
    } else if localhost.is_multicast() {
        println!(
            "=== WARNING: {} is a Multicast IP. Your OS might still send extra packets to other IPs when you target this IP ===",
            localhost
        );
    } else if !localhost.is_private() {
        println!(
            "=== WARNING: {} is a public IP. If Localhost Forwarding fails, your traffic may actually touch that IP ===",
            localhost
        );
    }
    println!("Localhost Forwarding configured for {}", localhost);
    println!();
}

pub fn build_relay_tunnel(
    config: &ServerConfig,
    bind_addr: Option<SocketAddr>,
) -> Result<Arc<Mutex<MultiPeerTunnel>>> {
    let relay = &config.relay;
    let listen_addr = match bind_addr {
        Some(addr) => addr,
        None => default_bind_addr(config)?,
    };
    if relay.peers().is_empty() {
        return Err(anyhow!("relay peer missing"));
    }
    let peer_configs = relay
        .peers()
        .iter()
        .map(|peer| WgPeerConfig {
            public_key: peer.public_key(),
            preshared_key: peer.preshared_key(),
            keepalive: peer.keepalive(),
            endpoint: resolve_peer_endpoint(peer),
            allowed_ips: peer.allowed_ips().to_vec(),
        })
        .collect::<Vec<_>>();
    let tunnel = MultiPeerTunnel::new(&relay.private_key(), listen_addr, peer_configs)?;
    Ok(Arc::new(Mutex::new(tunnel)))
}

#[cfg(test)]
mod tests {
    use super::{
        ServeOptions, api_bind_addr, collect_smoltcp_addresses, localhost_mapping,
        resolve_allocation_state_path,
    };
    use crate::peer::{Config, ServerConfig};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn api_bind_addr_prefers_ipv4_when_ipv6_disabled() {
        let mut relay = Config::new().expect("relay");
        relay.add_address("172.17.0.2/32").expect("addr v4");
        relay.add_address("fd:17::2/128").expect("addr v6");
        let config = ServerConfig { relay, e2ee: None };
        let options = ServeOptions {
            disable_ipv6: true,
            api_port: 8080,
            ..ServeOptions::default()
        };
        let bind = api_bind_addr(&config, &options).expect("bind");
        assert_eq!(bind.ip(), IpAddr::V4(crate::constants::default_api_v4()));
        assert_eq!(bind.port(), 8080);
    }

    #[test]
    fn localhost_mapping_uses_api_addr_for_e2ee() {
        let mut relay = Config::new().expect("relay");
        relay.add_address("172.17.0.2/32").expect("addr v4");
        let mut e2ee = Config::new().expect("e2ee");
        e2ee.add_address("192.0.2.10/32").expect("api v4");
        let config = ServerConfig {
            relay,
            e2ee: Some(e2ee),
        };
        let options = ServeOptions::default();
        assert_eq!(
            localhost_mapping(&config, &options),
            Some(Ipv4Addr::new(192, 0, 2, 10))
        );
    }

    #[test]
    fn collect_smoltcp_addresses_includes_localhost_ip() {
        let mut relay = Config::new().expect("relay");
        relay.add_address("172.17.0.2/32").expect("addr v4");
        relay.set_localhost_ip("10.0.0.123").expect("localhost");
        let mut e2ee = Config::new().expect("e2ee");
        e2ee.add_address("172.18.0.2/32").expect("e2ee v4");
        let config = ServerConfig {
            relay,
            e2ee: Some(e2ee),
        };
        let options = ServeOptions::default();
        let addrs = collect_smoltcp_addresses(&config, &options);
        assert!(addrs.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 123))));
    }

    #[test]
    fn allocation_state_path_is_opt_in() {
        let env = crate::serve::ServerEnv::from(std::collections::HashMap::new());
        let path = resolve_allocation_state_path(&env);
        assert!(path.is_none());
    }

    #[test]
    fn allocation_state_path_uses_env_override() {
        let mut values = std::collections::HashMap::new();
        values.insert(
            "WIRETAP_ALLOCATION_STATE".to_string(),
            "/tmp/wiretap_state.json".to_string(),
        );
        let env = crate::serve::ServerEnv::from(values);
        let path = resolve_allocation_state_path(&env);
        let expected = std::path::PathBuf::from("/tmp/wiretap_state.json");
        assert_eq!(path.unwrap(), expected);
    }
}
