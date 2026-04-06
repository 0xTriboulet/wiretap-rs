use crate::constants::{
    default_api_v6, default_client_e2ee_v4, default_client_e2ee_v6, default_client_relay_v4,
    default_client_relay_v6, default_server_e2ee_v4, default_server_e2ee_v6,
    default_server_relay_v4, default_server_relay_v6, increment_v4, increment_v6, mask_prefix_v4,
    mask_prefix_v6, relay_subnet_v4, relay_subnet_v6, SUBNET_V4_BITS, SUBNET_V6_BITS,
};
use crate::transport::socks5;
use crate::transport::userspace::resolve_peer_endpoint;
use crate::transport::wireguard::{MultiPeerSession, MultiPeerTunnel, PeerConfig as WgPeerConfig};
use anyhow::{anyhow, Result};
use get_if_addrs::IfAddr;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ExposeAction {
    Expose = 0,
    List = 1,
    Delete = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExposeRequest {
    pub action: ExposeAction,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: String,
    pub dynamic: bool,
    #[serde(default)]
    pub remote_addr: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExposeTuple {
    pub remote_addr: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: String,
}

#[derive(Debug)]
pub enum ExposeCommand {
    Add {
        tuple: ExposeTuple,
        dynamic: bool,
        respond: Sender<Result<()>>,
    },
    Remove {
        tuple: ExposeTuple,
        respond: Sender<Result<()>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum InterfaceType {
    Relay = 0,
    E2EE = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum PeerType {
    Client = 0,
    Server = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServerConfigs {
    pub relay_config: crate::peer::Config,
    pub e2ee_config: crate::peer::Config,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostInterface {
    pub name: String,
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkState {
    pub next_client_relay_addr4: std::net::Ipv4Addr,
    pub next_client_relay_addr6: std::net::Ipv6Addr,
    pub next_server_relay_addr4: std::net::Ipv4Addr,
    pub next_server_relay_addr6: std::net::Ipv6Addr,
    pub next_client_e2ee_addr4: std::net::Ipv4Addr,
    pub next_client_e2ee_addr6: std::net::Ipv6Addr,
    pub next_server_e2ee_addr4: std::net::Ipv4Addr,
    pub next_server_e2ee_addr6: std::net::Ipv6Addr,
    pub api_addr: std::net::IpAddr,
    pub server_relay_subnet4: std::net::Ipv4Addr,
    pub server_relay_subnet6: std::net::Ipv6Addr,
}

impl Default for NetworkState {
    fn default() -> Self {
        let relay4 = relay_subnet_v4();
        let relay6 = relay_subnet_v6();
        Self {
            next_client_relay_addr4: default_client_relay_v4(),
            next_client_relay_addr6: default_client_relay_v6(),
            next_server_relay_addr4: default_server_relay_v4(),
            next_server_relay_addr6: default_server_relay_v6(),
            next_client_e2ee_addr4: default_client_e2ee_v4(),
            next_client_e2ee_addr6: default_client_e2ee_v6(),
            next_server_e2ee_addr4: default_server_e2ee_v4(),
            next_server_e2ee_addr6: default_server_e2ee_v6(),
            api_addr: std::net::IpAddr::V6(default_api_v6()),
            server_relay_subnet4: relay4.network(),
            server_relay_subnet6: relay6.network(),
        }
    }
}

const ALLOCATION_STATE_VERSION: u8 = 1;

fn allocation_state_version() -> u8 {
    ALLOCATION_STATE_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AllocationSnapshot {
    #[serde(default = "allocation_state_version")]
    version: u8,
    next_state: NetworkState,
    client_addresses: HashMap<u64, NetworkState>,
    server_addresses: HashMap<u64, NetworkState>,
    next_client_index: u64,
    next_server_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddPeerRequest {
    pub interface: InterfaceType,
    pub config: crate::peer::PeerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddAllowedIpsRequest {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ApiRequest {
    Ping,
    Expose(ExposeRequest),
    ServerInfo,
    ServerInterfaces,
    Allocate(PeerType),
    AddPeer(AddPeerRequest),
    AddAllowedIps(AddAllowedIpsRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ApiResponse {
    Pong(String),
    ExposeList(Vec<ExposeTuple>),
    ServerInfo(ServerConfigs),
    ServerInterfaces(Vec<HostInterface>),
    Allocated(NetworkState),
    Ack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpStatusError {
    pub(crate) status: u16,
    message: String,
}

impl HttpStatusError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::new(405, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(500, message)
    }
}

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpStatusError {}

fn require_method(method: &str, expected: &str) -> std::result::Result<(), HttpStatusError> {
    if method == expected {
        Ok(())
    } else {
        Err(HttpStatusError::method_not_allowed("method not allowed"))
    }
}

fn map_allocate_error(err: anyhow::Error) -> HttpStatusError {
    let message = err.to_string();
    if message.contains("missing type") || message.contains("invalid type") {
        HttpStatusError::bad_request(message)
    } else {
        HttpStatusError::internal(message)
    }
}

pub(crate) fn handle_http_request_with_status(
    method: &str,
    url: &str,
    body: &[u8],
    remote_addr: Option<IpAddr>,
    service: &Arc<Mutex<ApiService>>,
) -> std::result::Result<ApiResponse, HttpStatusError> {
    let method = method.to_ascii_uppercase();
    let (path, query) = split_url(url);

    match path {
        "/ping" => Ok(ApiResponse::Pong("pong".into())),
        "/expose" => {
            require_method(method.as_str(), "POST")?;
            let mut expose_req: ExposeRequest = read_json_bytes(body).map_err(|err| {
                HttpStatusError::internal(format!("invalid expose request: {err}"))
            })?;
            if expose_req.remote_addr.is_none() {
                expose_req.remote_addr = remote_addr;
            }
            let mut svc = service
                .lock()
                .map_err(|_| HttpStatusError::internal("api service poisoned"))?;
            svc.handle_expose(expose_req)
                .map_err(|err| HttpStatusError::internal(err.to_string()))
        }
        "/serverinfo" => {
            require_method(method.as_str(), "GET")?;
            let svc = service
                .lock()
                .map_err(|_| HttpStatusError::internal("api service poisoned"))?;
            svc.handle_server_info()
                .map_err(|err| HttpStatusError::internal(err.to_string()))
        }
        "/serverinterfaces" => {
            require_method(method.as_str(), "GET")?;
            let svc = service
                .lock()
                .map_err(|_| HttpStatusError::internal("api service poisoned"))?;
            svc.handle_server_interfaces()
                .map_err(|err| HttpStatusError::internal(err.to_string()))
        }
        "/allocate" => {
            require_method(method.as_str(), "GET")?;
            handle_http_allocate_query(query, service).map_err(map_allocate_error)
        }
        "/addpeer" => {
            require_method(method.as_str(), "POST")?;
            let add = match parse_interface_query(query) {
                Ok(Some(interface)) => {
                    let config: crate::peer::PeerConfig = read_json_bytes(body)
                        .map_err(|err| HttpStatusError::internal(format!("invalid json: {err}")))?;
                    AddPeerRequest { interface, config }
                }
                Ok(None) => read_json_bytes(body)
                    .map_err(|err| HttpStatusError::internal(format!("invalid json: {err}")))?,
                Err(err) => return Err(HttpStatusError::bad_request(err.to_string())),
            };
            let mut svc = service
                .lock()
                .map_err(|_| HttpStatusError::internal("api service poisoned"))?;
            svc.handle_add_peer(add)
                .map_err(|err| HttpStatusError::internal(err.to_string()))
        }
        "/addallowedips" => {
            require_method(method.as_str(), "POST")?;
            let add: AddAllowedIpsRequest = read_json_bytes(body)
                .map_err(|err| HttpStatusError::internal(format!("invalid json: {err}")))?;
            let mut svc = service
                .lock()
                .map_err(|_| HttpStatusError::internal("api service poisoned"))?;
            svc.handle_add_allowed_ips(add)
                .map_err(|err| HttpStatusError::internal(err.to_string()))
        }
        _ => Err(HttpStatusError::not_found("not found")),
    }
}

pub fn handle_http_request(
    method: &str,
    url: &str,
    body: &[u8],
    remote_addr: Option<IpAddr>,
    service: &Arc<Mutex<ApiService>>,
) -> Result<ApiResponse> {
    handle_http_request_with_status(method, url, body, remote_addr, service)
        .map_err(|err| anyhow!(err.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiMessage {
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct ApiService {
    exposed: HashSet<ExposeTuple>,
    expose_handles: HashMap<ExposeTuple, ExposeHandle>,
    expose_tx: Option<Sender<ExposeCommand>>,
    relay_config: Option<crate::peer::Config>,
    e2ee_config: Option<crate::peer::Config>,
    host_interfaces: Vec<HostInterface>,
    next_state: NetworkState,
    client_addresses: HashMap<u64, NetworkState>,
    server_addresses: HashMap<u64, NetworkState>,
    next_client_index: u64,
    next_server_index: u64,
    relay_tunnel: Option<Arc<Mutex<MultiPeerTunnel>>>,
    e2ee_tunnel: Option<Arc<Mutex<MultiPeerSession>>>,
    allocation_state_path: Option<PathBuf>,
}

struct ExposeHandle {
    shutdown: Arc<AtomicBool>,
    thread: thread::JoinHandle<()>,
}

impl ApiService {
    pub fn new() -> Self {
        let mut service = Self::default();
        service.prime_state();
        service
    }

    pub fn with_configs(
        relay: Option<crate::peer::Config>,
        e2ee: Option<crate::peer::Config>,
    ) -> Self {
        let mut service = Self::default();
        if let Some(relay_config) = relay {
            service.apply_relay_defaults(&relay_config);
            service.relay_config = Some(relay_config);
        }
        if let Some(e2ee_config) = e2ee {
            service.apply_e2ee_defaults(&e2ee_config);
            service.e2ee_config = Some(e2ee_config);
        }
        service.prime_state();
        service
    }

    pub fn with_interfaces(mut self, ifaces: Vec<HostInterface>) -> Self {
        self.host_interfaces = ifaces;
        self
    }

    pub fn with_expose_tx(mut self, tx: Sender<ExposeCommand>) -> Self {
        self.expose_tx = Some(tx);
        self
    }

    pub fn set_expose_tx(&mut self, tx: Sender<ExposeCommand>) {
        self.expose_tx = Some(tx);
    }

    pub fn with_relay_tunnel(mut self, tunnel: Arc<Mutex<MultiPeerTunnel>>) -> Self {
        self.relay_tunnel = Some(tunnel);
        self
    }

    pub fn with_e2ee_tunnel(mut self, tunnel: Arc<Mutex<MultiPeerSession>>) -> Self {
        self.e2ee_tunnel = Some(tunnel);
        self
    }

    pub fn set_allocation_state_path<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<()> {
        self.allocation_state_path = Some(path.as_ref().to_path_buf());
        self.load_allocation_state()
    }

    pub fn handle_message(&mut self, message: ApiMessage) -> Result<ApiResponse> {
        let req: ApiRequest = serde_json::from_slice(&message.payload)
            .map_err(|err| anyhow!("failed to parse api request: {err}"))?;

        match req {
            ApiRequest::Ping => Ok(ApiResponse::Pong("pong".to_string())),
            ApiRequest::Expose(request) => self.handle_expose(request),
            ApiRequest::ServerInfo => self.handle_server_info(),
            ApiRequest::ServerInterfaces => self.handle_server_interfaces(),
            ApiRequest::Allocate(interface) => self.handle_allocate(interface),
            ApiRequest::AddPeer(req) => self.handle_add_peer(req),
            ApiRequest::AddAllowedIps(req) => self.handle_add_allowed_ips(req),
        }
    }

    fn handle_expose(&mut self, request: ExposeRequest) -> Result<ApiResponse> {
        match request.action {
            ExposeAction::List => {
                let tuples = self.exposed.iter().cloned().collect();
                Ok(ApiResponse::ExposeList(tuples))
            }
            ExposeAction::Expose => {
                let remote_addr = request
                    .remote_addr
                    .ok_or_else(|| anyhow!("remote addr missing"))?;
                if request.remote_port == 0 {
                    return Err(anyhow!("remote port required"));
                }
                if !request.dynamic && request.local_port == 0 {
                    return Err(anyhow!("local port required"));
                }
                let protocol = if request.protocol.is_empty() {
                    "tcp".to_string()
                } else {
                    request.protocol.clone()
                };
                if request.dynamic && protocol != "tcp" {
                    return Err(anyhow!("dynamic expose requires tcp"));
                }
                if !request.dynamic && protocol != "tcp" && protocol != "udp" {
                    return Err(anyhow!("invalid protocol"));
                }
                let tuple = ExposeTuple {
                    remote_addr,
                    local_port: request.local_port,
                    remote_port: request.remote_port,
                    protocol,
                };
                if self.exposed.contains(&tuple) {
                    return Err(anyhow!("port already exposed"));
                }

                let use_async = self.expose_tx.is_some();
                if let Some(tx) = self.expose_tx.as_ref().filter(|_| use_async) {
                    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
                    tx.send(ExposeCommand::Add {
                        tuple: tuple.clone(),
                        dynamic: request.dynamic,
                        respond: resp_tx,
                    })
                    .map_err(|_| anyhow!("expose handler unavailable"))?;
                    let () = resp_rx.recv().map_err(|_| anyhow!("expose failed"))??;
                } else {
                    let handle = if request.dynamic {
                        start_dynamic_listener(&tuple)?
                    } else {
                        start_expose_listener(&tuple)?
                    };
                    self.expose_handles.insert(tuple.clone(), handle);
                }
                self.exposed.insert(tuple);
                Ok(ApiResponse::Ack)
            }
            ExposeAction::Delete => {
                let remote_addr = request
                    .remote_addr
                    .ok_or_else(|| anyhow!("remote addr missing"))?;
                if request.protocol != "tcp" && request.protocol != "udp" {
                    return Err(anyhow!("invalid protocol"));
                }
                let tuple = ExposeTuple {
                    remote_addr,
                    local_port: request.local_port,
                    remote_port: request.remote_port,
                    protocol: request.protocol,
                };
                if !self.exposed.remove(&tuple) {
                    return Err(anyhow!("not found"));
                }
                let use_async = self.expose_tx.is_some();
                if let Some(tx) = self.expose_tx.as_ref().filter(|_| use_async) {
                    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
                    tx.send(ExposeCommand::Remove {
                        tuple: tuple.clone(),
                        respond: resp_tx,
                    })
                    .map_err(|_| anyhow!("expose handler unavailable"))?;
                    let _ = resp_rx.recv();
                } else if let Some(handle) = self.expose_handles.remove(&tuple) {
                    handle.shutdown.store(true, Ordering::Relaxed);
                    let _ = handle.thread.join();
                }
                Ok(ApiResponse::Ack)
            }
        }
    }

    fn handle_server_info(&self) -> Result<ApiResponse> {
        let relay = self
            .relay_config
            .clone()
            .ok_or_else(|| anyhow!("missing relay config"))?;
        let e2ee = self
            .e2ee_config
            .clone()
            .unwrap_or_else(crate::peer::Config::empty);
        Ok(ApiResponse::ServerInfo(ServerConfigs {
            relay_config: relay,
            e2ee_config: e2ee,
        }))
    }

    fn handle_server_interfaces(&self) -> Result<ApiResponse> {
        Ok(ApiResponse::ServerInterfaces(self.host_interfaces.clone()))
    }

    fn handle_allocate(&mut self, peer_type: PeerType) -> Result<ApiResponse> {
        // Return current state and advance counters by one
        let previous = self.allocation_state_path.as_ref().map(|_| self.snapshot());
        let state = self.next_state.clone();
        match peer_type {
            PeerType::Server => {
                self.next_state.next_server_relay_addr4 =
                    increment_v4(state.next_server_relay_addr4, 1);
                self.next_state.next_server_relay_addr6 =
                    increment_v6(state.next_server_relay_addr6, 1);
                self.next_state.next_server_e2ee_addr4 =
                    increment_v4(state.next_server_e2ee_addr4, 1);
                self.next_state.next_server_e2ee_addr6 =
                    increment_v6(state.next_server_e2ee_addr6, 1);
                self.next_state.api_addr = match state.api_addr {
                    std::net::IpAddr::V4(addr) => std::net::IpAddr::V4(increment_v4(addr, 1)),
                    std::net::IpAddr::V6(addr) => std::net::IpAddr::V6(increment_v6(addr, 1)),
                };
                let index = self.next_server_index;
                self.server_addresses.insert(index, state.clone());
                self.next_server_index = self.next_server_index.saturating_add(1);
            }
            PeerType::Client => {
                self.next_state.next_client_relay_addr4 =
                    increment_v4(state.next_client_relay_addr4, 1);
                self.next_state.next_client_relay_addr6 =
                    increment_v6(state.next_client_relay_addr6, 1);
                self.next_state.next_client_e2ee_addr4 =
                    increment_v4(state.next_client_e2ee_addr4, 1);
                self.next_state.next_client_e2ee_addr6 =
                    increment_v6(state.next_client_e2ee_addr6, 1);
                let index = self.next_client_index;
                self.client_addresses.insert(index, state.clone());
                self.next_client_index = self.next_client_index.saturating_add(1);
            }
        }
        if let Err(err) = self.save_allocation_state() {
            if let Some(snapshot) = previous {
                self.apply_snapshot(snapshot);
            }
            return Err(err);
        }
        Ok(ApiResponse::Allocated(state))
    }

    fn handle_add_peer(&mut self, req: AddPeerRequest) -> Result<ApiResponse> {
        if req.config.public_key() == crate::peer::Key::zero() {
            return Err(anyhow!("public key required"));
        }
        if req.config.allowed_ips().is_empty() {
            return Err(anyhow!("allowed ips required"));
        }

        match req.interface {
            InterfaceType::Relay => {
                if let Some(tunnel) = &self.relay_tunnel {
                    let mut tunnel = tunnel
                        .lock()
                        .map_err(|_| anyhow!("relay tunnel poisoned"))?;
                    let wg_peer = WgPeerConfig {
                        public_key: req.config.public_key(),
                        preshared_key: req.config.preshared_key(),
                        keepalive: req.config.keepalive(),
                        endpoint: resolve_peer_endpoint(&req.config),
                        allowed_ips: req.config.allowed_ips().to_vec(),
                    };
                    tunnel.add_peer(wg_peer)?;
                }
            }
            InterfaceType::E2EE => {
                if let Some(tunnel) = &self.e2ee_tunnel {
                    let mut tunnel = tunnel.lock().map_err(|_| anyhow!("e2ee tunnel poisoned"))?;
                    let wg_peer = WgPeerConfig {
                        public_key: req.config.public_key(),
                        preshared_key: req.config.preshared_key(),
                        keepalive: req.config.keepalive(),
                        endpoint: resolve_peer_endpoint(&req.config),
                        allowed_ips: req.config.allowed_ips().to_vec(),
                    };
                    tunnel.add_peer(wg_peer)?;
                }
            }
        }

        let config = match req.interface {
            InterfaceType::Relay => self
                .relay_config
                .as_mut()
                .ok_or_else(|| anyhow!("relay config missing"))?,
            InterfaceType::E2EE => self
                .e2ee_config
                .as_mut()
                .ok_or_else(|| anyhow!("e2ee config missing"))?,
        };
        config.add_peer(req.config.clone());
        Ok(ApiResponse::Ack)
    }

    fn handle_add_allowed_ips(&mut self, req: AddAllowedIpsRequest) -> Result<ApiResponse> {
        let config = self
            .relay_config
            .as_mut()
            .ok_or_else(|| anyhow!("relay config missing"))?;
        let target = config
            .peers_mut()
            .iter_mut()
            .find(|p| p.public_key().to_string() == req.public_key)
            .ok_or_else(|| anyhow!("peer not found"))?;
        let mut tunnel = match &self.relay_tunnel {
            Some(tunnel) => Some(
                tunnel
                    .lock()
                    .map_err(|_| anyhow!("relay tunnel poisoned"))?,
            ),
            None => None,
        };
        for allowed in req.allowed_ips {
            target.add_allowed_ip(&allowed)?;
            if let Some(tunnel) = tunnel.as_mut() {
                if let Some(last) = target.allowed_ips().last().copied() {
                    tunnel.add_allowed_ips(&target.public_key(), &[last])?;
                }
            }
        }
        Ok(ApiResponse::Ack)
    }

    fn apply_relay_defaults(&mut self, relay: &crate::peer::Config) {
        if let Some(addr) = first_ipv4_addr(relay) {
            self.next_state.next_server_relay_addr4 = addr;
            self.next_state.server_relay_subnet4 = mask_prefix_v4(addr, SUBNET_V4_BITS);
        }
        if let Some(addr) = first_ipv6_addr(relay) {
            self.next_state.next_server_relay_addr6 = addr;
            self.next_state.server_relay_subnet6 = mask_prefix_v6(addr, SUBNET_V6_BITS);
        }
    }

    fn apply_e2ee_defaults(&mut self, e2ee: &crate::peer::Config) {
        if let Some(addr) = first_ip_addr(e2ee) {
            self.next_state.api_addr = addr;
        }
    }

    fn prime_state(&mut self) {
        self.server_addresses
            .insert(self.next_server_index, self.next_state.clone());
        self.next_server_index = self.next_server_index.saturating_add(1);
        self.next_state.next_client_relay_addr4 =
            increment_v4(self.next_state.next_client_relay_addr4, 1);
        self.next_state.next_client_relay_addr6 =
            increment_v6(self.next_state.next_client_relay_addr6, 1);
        self.next_state.next_server_relay_addr4 =
            increment_v4(self.next_state.next_server_relay_addr4, 1);
        self.next_state.next_server_relay_addr6 =
            increment_v6(self.next_state.next_server_relay_addr6, 1);
        self.next_state.next_client_e2ee_addr4 =
            increment_v4(self.next_state.next_client_e2ee_addr4, 1);
        self.next_state.next_client_e2ee_addr6 =
            increment_v6(self.next_state.next_client_e2ee_addr6, 1);
        self.next_state.next_server_e2ee_addr4 =
            increment_v4(self.next_state.next_server_e2ee_addr4, 1);
        self.next_state.next_server_e2ee_addr6 =
            increment_v6(self.next_state.next_server_e2ee_addr6, 1);
        self.next_state.api_addr = match self.next_state.api_addr {
            IpAddr::V4(addr) => IpAddr::V4(increment_v4(addr, 1)),
            IpAddr::V6(addr) => IpAddr::V6(increment_v6(addr, 1)),
        };
    }

    fn load_allocation_state(&mut self) -> Result<()> {
        let Some(path) = self.allocation_state_path.as_ref() else {
            return Ok(());
        };
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let snapshot: AllocationSnapshot = serde_json::from_str(&contents)
            .map_err(|err| anyhow!("failed to parse allocation state: {err}"))?;
        if snapshot.version != ALLOCATION_STATE_VERSION {
            return Err(anyhow!(
                "unsupported allocation state version {}",
                snapshot.version
            ));
        }
        self.apply_snapshot(snapshot);
        Ok(())
    }

    fn save_allocation_state(&self) -> Result<()> {
        let Some(path) = self.allocation_state_path.as_ref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let snapshot = self.snapshot();
        let payload = serde_json::to_vec_pretty(&snapshot)?;
        write_atomic(path, &payload)?;
        Ok(())
    }

    fn apply_snapshot(&mut self, snapshot: AllocationSnapshot) {
        self.next_state = snapshot.next_state;
        self.client_addresses = snapshot.client_addresses;
        self.server_addresses = snapshot.server_addresses;
        self.next_client_index = snapshot.next_client_index;
        self.next_server_index = snapshot.next_server_index;
    }

    fn snapshot(&self) -> AllocationSnapshot {
        AllocationSnapshot {
            version: ALLOCATION_STATE_VERSION,
            next_state: self.next_state.clone(),
            client_addresses: self.client_addresses.clone(),
            server_addresses: self.server_addresses.clone(),
            next_client_index: self.next_client_index,
            next_server_index: self.next_server_index,
        }
    }
}

fn write_atomic(path: &std::path::Path, payload: &[u8]) -> Result<()> {
    let mut tmp_os = std::ffi::OsString::from(path.as_os_str());
    tmp_os.push(".tmp");
    let tmp_path = std::path::PathBuf::from(tmp_os);
    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(payload)?;
        file.sync_all()?;
    }
    if std::fs::rename(&tmp_path, path).is_err() {
        let _ = std::fs::remove_file(path);
        std::fs::rename(&tmp_path, path)?;
    }
    Ok(())
}

pub fn collect_host_interfaces() -> Vec<HostInterface> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    let interfaces = match get_if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(err) => {
            eprintln!("API Error: {err}");
            return Vec::new();
        }
    };

    for iface in interfaces {
        let entry = map.entry(iface.name).or_default();
        match iface.addr {
            IfAddr::V4(addr) => {
                let prefix = ipv4_prefix_len(addr.netmask);
                entry.push(format!("{}/{}", addr.ip, prefix));
            }
            IfAddr::V6(addr) => {
                let prefix = ipv6_prefix_len(addr.netmask);
                entry.push(format!("{}/{}", addr.ip, prefix));
            }
        }
    }

    let mut output = map
        .into_iter()
        .map(|(name, addrs)| HostInterface { name, addrs })
        .collect::<Vec<_>>();
    output.sort_by(|a, b| a.name.cmp(&b.name));
    output
}

fn ipv4_prefix_len(mask: Ipv4Addr) -> u32 {
    u32::from(mask).count_ones()
}

fn ipv6_prefix_len(mask: Ipv6Addr) -> u32 {
    u128::from(mask).count_ones()
}

fn start_expose_listener(tuple: &ExposeTuple) -> Result<ExposeHandle> {
    let remote = SocketAddr::new(tuple.remote_addr, tuple.local_port);
    let listen = match tuple.remote_addr {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tuple.remote_port),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), tuple.remote_port),
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handle = shutdown.clone();

    let thread = match tuple.protocol.as_str() {
        "tcp" => thread::spawn(move || run_tcp_forwarder(listen, remote, shutdown_handle)),
        "udp" => thread::spawn(move || run_udp_forwarder(listen, remote, shutdown_handle)),
        _ => return Err(anyhow!("invalid protocol")),
    };

    Ok(ExposeHandle { shutdown, thread })
}

fn start_dynamic_listener(tuple: &ExposeTuple) -> Result<ExposeHandle> {
    let listen = match tuple.remote_addr {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tuple.remote_port),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), tuple.remote_port),
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handle = shutdown.clone();
    let remote_addr = tuple.remote_addr;

    let thread = thread::spawn(move || run_socks5_forwarder(listen, remote_addr, shutdown_handle));
    Ok(ExposeHandle { shutdown, thread })
}

fn run_tcp_forwarder(listen: SocketAddr, remote: SocketAddr, shutdown: Arc<AtomicBool>) {
    let listener = match TcpListener::bind(listen) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("expose tcp bind failed on {}: {}", listen, err);
            return;
        }
    };
    if listener.set_nonblocking(true).is_err() {
        return;
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((inbound, _)) => {
                thread::spawn(move || {
                    if let Ok(outbound) =
                        TcpStream::connect_timeout(&remote, Duration::from_secs(2))
                    {
                        proxy_tcp(inbound, outbound);
                    }
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn proxy_tcp(mut inbound: TcpStream, mut outbound: TcpStream) {
    let _ = inbound.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = inbound.set_write_timeout(Some(Duration::from_secs(30)));
    let _ = outbound.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = outbound.set_write_timeout(Some(Duration::from_secs(30)));

    let mut inbound_clone = match inbound.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let mut outbound_clone = match outbound.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };

    let _ = thread::spawn(move || {
        let _ = std::io::copy(&mut inbound_clone, &mut outbound);
    });

    let _ = std::io::copy(&mut outbound_clone, &mut inbound);
}

fn run_socks5_forwarder(listen: SocketAddr, remote_ip: IpAddr, shutdown: Arc<AtomicBool>) {
    let listener = match TcpListener::bind(listen) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("expose socks bind failed on {}: {}", listen, err);
            return;
        }
    };
    if listener.set_nonblocking(true).is_err() {
        return;
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                thread::spawn(move || handle_socks5_connection(stream, remote_ip));
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn handle_socks5_connection(mut client: TcpStream, remote_ip: IpAddr) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));

    let port = match socks5::parse_connect_port(&mut client) {
        Some(port) => port,
        None => return,
    };

    let remote = SocketAddr::new(remote_ip, port);
    let outbound = match TcpStream::connect_timeout(&remote, Duration::from_secs(5)) {
        Ok(stream) => stream,
        Err(_) => {
            let _ = socks5::send_reply(&mut client, 0x05);
            return;
        }
    };

    if socks5::send_reply(&mut client, 0x00).is_err() {
        return;
    }
    proxy_tcp(client, outbound);
}

fn run_udp_forwarder(listen: SocketAddr, remote: SocketAddr, shutdown: Arc<AtomicBool>) {
    let socket = match UdpSocket::bind(listen) {
        Ok(sock) => sock,
        Err(err) => {
            eprintln!("expose udp bind failed on {}: {}", listen, err);
            return;
        }
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
    let mut buffer = vec![0u8; 65535];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match socket.recv_from(&mut buffer) {
            Ok((len, src)) => {
                let payload = &buffer[..len];
                if let Some(reply) = udp_roundtrip(remote, payload) {
                    let _ = socket.send_to(&reply, src);
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => continue,
        }
    }
}

fn udp_roundtrip(remote: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let bind_addr = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let socket = UdpSocket::bind(bind_addr).ok()?;
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = socket.send_to(payload, remote);

    let mut buffer = vec![0u8; 65535];
    let (len, _) = socket.recv_from(&mut buffer).ok()?;
    buffer.truncate(len);
    Some(buffer)
}

fn first_ipv4_addr(config: &crate::peer::Config) -> Option<Ipv4Addr> {
    config.addresses().iter().find_map(|net| match net {
        IpNet::V4(net) => Some(net.addr()),
        _ => None,
    })
}

fn first_ipv6_addr(config: &crate::peer::Config) -> Option<Ipv6Addr> {
    config.addresses().iter().find_map(|net| match net {
        IpNet::V6(net) => Some(net.addr()),
        _ => None,
    })
}

fn first_ip_addr(config: &crate::peer::Config) -> Option<IpAddr> {
    config.addresses().first().map(|net| match net {
        IpNet::V4(net) => IpAddr::V4(net.addr()),
        IpNet::V6(net) => IpAddr::V6(net.addr()),
    })
}

/// Starts a lightweight HTTP API server backed by `ApiService`.
/// This is a placeholder until userspace netstack wiring exists.
pub fn run_http_api(
    bind: SocketAddr,
    service: Arc<Mutex<ApiService>>,
) -> Result<thread::JoinHandle<()>> {
    let server = tiny_http::Server::http(bind)
        .map_err(|err| anyhow!("failed to bind api server on {bind}: {err}"))?;

    let handle = thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let remote = req
                .remote_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            println!("(client {remote}) - API: {}", req.url());
            let method = req.method().as_str().to_uppercase();
            let url = req.url().to_string();
            let mut body = Vec::new();
            let result = match req.as_reader().read_to_end(&mut body) {
                Ok(_) => handle_http_request_with_status(
                    method.as_str(),
                    url.as_str(),
                    &body,
                    req.remote_addr().map(|addr| addr.ip()),
                    &service,
                ),
                Err(err) => Err(HttpStatusError::internal(format!(
                    "failed to read body: {err}"
                ))),
            };

            let response = match result {
                Ok(ApiResponse::Pong(body)) => tiny_http::Response::from_string(body),
                Ok(ApiResponse::ExposeList(list)) => match serde_json::to_string(&list) {
                    Ok(json) => tiny_http::Response::from_string(json),
                    Err(err) => {
                        tiny_http::Response::from_string(err.to_string()).with_status_code(500)
                    }
                },
                Ok(ApiResponse::ServerInfo(configs)) => match serde_json::to_string(&configs) {
                    Ok(json) => tiny_http::Response::from_string(json),
                    Err(err) => {
                        tiny_http::Response::from_string(err.to_string()).with_status_code(500)
                    }
                },
                Ok(ApiResponse::ServerInterfaces(list)) => match serde_json::to_string(&list) {
                    Ok(json) => tiny_http::Response::from_string(json),
                    Err(err) => {
                        tiny_http::Response::from_string(err.to_string()).with_status_code(500)
                    }
                },
                Ok(ApiResponse::Allocated(state)) => match serde_json::to_string(&state) {
                    Ok(json) => tiny_http::Response::from_string(json),
                    Err(err) => {
                        tiny_http::Response::from_string(err.to_string()).with_status_code(500)
                    }
                },
                Ok(ApiResponse::Ack) => tiny_http::Response::from_string("ok"),
                Err(err) => {
                    tiny_http::Response::from_string(err.to_string()).with_status_code(err.status)
                }
            };

            let _ = req.respond(response);
        }
    });

    Ok(handle)
}

fn split_url(url: &str) -> (&str, Option<&str>) {
    match url.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (url, None),
    }
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => continue,
        };
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn parse_peer_type_query(query: Option<&str>) -> Result<PeerType> {
    let value = query_value(query, "type").ok_or_else(|| anyhow!("missing type"))?;
    match value.as_str() {
        "0" => Ok(PeerType::Client),
        "1" => Ok(PeerType::Server),
        _ => Err(anyhow!("invalid type")),
    }
}

fn parse_interface_query(query: Option<&str>) -> Result<Option<InterfaceType>> {
    let Some(value) = query_value(query, "interface") else {
        return Ok(None);
    };
    match value.as_str() {
        "0" => Ok(Some(InterfaceType::Relay)),
        "1" => Ok(Some(InterfaceType::E2EE)),
        _ => Err(anyhow!("invalid interface")),
    }
}

fn handle_http_allocate_query(
    query: Option<&str>,
    service: &Arc<Mutex<ApiService>>,
) -> Result<ApiResponse> {
    let peer_type = parse_peer_type_query(query)?;
    let mut svc = service
        .lock()
        .map_err(|_| anyhow!("api service poisoned"))?;
    svc.handle_allocate(peer_type)
}

fn read_json_bytes<T: for<'a> Deserialize<'a>>(body: &[u8]) -> Result<T> {
    if body.is_empty() {
        return serde_json::from_str("").map_err(|err| anyhow!("invalid json: {err}"));
    }
    serde_json::from_slice(body).map_err(|err| anyhow!("invalid json: {err}"))
}
