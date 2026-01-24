//! HTTP API client functions for communicating with wiretap servers.
//!
//! This module provides client-side functions to interact with the wiretap server's HTTP API.
//! The API is served over the WireGuard tunnel interface and provides endpoints for:
//!
//! - Health checks and connectivity testing (`ping`)
//! - Port exposure management (`expose`, `expose_list`, `expose_remove`)
//! - Server information retrieval (`server_info`, `server_interfaces`)
//! - Network allocation (`allocate`)
//! - Peer management (`add_peer`, `add_allowed_ips`)
//!
//! # Example
//!
//! ```rust,no_run
//! use wiretap_rs::api;
//! use std::net::SocketAddr;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Connect to the default IPv6 API address
//! let api_addr: SocketAddr = "[::2]:80".parse()?;
//!
//! // Test connectivity
//! let response = api::ping(api_addr)?;
//! println!("Server responded: {}", response);
//!
//! // List current port exposures
//! let rules = api::expose_list(api_addr)?;
//! for rule in rules {
//!     println!("Exposed: {}:{} -> {}", rule.protocol, rule.remote_port, rule.remote_addr);
//! }
//! # Ok(())
//! # }
//! ```

use crate::peer::{Config, PeerConfig};
use crate::transport::api::{
    AddAllowedIpsRequest, HostInterface, InterfaceType, NetworkState, PeerType, ServerConfigs,
};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
enum ExposeAction {
    Expose = 0,
    List = 1,
    Delete = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ExposeRequestDto {
    action: ExposeAction,
    local_port: u16,
    remote_port: u16,
    protocol: String,
    dynamic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExposeTupleDto {
    remote_addr: String,
    local_port: u16,
    remote_port: u16,
    protocol: String,
}

/// An active port exposure rule on the server.
///
/// Represents a mapping that forwards traffic from a remote port on the server
/// to a local port on the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeRule {
    /// The remote IP address where the port is exposed.
    pub remote_addr: IpAddr,
    
    /// The local port on the client (None for dynamic SOCKS5 exposure).
    pub local_port: Option<u16>,
    
    /// The remote port number being exposed.
    pub remote_port: u16,
    
    /// The protocol being exposed ("tcp", "udp", or "dynamic").
    pub protocol: String,
}

/// Sends a ping request to the wiretap server API.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
///
/// # Returns
///
/// The server's response message (typically "pong").
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the server is unreachable.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::ping;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let response = ping(api_addr)?;
/// assert_eq!(response, "pong");
/// # Ok(())
/// # }
/// ```
pub fn ping(addr: SocketAddr) -> Result<String> {
    let url = format!("http://{addr}/ping");
    let body = read_body(http_agent().get(&url).call())?;
    Ok(body)
}

/// Exposes a port on the server, forwarding traffic to the client.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
/// * `local_port` - The local port on the client to forward to (None for dynamic/SOCKS5)
/// * `remote_port` - The port number to expose on the server
/// * `protocol` - The protocol to expose ("tcp", "udp", or "dynamic" for SOCKS5)
/// * `dynamic` - Whether this is a dynamic SOCKS5 proxy exposure
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the server rejects the request.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::expose;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
///
/// // Expose local port 8080 as remote port 80 via TCP
/// expose(api_addr, Some(8080), 80, "tcp", false)?;
///
/// // Expose dynamic SOCKS5 proxy on port 1080
/// expose(api_addr, None, 1080, "dynamic", true)?;
/// # Ok(())
/// # }
/// ```
pub fn expose(
    addr: SocketAddr,
    local_port: Option<u16>,
    remote_port: u16,
    protocol: &str,
    dynamic: bool,
) -> Result<()> {
    let url = format!("http://{addr}/expose");
    let request = ExposeRequestDto {
        action: ExposeAction::Expose,
        local_port: local_port.unwrap_or(0),
        remote_port,
        protocol: protocol.to_string(),
        dynamic,
    };

    read_body(
        http_agent()
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::to_string(&request)?),
    )
    .map(|_| ())
}

/// Lists all active port exposures on the server.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
///
/// # Returns
///
/// A vector of `ExposeRule` representing all active port exposures.
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the response cannot be parsed.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::expose_list;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let rules = expose_list(api_addr)?;
///
/// for rule in rules {
///     println!("{}:{} -> {:?}:{}", 
///         rule.protocol, rule.remote_port, rule.local_port, rule.remote_addr);
/// }
/// # Ok(())
/// # }
/// ```
pub fn expose_list(addr: SocketAddr) -> Result<Vec<ExposeRule>> {
    let url = format!("http://{addr}/expose");
    let request = ExposeRequestDto {
        action: ExposeAction::List,
        local_port: 0,
        remote_port: 0,
        protocol: String::new(),
        dynamic: false,
    };

    let body = read_body(
        http_agent()
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::to_string(&request)?),
    )?;

    let tuples: Vec<ExposeTupleDto> = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse expose list response: {body}"))?;

    let rules = tuples
        .into_iter()
        .map(|t| {
            let remote_addr = t
                .remote_addr
                .parse::<IpAddr>()
                .map_err(|err| anyhow!("invalid remote addr in response: {err}"))?;

            Ok(ExposeRule {
                remote_addr,
                local_port: if t.local_port == 0 {
                    None
                } else {
                    Some(t.local_port)
                },
                remote_port: t.remote_port,
                protocol: t.protocol,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(rules)
}

/// Removes a port exposure from the server.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
/// * `local_port` - The local port of the exposure to remove
/// * `remote_port` - The remote port of the exposure to remove
/// * `protocol` - The protocol of the exposure to remove
/// * `dynamic` - Whether this is a dynamic exposure
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the exposure does not exist.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::expose_remove;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
///
/// // Remove the TCP exposure on port 80
/// expose_remove(api_addr, Some(8080), 80, "tcp", false)?;
/// # Ok(())
/// # }
/// ```
pub fn expose_remove(
    addr: SocketAddr,
    local_port: Option<u16>,
    remote_port: u16,
    protocol: &str,
    dynamic: bool,
) -> Result<()> {
    let url = format!("http://{addr}/expose");
    let request = ExposeRequestDto {
        action: ExposeAction::Delete,
        local_port: local_port.unwrap_or(0),
        remote_port,
        protocol: protocol.to_string(),
        dynamic,
    };

    read_body(
        http_agent()
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::to_string(&request)?),
    )
    .map(|_| ())
}

fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(3))
        .try_proxy_from_env(false)
        .build()
}

fn read_body(result: Result<ureq::Response, ureq::Error>) -> Result<String> {
    match result {
        Ok(resp) => resp
            .into_string()
            .map_err(|err| anyhow!("failed to read response body: {err}")),
        Err(ureq::Error::Status(_, resp)) => {
            let body = resp
                .into_string()
                .unwrap_or_else(|_| "request failed".to_string());
            Err(anyhow!(body))
        }
        Err(err) => Err(anyhow!(err)),
    }
}

/// Retrieves the server's WireGuard configuration for relay and E2EE interfaces.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
///
/// # Returns
///
/// A tuple of `(relay_config, e2ee_config)` containing the server's configurations.
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the response cannot be parsed.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::server_info;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let (relay, e2ee) = server_info(api_addr)?;
///
/// println!("Server relay public key: {}", relay.public_key());
/// println!("Server E2EE public key: {}", e2ee.public_key());
/// # Ok(())
/// # }
/// ```
pub fn server_info(addr: SocketAddr) -> Result<(Config, Config)> {
    let url = format!("http://{addr}/serverinfo");
    let body = read_body(http_agent().get(&url).call())?;
    let configs: ServerConfigs = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse serverinfo: {body}"))?;
    Ok((configs.relay_config, configs.e2ee_config))
}

/// Retrieves the list of network interfaces available on the server.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
///
/// # Returns
///
/// A vector of `HostInterface` describing the server's network interfaces.
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the response cannot be parsed.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::server_interfaces;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let interfaces = server_interfaces(api_addr)?;
///
/// for iface in interfaces {
///     println!("Interface: {}", iface.name);
///     for addr in &iface.addrs {
///         println!("  Address: {}", addr);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn server_interfaces(addr: SocketAddr) -> Result<Vec<HostInterface>> {
    let url = format!("http://{addr}/serverinterfaces");
    let body = read_body(http_agent().get(&url).call())?;
    let list: Vec<HostInterface> = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse serverinterfaces: {body}"))?;
    Ok(list)
}

/// Allocates network addresses for a new peer on the server.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
/// * `peer_type` - The type of peer to allocate addresses for (Client or Server)
///
/// # Returns
///
/// A `NetworkState` containing the allocated IP addresses for relay and E2EE interfaces.
///
/// # Errors
///
/// Returns an error if the HTTP request fails or address allocation fails.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::allocate;
/// use wiretap_rs::transport::api::PeerType;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let state = allocate(api_addr, PeerType::Client)?;
///
/// println!("Next client relay IPv4: {}", state.next_client_relay_addr4);
/// println!("Next client relay IPv6: {}", state.next_client_relay_addr6);
/// # Ok(())
/// # }
/// ```
pub fn allocate(addr: SocketAddr, peer_type: PeerType) -> Result<NetworkState> {
    let type_value = match peer_type {
        PeerType::Client => 0,
        PeerType::Server => 1,
    };
    let url = format!("http://{addr}/allocate?type={type_value}");
    let body = read_body(http_agent().get(&url).call())?;
    let state: NetworkState =
        serde_json::from_str(&body).with_context(|| format!("failed to parse allocate: {body}"))?;
    Ok(state)
}

/// Adds a new WireGuard peer to one of the server's interfaces.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
/// * `iface` - The interface to add the peer to (Relay or E2EE)
/// * `config` - The peer configuration to add
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the peer cannot be added.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::add_peer;
/// use wiretap_rs::transport::api::InterfaceType;
/// use wiretap_rs::peer::PeerConfig;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let peer_config = PeerConfig::new()?;
///
/// add_peer(api_addr, InterfaceType::Relay, peer_config)?;
/// # Ok(())
/// # }
/// ```
pub fn add_peer(addr: SocketAddr, iface: InterfaceType, config: PeerConfig) -> Result<()> {
    let iface_value = match iface {
        InterfaceType::Relay => 0,
        InterfaceType::E2EE => 1,
    };
    let url = format!("http://{addr}/addpeer?interface={iface_value}");
    read_body(
        http_agent()
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::to_string(&config)?),
    )
    .map(|_| ())
}

/// Adds allowed IPs to an existing peer on the server.
///
/// # Arguments
///
/// * `addr` - The socket address of the wiretap API endpoint
/// * `public_key` - The public key of the peer to update (base64-encoded)
/// * `allowed_ips` - List of CIDR ranges to add to the peer's allowed IPs
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the peer does not exist.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::api::add_allowed_ips;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// // Use a valid base64-encoded WireGuard public key (44 characters)
/// let peer_pubkey = "YourBase64EncodedPublicKeyGoesHere1234567=";
/// let routes = vec!["10.0.0.0/24".to_string(), "192.168.1.0/24".to_string()];
///
/// add_allowed_ips(api_addr, peer_pubkey, &routes)?;
/// # Ok(())
/// # }
/// ```
pub fn add_allowed_ips(addr: SocketAddr, public_key: &str, allowed_ips: &[String]) -> Result<()> {
    let url = format!("http://{addr}/addallowedips");
    let req = AddAllowedIpsRequest {
        public_key: public_key.to_string(),
        allowed_ips: allowed_ips.to_vec(),
    };
    read_body(
        http_agent()
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::to_string(&req)?),
    )
    .map(|_| ())
}
