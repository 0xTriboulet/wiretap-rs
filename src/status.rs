//! Status reporting and introspection for wiretap configurations.
//!
//! This module provides utilities to load and parse wiretap configuration files,
//! extract server information, and build status summaries of the network topology.
//!
//! # Example
//!
//! ```rust,no_run
//! use wiretap_rs::status;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Load status from configuration files
//! let summary = status::load_status_summary(
//!     "wiretap_relay.conf",
//!     "wiretap.conf"
//! )?;
//!
//! println!("Client relay public key: {}", summary.client_relay_public);
//! println!("Client E2EE public key: {}", summary.client_e2ee_public);
//!
//! for server in &summary.servers {
//!     println!("Server: {}", server.public_key);
//!     if let Some(api) = &server.api {
//!         println!("  API: {}", api);
//!     }
//!     for route in &server.routes {
//!         println!("  Route: {}", route);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use crate::peer::parse_config;
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use std::net::IpAddr;

/// Summary of the current wiretap client configuration.
///
/// Contains public keys for the client's relay and E2EE interfaces,
/// plus information about all configured servers.
#[derive(Debug, Clone)]
pub struct StatusSummary {
    /// Public key of the client's relay interface.
    pub client_relay_public: String,

    /// Public key of the client's E2EE interface.
    pub client_e2ee_public: String,

    /// List of servers configured in the E2EE interface.
    pub servers: Vec<ServerSummary>,
}

/// Information about a single server in the wiretap network.
#[derive(Debug, Clone)]
pub struct ServerSummary {
    /// WireGuard public key of the server.
    pub public_key: String,

    /// API address of the server, if available.
    pub api: Option<IpAddr>,

    /// Network routes accessible through this server.
    pub routes: Vec<IpNet>,

    /// Optional nickname for the server.
    pub nickname: Option<String>,
}

impl StatusSummary {
    pub fn from_configs(relay_contents: &str, e2ee_contents: &str) -> Result<Self> {
        if relay_contents.trim().is_empty() || e2ee_contents.trim().is_empty() {
            return Err(anyhow!("config contents missing"));
        }
        let relay = parse_config(relay_contents)?;
        let e2ee = parse_config(e2ee_contents)?;

        let mut servers = Vec::new();
        for peer in e2ee.peers() {
            let (routes, api) = split_routes_and_api(peer.allowed_ips());
            servers.push(ServerSummary {
                public_key: peer.public_key().to_string(),
                api,
                routes,
                nickname: peer.nickname().map(|v| v.to_string()),
            });
        }

        Ok(Self {
            client_relay_public: relay.public_key().to_string(),
            client_e2ee_public: e2ee.public_key().to_string(),
            servers,
        })
    }
}

/// Splits a peer's allowed IPs into routes and an optional API address.
///
/// The last allowed IP in the list is treated as the API address, and the
/// remaining entries are treated as routes to networks accessible through the server.
///
/// # Arguments
///
/// * `allowed` - Slice of IP networks from a peer's AllowedIPs configuration
///
/// # Returns
///
/// A tuple of `(routes, api_address)` where:
/// - `routes` are the network routes (all but the last allowed IP)
/// - `api_address` is the IP address from the last allowed IP entry
///
/// # Example
///
/// ```rust
/// use wiretap_rs::status::split_routes_and_api;
/// use ipnet::IpNet;
///
/// let allowed = vec![
///     "10.0.0.0/24".parse::<IpNet>().unwrap(),
///     "192.168.1.0/24".parse().unwrap(),
///     "::2/128".parse().unwrap(),  // API address
/// ];
///
/// let (routes, api) = split_routes_and_api(&allowed);
/// assert_eq!(routes.len(), 2);
/// assert_eq!(api.unwrap().to_string(), "::2");
/// ```
pub fn split_routes_and_api(allowed: &[IpNet]) -> (Vec<IpNet>, Option<IpAddr>) {
    if allowed.is_empty() {
        return (Vec::new(), None);
    }
    let mut routes = allowed.to_vec();
    let api = routes.pop().map(|net| net.addr());
    (routes, api)
}

/// Loads a status summary from wiretap configuration files.
///
/// Reads and parses the relay and E2EE configuration files to extract
/// client public keys and server information.
///
/// # Arguments
///
/// * `relay_path` - Path to the client relay configuration file
/// * `e2ee_path` - Path to the client E2EE configuration file
///
/// # Returns
///
/// A `StatusSummary` containing the parsed configuration information.
///
/// # Errors
///
/// Returns an error if:
/// - Either configuration file cannot be read
/// - The configuration files contain invalid WireGuard syntax
/// - Required fields are missing from the configuration
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::status::load_status_summary;
///
/// # fn example() -> anyhow::Result<()> {
/// let summary = load_status_summary(
///     "wiretap_relay.conf",
///     "wiretap.conf"
/// )?;
///
/// println!("Client has {} server(s) configured", summary.servers.len());
/// # Ok(())
/// # }
/// ```
pub fn load_status_summary(relay_path: &str, e2ee_path: &str) -> Result<StatusSummary> {
    let relay_contents = std::fs::read_to_string(relay_path)?;
    let e2ee_contents = std::fs::read_to_string(e2ee_path)?;
    StatusSummary::from_configs(&relay_contents, &e2ee_contents)
}
