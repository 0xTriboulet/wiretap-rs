//! Port exposure functionality for wiretap.
//!
//! This module provides utilities for exposing ports through the wiretap tunnel,
//! allowing remote access to local services. Supports TCP, UDP, and dynamic SOCKS5 proxy.
//!
//! # Port Exposure Modes
//!
//! - **TCP/UDP**: Expose a specific local port as a remote port
//! - **Dynamic (SOCKS5)**: Create a SOCKS5 proxy on the remote server
//!
//! # Example
//!
//! ```rust,no_run
//! use wiretap_rs::expose::{resolve_api_addrs, validate_expose_request, run_expose, ExposeMode};
//!
//! # fn example() -> anyhow::Result<()> {
//! // Resolve API addresses from configuration
//! let api_addrs = resolve_api_addrs("wiretap.conf", "")?;
//!
//! // Create a TCP port exposure request
//! let request = validate_expose_request(
//!     api_addrs,
//!     80,                  // API port
//!     Some(8080),          // Local port
//!     Some(80),            // Remote port
//!     "tcp",               // Protocol
//!     false                // Not dynamic
//! )?;
//!
//! // Execute the exposure
//! run_expose(ExposeMode::Expose, &request)?;
//! # Ok(())
//! # }
//! ```

use crate::peer::parse_config;
use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};

/// A validated port exposure request.
///
/// Contains all the information needed to expose a port through the wiretap tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeRequest {
    /// List of API addresses to send the exposure request to.
    pub api_addrs: Vec<IpAddr>,

    /// Port number of the API endpoint.
    pub api_port: u16,

    /// Local port to expose (None for dynamic SOCKS5).
    pub local_port: Option<u16>,

    /// Remote port number on the server.
    pub remote_port: u16,

    /// Protocol: "tcp", "udp", or "dynamic" for SOCKS5.
    pub protocol: String,

    /// Whether this is a dynamic SOCKS5 proxy.
    pub dynamic: bool,
}

/// Mode of operation for port exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposeMode {
    /// Create a new port exposure.
    Expose,

    /// List existing port exposures.
    List,

    /// Remove an existing port exposure.
    Remove,
}

/// Resolves API addresses from a configuration file or explicit address.
///
/// # Arguments
///
/// * `config_path` - Path to the wiretap configuration file
/// * `server_address` - Explicit server address (if provided, overrides config file)
///
/// # Returns
///
/// A list of API addresses that can be used to communicate with wiretap servers.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration file cannot be read
/// - The server address cannot be parsed
/// - No API addresses are found in the configuration
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::expose::resolve_api_addrs;
///
/// # fn example() -> anyhow::Result<()> {
/// // Resolve from config file
/// let addrs = resolve_api_addrs("wiretap.conf", "")?;
/// println!("Found {} API address(es)", addrs.len());
///
/// // Use explicit address
/// let addrs = resolve_api_addrs("wiretap.conf", "::2")?;
/// assert_eq!(addrs.len(), 1);
/// # Ok(())
/// # }
/// ```
pub fn resolve_api_addrs(config_path: &str, server_address: &str) -> Result<Vec<IpAddr>> {
    if !server_address.is_empty() {
        let addr = server_address.parse::<IpAddr>()?;
        return Ok(vec![addr]);
    }

    let contents = std::fs::read_to_string(config_path)?;
    let config = parse_config(&contents)?;
    let mut addrs = Vec::new();
    for peer in config.peers() {
        if let Some(api) = peer.api_addr() {
            addrs.push(api);
        }
    }
    if addrs.is_empty() {
        return Err(anyhow!("no API addresses found"));
    }
    Ok(addrs)
}

/// Validates and constructs a port exposure request.
///
/// # Arguments
///
/// * `api_addrs` - List of API addresses to send requests to
/// * `api_port` - Port number of the API endpoint
/// * `local_port` - Local port to expose (None for dynamic SOCKS5)
/// * `remote_port` - Remote port on the server
/// * `protocol` - Protocol ("tcp", "udp", or "dynamic")
/// * `dynamic` - Whether this is a dynamic SOCKS5 proxy
///
/// # Returns
///
/// A validated `ExposeRequest` ready to be executed.
///
/// # Errors
///
/// Returns an error if:
/// - No API addresses are provided
/// - Port numbers are invalid (0 or missing when required)
/// - Protocol is invalid (must be "tcp" or "udp" for non-dynamic exposures)
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::expose::validate_expose_request;
///
/// # fn example() -> anyhow::Result<()> {
/// // TCP port exposure
/// let request = validate_expose_request(
///     vec!["::2".parse()?],
///     80,
///     Some(8080),  // Local port
///     Some(80),    // Remote port
///     "tcp",
///     false
/// )?;
///
/// // Dynamic SOCKS5 proxy
/// let request = validate_expose_request(
///     vec!["::2".parse()?],
///     80,
///     None,        // No local port for SOCKS5
///     Some(1080),  // Remote SOCKS5 port
///     "dynamic",
///     true
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn validate_expose_request(
    api_addrs: Vec<IpAddr>,
    api_port: u16,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    protocol: &str,
    dynamic: bool,
) -> Result<ExposeRequest> {
    if api_addrs.is_empty() {
        return Err(anyhow!("no API addresses provided"));
    }
    if api_port == 0 {
        return Err(anyhow!("invalid API port"));
    }

    if dynamic {
        let remote = remote_port.ok_or_else(|| anyhow!("remote port required for dynamic"))?;
        if remote == 0 {
            return Err(anyhow!("invalid remote port"));
        }
        return Ok(ExposeRequest {
            api_addrs,
            api_port,
            local_port: None,
            remote_port: remote,
            protocol: protocol.to_string(),
            dynamic: true,
        });
    }

    let local = local_port.ok_or_else(|| anyhow!("local port required"))?;
    if local == 0 {
        return Err(anyhow!("invalid local port"));
    }
    let remote = remote_port.unwrap_or(local);
    if remote == 0 {
        return Err(anyhow!("invalid remote port"));
    }
    if protocol != "tcp" && protocol != "udp" {
        return Err(anyhow!("invalid protocol"));
    }

    Ok(ExposeRequest {
        api_addrs,
        api_port,
        local_port: Some(local),
        remote_port: remote,
        protocol: protocol.to_string(),
        dynamic: false,
    })
}

/// Executes a port exposure operation.
///
/// Performs the requested operation (expose, list, or remove) on all API addresses
/// in the request and prints status information to stdout.
///
/// # Arguments
///
/// * `mode` - The operation to perform
/// * `request` - The validated exposure request
///
/// # Errors
///
/// Returns an error if any API request fails.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::expose::{validate_expose_request, run_expose, ExposeMode};
///
/// # fn example() -> anyhow::Result<()> {
/// let request = validate_expose_request(
///     vec!["::2".parse()?],
///     80,
///     Some(8080),
///     Some(80),
///     "tcp",
///     false
/// )?;
///
/// // Expose the port
/// run_expose(ExposeMode::Expose, &request)?;
///
/// // List all exposures
/// run_expose(ExposeMode::List, &request)?;
///
/// // Remove the exposure
/// run_expose(ExposeMode::Remove, &request)?;
/// # Ok(())
/// # }
/// ```
pub fn run_expose(mode: ExposeMode, request: &ExposeRequest) -> Result<()> {
    match mode {
        ExposeMode::Expose => {
            for addr in &request.api_addrs {
                let api = SocketAddr::new(*addr, request.api_port);
                crate::api::expose(
                    api,
                    request.local_port,
                    request.remote_port,
                    &request.protocol,
                    request.dynamic,
                )?;
                println!(
                    "expose: local {} <- remote {}/{} [{}]",
                    request
                        .local_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "*".into()),
                    request.remote_port,
                    request.protocol,
                    api
                );
            }
        }
        ExposeMode::List => {
            for addr in &request.api_addrs {
                let api = SocketAddr::new(*addr, request.api_port);
                let rules = crate::api::expose_list(api)?;
                println!("[{}] {} rules", api, rules.len());
                for line in format_expose_rules(&rules) {
                    println!("  {}", line);
                }
            }
        }
        ExposeMode::Remove => {
            for addr in &request.api_addrs {
                let api = SocketAddr::new(*addr, request.api_port);
                crate::api::expose_remove(
                    api,
                    request.local_port,
                    request.remote_port,
                    &request.protocol,
                    request.dynamic,
                )?;
                println!(
                    "remove: local {} <- remote {}/{} [{}]",
                    request
                        .local_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "*".into()),
                    request.remote_port,
                    request.protocol,
                    api
                );
            }
        }
    }
    Ok(())
}

/// Formats a list of exposure rules as human-readable strings.
///
/// # Arguments
///
/// * `rules` - Slice of exposure rules to format
///
/// # Returns
///
/// A vector of formatted strings describing each exposure rule.
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::expose::format_expose_rules;
/// use wiretap_rs::api;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let rules = api::expose_list(api_addr)?;
/// let formatted = format_expose_rules(&rules);
///
/// for line in formatted {
///     println!("{}", line);
/// }
/// # Ok(())
/// # }
/// ```
pub fn format_expose_rules(rules: &[crate::api::ExposeRule]) -> Vec<String> {
    rules
        .iter()
        .map(|r| {
            let local = r
                .local_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "*".into());
            format!("local {} <- remote {}/{}", local, r.remote_port, r.protocol)
        })
        .collect()
}
