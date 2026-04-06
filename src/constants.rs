//! Network constants and default values for wiretap.
//!
//! This module provides the standard subnet ranges, IP addresses, and configuration
//! defaults used throughout the wiretap system. These constants define the network
//! topology for relay tunnels, E2EE tunnels, and the API interface.
//!
//! # Network Architecture
//!
//! Wiretap uses separate subnet ranges for different purposes:
//!
//! - **API subnets**: `::/8` (IPv6) and `192.0.2.0/24` (IPv4) - for the HTTP API
//! - **Relay subnets**: `fd:17::/40` (IPv6) and `172.17.0.0/16` (IPv4) - server relay interfaces
//! - **Client relay subnets**: `fd:16::/40` (IPv6) and `172.16.0.0/16` (IPv4) - client relay interfaces
//! - **E2EE subnets**: `fd:18::/40` (IPv6) and `172.18.0.0/16` (IPv4) - server E2EE interfaces
//! - **Client E2EE subnets**: `fd:19::/40` (IPv6) and `172.19.0.0/16` (IPv4) - client E2EE interfaces
//!
//! # Example
//!
//! ```rust
//! use wiretap_rs::constants;
//!
//! // Get the default API address for IPv6
//! let api_addr = constants::default_api_v6();
//! println!("API address: {}", api_addr); // ::2
//!
//! // Get the relay subnet range
//! let relay_subnet = constants::relay_subnet_v4();
//! println!("Relay subnet: {}", relay_subnet); // 172.17.0.0/16
//! ```

use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Version string for the wiretap-rs implementation.
pub const VERSION: &str = "v0.1.0";

/// Default UDP port for the relay WireGuard interface.
pub const DEFAULT_PORT: u16 = 51820;

/// Default UDP port for the E2EE (end-to-end encrypted) WireGuard interface.
pub const DEFAULT_E2EE_PORT: u16 = 51821;

/// Default WireGuard persistent keepalive interval in seconds.
pub const DEFAULT_KEEPALIVE: u16 = 25;

/// Default MTU (Maximum Transmission Unit) for WireGuard interfaces.
pub const DEFAULT_MTU: u16 = 1420;

/// Default timeout for operation completion in milliseconds.
pub const DEFAULT_COMPLETION_TIMEOUT_MS: u64 = 5_000;

/// Default connection timeout in milliseconds.
pub const DEFAULT_CONN_TIMEOUT_MS: u64 = 5_000;

/// Default TCP keepalive idle time in seconds before sending probes.
pub const DEFAULT_KEEPALIVE_IDLE_SECS: u64 = 60;

/// Default TCP keepalive probe interval in seconds.
pub const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 60;

/// Default number of TCP keepalive probes before giving up.
pub const DEFAULT_KEEPALIVE_COUNT: u32 = 3;

/// Default UDP connection idle timeout in seconds.
pub const DEFAULT_UDP_TIMEOUT_SECS: u64 = 60;

/// Number of bits in the subnet mask for IPv4 allocations.
pub const SUBNET_V4_BITS: u8 = 24;

/// Number of bits in the subnet mask for IPv6 allocations.
pub const SUBNET_V6_BITS: u8 = 48;

/// Default filename for the client relay configuration file.
pub const DEFAULT_CONFIG_RELAY: &str = "wiretap_relay.conf";

/// Default filename for the client E2EE configuration file.
pub const DEFAULT_CONFIG_E2EE: &str = "wiretap.conf";

/// Default filename for the server configuration file.
pub const DEFAULT_CONFIG_SERVER: &str = "wiretap_server.conf";

/// HTTP API port number (served over the tunnel interface).
pub const API_PORT: u16 = 80;

/// Returns the IPv6 subnet used for the API interface.
///
/// The API subnet is `::/8`, which provides a large address space for API endpoints.
/// The default API address is typically `::2`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::api_subnet_v6;
///
/// let subnet = api_subnet_v6();
/// assert_eq!(subnet.to_string(), "::/8");
/// ```
pub fn api_subnet_v6() -> Ipv6Net {
    "::/8".parse().expect("valid api subnet v6")
}

/// Returns the IPv4 subnet used for the API interface.
///
/// The API subnet is `192.0.2.0/24` (from RFC 5737 TEST-NET-1).
/// The default API address is `192.0.2.2`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::api_subnet_v4;
///
/// let subnet = api_subnet_v4();
/// assert_eq!(subnet.to_string(), "192.0.2.0/24");
/// ```
pub fn api_subnet_v4() -> Ipv4Net {
    "192.0.2.0/24".parse().expect("valid api subnet v4")
}

/// Returns the IPv4 subnet for client relay interfaces.
///
/// Client relay addresses are allocated from `172.16.0.0/16`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::client_relay_subnet_v4;
///
/// let subnet = client_relay_subnet_v4();
/// assert_eq!(subnet.to_string(), "172.16.0.0/16");
/// ```
pub fn client_relay_subnet_v4() -> Ipv4Net {
    "172.16.0.0/16"
        .parse()
        .expect("valid client relay v4 subnet")
}

/// Returns the IPv6 subnet for client relay interfaces.
///
/// Client relay addresses are allocated from `fd:16::/40`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::client_relay_subnet_v6;
///
/// let subnet = client_relay_subnet_v6();
/// assert_eq!(subnet.to_string(), "fd:16::/40");
/// ```
pub fn client_relay_subnet_v6() -> Ipv6Net {
    "fd:16::/40".parse().expect("valid client relay v6 subnet")
}

/// Returns the IPv4 subnet for server relay interfaces.
///
/// Server relay addresses are allocated from `172.17.0.0/16`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::relay_subnet_v4;
///
/// let subnet = relay_subnet_v4();
/// assert_eq!(subnet.to_string(), "172.17.0.0/16");
/// ```
pub fn relay_subnet_v4() -> Ipv4Net {
    "172.17.0.0/16".parse().expect("valid relay v4 subnet")
}

/// Returns the IPv6 subnet for server relay interfaces.
///
/// Server relay addresses are allocated from `fd:17::/40`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::relay_subnet_v6;
///
/// let subnet = relay_subnet_v6();
/// assert_eq!(subnet.to_string(), "fd:17::/40");
/// ```
pub fn relay_subnet_v6() -> Ipv6Net {
    "fd:17::/40".parse().expect("valid relay v6 subnet")
}

/// Returns the IPv4 subnet for server E2EE interfaces.
///
/// Server E2EE addresses are allocated from `172.18.0.0/16`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::e2ee_subnet_v4;
///
/// let subnet = e2ee_subnet_v4();
/// assert_eq!(subnet.to_string(), "172.18.0.0/16");
/// ```
pub fn e2ee_subnet_v4() -> Ipv4Net {
    "172.18.0.0/16".parse().expect("valid e2ee v4 subnet")
}

/// Returns the IPv6 subnet for server E2EE interfaces.
///
/// Server E2EE addresses are allocated from `fd:18::/40`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::e2ee_subnet_v6;
///
/// let subnet = e2ee_subnet_v6();
/// assert_eq!(subnet.to_string(), "fd:18::/40");
/// ```
pub fn e2ee_subnet_v6() -> Ipv6Net {
    "fd:18::/40".parse().expect("valid e2ee v6 subnet")
}

/// Returns the IPv4 subnet for client E2EE interfaces.
///
/// Client E2EE addresses are allocated from `172.19.0.0/16`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::client_e2ee_subnet_v4;
///
/// let subnet = client_e2ee_subnet_v4();
/// assert_eq!(subnet.to_string(), "172.19.0.0/16");
/// ```
pub fn client_e2ee_subnet_v4() -> Ipv4Net {
    "172.19.0.0/16"
        .parse()
        .expect("valid client e2ee v4 subnet")
}

/// Returns the IPv6 subnet for client E2EE interfaces.
///
/// Client E2EE addresses are allocated from `fd:19::/40`.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::client_e2ee_subnet_v6;
///
/// let subnet = client_e2ee_subnet_v6();
/// assert_eq!(subnet.to_string(), "fd:19::/40");
/// ```
pub fn client_e2ee_subnet_v6() -> Ipv6Net {
    "fd:19::/40".parse().expect("valid client e2ee v6 subnet")
}

/// Returns the default IPv4 address for a client relay interface.
///
/// This is the first usable address in the client relay subnet (`172.16.0.1`).
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_client_relay_v4;
///
/// let addr = default_client_relay_v4();
/// assert_eq!(addr.to_string(), "172.16.0.1");
/// ```
pub fn default_client_relay_v4() -> Ipv4Addr {
    increment_v4(client_relay_subnet_v4().network(), 1)
}

/// Returns the default IPv6 address for a client relay interface.
///
/// This is the first usable address in the client relay subnet.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_client_relay_v6;
///
/// let addr = default_client_relay_v6();
/// assert_eq!(addr.to_string(), "fd:16::1");
/// ```
pub fn default_client_relay_v6() -> Ipv6Addr {
    increment_v6(client_relay_subnet_v6().network(), 1)
}

/// Returns the default IPv4 address for a client E2EE interface.
///
/// This is the first usable address in the client E2EE subnet (`172.19.0.1`).
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_client_e2ee_v4;
///
/// let addr = default_client_e2ee_v4();
/// assert_eq!(addr.to_string(), "172.19.0.1");
/// ```
pub fn default_client_e2ee_v4() -> Ipv4Addr {
    increment_v4(client_e2ee_subnet_v4().network(), 1)
}

/// Returns the default IPv6 address for a client E2EE interface.
///
/// This is the first usable address in the client E2EE subnet.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_client_e2ee_v6;
///
/// let addr = default_client_e2ee_v6();
/// assert_eq!(addr.to_string(), "fd:19::1");
/// ```
pub fn default_client_e2ee_v6() -> Ipv6Addr {
    increment_v6(client_e2ee_subnet_v6().network(), 1)
}

/// Returns the default IPv4 address for a server relay interface.
///
/// This is the second usable address in the relay subnet (`172.17.0.2`).
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_server_relay_v4;
///
/// let addr = default_server_relay_v4();
/// assert_eq!(addr.to_string(), "172.17.0.2");
/// ```
pub fn default_server_relay_v4() -> Ipv4Addr {
    increment_v4(relay_subnet_v4().network(), 2)
}

/// Returns the default IPv6 address for a server relay interface.
///
/// This is the second usable address in the relay subnet.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_server_relay_v6;
///
/// let addr = default_server_relay_v6();
/// assert_eq!(addr.to_string(), "fd:17::2");
/// ```
pub fn default_server_relay_v6() -> Ipv6Addr {
    increment_v6(relay_subnet_v6().network(), 2)
}

/// Returns the default IPv4 address for a server E2EE interface.
///
/// This is the second usable address in the E2EE subnet (`172.18.0.2`).
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_server_e2ee_v4;
///
/// let addr = default_server_e2ee_v4();
/// assert_eq!(addr.to_string(), "172.18.0.2");
/// ```
pub fn default_server_e2ee_v4() -> Ipv4Addr {
    increment_v4(e2ee_subnet_v4().network(), 2)
}

/// Returns the default IPv6 address for a server E2EE interface.
///
/// This is the second usable address in the E2EE subnet.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_server_e2ee_v6;
///
/// let addr = default_server_e2ee_v6();
/// assert_eq!(addr.to_string(), "fd:18::2");
/// ```
pub fn default_server_e2ee_v6() -> Ipv6Addr {
    increment_v6(e2ee_subnet_v6().network(), 2)
}

/// Returns the default IPv6 address for the API interface.
///
/// This is typically `::2`, the standard API endpoint for IPv6 connections.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_api_v6;
///
/// let addr = default_api_v6();
/// assert_eq!(addr.to_string(), "::2");
/// ```
pub fn default_api_v6() -> Ipv6Addr {
    increment_v6(api_subnet_v6().network(), 2)
}

/// Returns the default IPv4 address for the API interface.
///
/// This is `192.0.2.2`, the standard API endpoint for IPv4 connections.
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::default_api_v4;
///
/// let addr = default_api_v4();
/// assert_eq!(addr.to_string(), "192.0.2.2");
/// ```
pub fn default_api_v4() -> Ipv4Addr {
    increment_v4(api_subnet_v4().network(), 2)
}

/// Increments an IPv4 address by a given delta.
///
/// Uses saturating addition to prevent overflow.
///
/// # Arguments
///
/// * `base` - The starting IPv4 address
/// * `delta` - The amount to increment by
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::increment_v4;
/// use std::net::Ipv4Addr;
///
/// let base = Ipv4Addr::new(192, 168, 1, 0);
/// let result = increment_v4(base, 10);
/// assert_eq!(result, Ipv4Addr::new(192, 168, 1, 10));
/// ```
pub fn increment_v4(base: Ipv4Addr, delta: u32) -> Ipv4Addr {
    let value = u32::from(base).saturating_add(delta);
    Ipv4Addr::from(value)
}

/// Increments an IPv6 address by a given delta.
///
/// Uses saturating addition to prevent overflow.
///
/// # Arguments
///
/// * `base` - The starting IPv6 address
/// * `delta` - The amount to increment by
///
/// # Example
///
/// ```rust
/// use wiretap_rs::constants::increment_v6;
/// use std::net::Ipv6Addr;
///
/// let base = Ipv6Addr::new(0xfd, 0x16, 0, 0, 0, 0, 0, 0);
/// let result = increment_v6(base, 5);
/// assert_eq!(result, Ipv6Addr::new(0xfd, 0x16, 0, 0, 0, 0, 0, 5));
/// ```
pub fn increment_v6(base: Ipv6Addr, delta: u128) -> Ipv6Addr {
    let value = u128::from(base).saturating_add(delta);
    Ipv6Addr::from(value)
}

/// Applies an IPv4 network prefix mask and returns the masked address.
pub fn mask_prefix_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    Ipv4Addr::from(u32::from(addr) & mask)
}

/// Applies an IPv6 network prefix mask and returns the masked address.
pub fn mask_prefix_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    };
    Ipv6Addr::from(u128::from(addr) & mask)
}
