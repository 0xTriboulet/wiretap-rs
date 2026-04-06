//! # wiretap-rs
//!
//! A user-space WireGuard relay/proxy system written in Rust.
//!
//! ## Overview
//!
//! `wiretap-rs` is a Rust port of the original Go-based wiretap, providing a WireGuard-based
//! relay and proxy system that operates entirely in user space. It allows clients to route
//! traffic into a target network through a chain of servers using WireGuard tunnels.
//!
//! The system runs both a **relay** WireGuard interface and an optional nested **E2EE**
//! (end-to-end encrypted) WireGuard interface entirely in user space, terminating WireGuard
//! tunnels and forwarding traffic into the host network using a userspace TCP/UDP stack
//! (smoltcp) plus OS sockets.
//!
//! ## Architecture
//!
//! - **Relay WG tunnel**: Transports packets between peers over UDP
//! - **E2EE WG tunnel**: Optional nested tunnel over the relay for end-to-end encryption
//! - **Userspace data path**:
//!   - TCP/UDP packets handled by smoltcp and bridged to OS sockets
//!   - ICMP echo handled by crafting replies when system ping succeeds
//! - **HTTP API**: Served via the tunnel address for peer management and port exposure
//!
//! ## Main Modules
//!
//! - [`peer`]: WireGuard peer and configuration management
//! - [`api`]: HTTP API client functions for server communication
//! - [`add`]: Logic for adding clients and servers to the network
//! - [`expose`]: Port exposure functionality (TCP/UDP/SOCKS5)
//! - [`serve`]: Server runtime and main event loop
//! - [`transport`]: WireGuard transport layer and packet handling
//! - [`constants`]: Network subnet and IP address constants
//! - [`logging`]: Logging configuration and utilities
//! - [`ping`]: Connectivity testing
//! - [`status`]: Status reporting and introspection
//! - [`cli`]: Command-line interface (not typically used as library)
//!
//! ## Quick Start
//!
//! ### As a Library
//!
//! Add to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! wiretap-rs = "0.1"
//! ```
//!
//! ### Basic Usage Example
//!
//! ```rust,no_run
//! use wiretap_rs::peer::{Config, parse_config};
//! use wiretap_rs::api;
//! use std::net::SocketAddr;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Parse a WireGuard configuration file
//! let config_content = std::fs::read_to_string("wiretap.conf")?;
//! let config = parse_config(&config_content)?;
//!
//! // Connect to a wiretap server API
//! let api_addr: SocketAddr = "[::2]:80".parse()?;
//! let response = api::ping(api_addr)?;
//! println!("Server response: {}", response);
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - Pure Rust implementation with no external WireGuard dependencies
//! - Userspace TCP/UDP/ICMP handling via smoltcp
//! - Dynamic port exposure with SOCKS5 support
//! - API-driven peer management
//! - Nested E2EE tunnels for enhanced security
//!
//! ## Protocol Support
//!
//! - ✅ TCP
//! - ✅ UDP
//! - ✅ ICMP echo (ping)
//! - ❌ Other IP protocols (not supported)

pub mod add;
pub mod api;
pub mod cli;
pub(crate) mod clipboard;
pub mod constants;
pub mod expose;
pub mod logging;
pub mod peer;
pub mod ping;
pub mod serve;
pub mod status;
pub mod transport;
