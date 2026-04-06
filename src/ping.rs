//! Connectivity testing via the wiretap API.
//!
//! This module provides functions to test connectivity to a wiretap server
//! by sending ping requests to the HTTP API and measuring response times.
//!
//! # Example
//!
//! ```rust,no_run
//! use wiretap_rs::ping;
//! use std::net::SocketAddr;
//!
//! # fn example() -> anyhow::Result<()> {
//! let api_addr: SocketAddr = "[::2]:80".parse()?;
//! let response = ping::run_ping(api_addr)?;
//!
//! println!("Ping successful: {}", response.message);
//! println!("Round-trip time: {:?}", response.duration);
//! # Ok(())
//! # }
//! ```

use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Response from a ping request to the wiretap API.
///
/// Contains the server's response message and the round-trip duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResponse {
    /// The message returned by the server (typically "pong").
    pub message: String,

    /// The round-trip time for the ping request.
    pub duration: Duration,
}

/// Sends a ping request to the wiretap API and measures the response time.
///
/// # Arguments
///
/// * `api` - The socket address of the wiretap API endpoint
///
/// # Returns
///
/// A `PingResponse` containing the server's message and the round-trip duration.
///
/// # Errors
///
/// Returns an error if:
/// - The HTTP request fails
/// - The server is unreachable
/// - The response cannot be parsed
///
/// # Example
///
/// ```rust,no_run
/// use wiretap_rs::ping::run_ping;
/// use std::net::SocketAddr;
///
/// # fn example() -> anyhow::Result<()> {
/// // Ping the default IPv6 API address
/// let api_addr: SocketAddr = "[::2]:80".parse()?;
/// let response = run_ping(api_addr)?;
///
/// println!("Server responded: {}", response.message);
/// println!("Latency: {} ms", response.duration.as_millis());
/// # Ok(())
/// # }
/// ```
pub fn run_ping(api: SocketAddr) -> Result<PingResponse> {
    let start = Instant::now();
    let message = crate::api::ping(api)?;
    let duration = start.elapsed();
    Ok(PingResponse { message, duration })
}
