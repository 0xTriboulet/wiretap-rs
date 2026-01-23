use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResponse {
    pub message: String,
    pub duration: Duration,
}

pub fn run_ping(api: SocketAddr) -> Result<PingResponse> {
    let start = Instant::now();
    let message = crate::api::ping(api)?;
    let duration = start.elapsed();
    Ok(PingResponse { message, duration })
}
