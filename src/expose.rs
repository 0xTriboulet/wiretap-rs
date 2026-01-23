use crate::peer::parse_config;
use anyhow::{Result, anyhow};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeRequest {
    pub api_addrs: Vec<IpAddr>,
    pub api_port: u16,
    pub local_port: Option<u16>,
    pub remote_port: u16,
    pub protocol: String,
    pub dynamic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposeMode {
    Expose,
    List,
    Remove,
}

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
