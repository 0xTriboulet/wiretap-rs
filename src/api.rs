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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeRule {
    pub remote_addr: IpAddr,
    pub local_port: Option<u16>,
    pub remote_port: u16,
    pub protocol: String,
}

pub fn ping(addr: SocketAddr) -> Result<String> {
    let url = format!("http://{addr}/ping");
    let body = read_body(http_agent().get(&url).call())?;
    Ok(body)
}

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

pub fn server_info(addr: SocketAddr) -> Result<(Config, Config)> {
    let url = format!("http://{addr}/serverinfo");
    let body = read_body(http_agent().get(&url).call())?;
    let configs: ServerConfigs = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse serverinfo: {body}"))?;
    Ok((configs.relay_config, configs.e2ee_config))
}

pub fn server_interfaces(addr: SocketAddr) -> Result<Vec<HostInterface>> {
    let url = format!("http://{addr}/serverinterfaces");
    let body = read_body(http_agent().get(&url).call())?;
    let list: Vec<HostInterface> = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse serverinterfaces: {body}"))?;
    Ok(list)
}

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
