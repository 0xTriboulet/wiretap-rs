use crate::peer::parse_config;
use anyhow::{Result, anyhow};
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct StatusSummary {
    pub client_relay_public: String,
    pub client_e2ee_public: String,
    pub servers: Vec<ServerSummary>,
}

#[derive(Debug, Clone)]
pub struct ServerSummary {
    pub public_key: String,
    pub api: Option<IpAddr>,
    pub routes: Vec<IpNet>,
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

pub fn split_routes_and_api(allowed: &[IpNet]) -> (Vec<IpNet>, Option<IpAddr>) {
    if allowed.is_empty() {
        return (Vec::new(), None);
    }
    let mut routes = allowed.to_vec();
    let api = routes.pop().map(|net| net.addr());
    (routes, api)
}

pub fn load_status_summary(relay_path: &str, e2ee_path: &str) -> Result<StatusSummary> {
    let relay_contents = std::fs::read_to_string(relay_path)?;
    let e2ee_contents = std::fs::read_to_string(e2ee_path)?;
    StatusSummary::from_configs(&relay_contents, &e2ee_contents)
}
