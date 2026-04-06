use crate::transport::{FlowTuple, TransportProtocol};
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub flow: FlowTuple,
    pub protocol: TransportProtocol,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: IpNet,
    pub next_hop: Option<IpAddr>,
    pub peer_endpoint: Option<SocketAddr>,
}

#[derive(Debug, Default)]
pub struct PacketRouter {
    routes: Vec<Route>,
}

impl PacketRouter {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn add_route(&mut self, route: Route) {
        self.routes.push(route);
    }

    pub fn route(&self, dst: IpAddr) -> Option<&Route> {
        let mut best: Option<&Route> = None;
        let mut best_prefix = 0u8;
        for route in &self.routes {
            if route.destination.contains(&dst) {
                let prefix = route.destination.prefix_len();
                if prefix >= best_prefix {
                    best_prefix = prefix;
                    best = Some(route);
                }
            }
        }
        best
    }

    pub fn add_routes_from_allowed(&mut self, allowed: &[String]) -> Result<()> {
        for entry in allowed {
            let net: IpNet = entry
                .parse()
                .map_err(|err| anyhow!("invalid route {entry}: {err}"))?;
            self.add_route(Route {
                destination: net,
                next_hop: None,
                peer_endpoint: None,
            });
        }
        Ok(())
    }
}
