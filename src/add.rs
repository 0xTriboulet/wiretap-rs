use crate::constants;
use crate::peer::{
    create_server_command, create_server_file, next_prefix_for_peers, parse_config, Config,
    PeerConfigArgs, Shell,
};
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct AddServerArgs {
    pub endpoint: String,
    pub routes: Vec<String>,
    pub outbound_endpoint: Option<String>,
    pub port: Option<u16>,
    pub keepalive: u16,
    pub server_address: Option<String>,
    pub localhost_ip: Option<String>,
    pub nickname: Option<String>,
    pub disable_ipv6: bool,
}

#[derive(Debug, Clone)]
pub struct AddServerPlan {
    pub client_relay_update: String,
    pub client_e2ee_update: String,
    pub server_relay_config: String,
    pub server_e2ee_config: String,
    pub server_command_posix: String,
    pub server_command_powershell: String,
}

#[derive(Debug, Clone)]
pub struct AddServerApiPlan {
    pub plan: AddServerPlan,
    pub server_relay_peer: crate::peer::PeerConfig,
}

#[derive(Debug, Clone)]
pub struct AddClientArgs {
    pub endpoint: String,
    pub port: Option<u16>,
    pub disable_ipv6: bool,
}

#[derive(Debug, Clone)]
pub struct AddClientApiArgs {
    pub endpoint: Option<String>,
    pub outbound_endpoint: Option<String>,
    pub port: Option<u16>,
    pub keepalive: u16,
    pub disable_ipv6: bool,
}

#[derive(Debug, Clone)]
pub struct AddClientPlan {
    pub relay_config: String,
    pub e2ee_config: String,
}

#[derive(Debug, Clone)]
pub struct AddClientApiPlan {
    pub plan: AddClientPlan,
    pub client_relay_peer: crate::peer::PeerConfig,
    pub client_e2ee_peer: crate::peer::PeerConfig,
    pub leaf_addr: IpAddr,
}

pub fn build_add_client_plan(
    relay_contents: &str,
    e2ee_contents: &str,
    args: &AddClientArgs,
) -> Result<AddClientPlan> {
    let relay = parse_config(relay_contents)?;
    let e2ee = parse_config(e2ee_contents)?;
    let disable_v6 = args.disable_ipv6
        || (e2ee.addresses().len() == 1
            && e2ee
                .addresses()
                .first()
                .is_some_and(|net| net.addr().is_ipv4()));

    let client_relay_addr = relay
        .addresses()
        .first()
        .ok_or_else(|| anyhow!("missing relay interface address"))?
        .addr();
    let client_e2ee_addr = e2ee
        .addresses()
        .first()
        .ok_or_else(|| anyhow!("missing e2ee interface address"))?
        .addr();

    let port = match args.port {
        Some(port) => port,
        None => port_from_endpoint(&args.endpoint)?,
    };

    let relay_allowed = relay
        .peers()
        .first()
        .map(|peer| {
            peer.allowed_ips()
                .iter()
                .filter(|ip| !disable_v6 || ip.addr().is_ipv4())
                .map(|ip| ip.to_string())
                .collect()
        })
        .unwrap_or_else(Vec::new);

    let relay_peer_args = PeerConfigArgs {
        public_key: Some(relay.public_key().to_string()),
        allowed_ips: relay_allowed,
        endpoint: Some(args.endpoint.clone()),
        ..Default::default()
    };

    let e2ee_allowed = e2ee
        .peers()
        .iter()
        .flat_map(|peer| peer.allowed_ips().iter())
        .filter(|ip| !disable_v6 || ip.addr().is_ipv4())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();

    let e2ee_peer_args = PeerConfigArgs {
        public_key: Some(e2ee.public_key().to_string()),
        allowed_ips: e2ee_allowed,
        endpoint: Some(format!("{}:51821", client_relay_addr)),
        ..Default::default()
    };

    let mut new_relay = Config::new()?;
    new_relay.set_port(port)?;
    let relay_addrs = next_prefix_for_peers(relay.peers());
    let relay_addr = relay_addrs
        .first()
        .map(|ip| ip.addr())
        .unwrap_or(client_relay_addr);
    new_relay.add_address(&format!("{}/32", relay_addr))?;
    if !disable_v6 {
        if let Some(ipv6) = relay.addresses().iter().find(|net| net.addr().is_ipv6()) {
            new_relay.add_address(&format!("{}/128", ipv6.addr()))?;
        }
    }
    new_relay.add_peer(crate::peer::PeerConfig::from_args(relay_peer_args)?);

    let mut new_e2ee = Config::new()?;
    new_e2ee.set_port(51821)?;
    let e2ee_addrs = next_prefix_for_peers(e2ee.peers());
    let e2ee_addr = e2ee_addrs
        .first()
        .map(|ip| ip.addr())
        .unwrap_or(client_e2ee_addr);
    new_e2ee.add_address(&format!("{}/32", e2ee_addr))?;
    if !disable_v6 {
        if let Some(ipv6) = e2ee.addresses().iter().find(|net| net.addr().is_ipv6()) {
            new_e2ee.add_address(&format!("{}/128", ipv6.addr()))?;
        }
    }
    new_e2ee.add_peer(crate::peer::PeerConfig::from_args(e2ee_peer_args)?);

    Ok(AddClientPlan {
        relay_config: new_relay.as_file(),
        e2ee_config: new_e2ee.as_file(),
    })
}

pub fn build_add_client_plan_from_files(
    relay_path: &str,
    e2ee_path: &str,
    args: &AddClientArgs,
) -> Result<AddClientPlan> {
    let relay_contents = std::fs::read_to_string(relay_path)?;
    let e2ee_contents = std::fs::read_to_string(e2ee_path)?;
    build_add_client_plan(&relay_contents, &e2ee_contents, args)
}

pub fn build_add_server_plan(
    relay_contents: &str,
    e2ee_contents: &str,
    args: &AddServerArgs,
) -> Result<AddServerPlan> {
    let mut client_relay = parse_config(relay_contents)?;
    let mut client_e2ee = parse_config(e2ee_contents)?;

    if args.routes.is_empty() {
        return Err(anyhow!("routes required"));
    }
    if args.endpoint.is_empty() && args.outbound_endpoint.is_none() {
        return Err(anyhow!("endpoint required"));
    }

    let new_allowed = parse_routes(&args.routes)?;

    let relay_peers = client_relay.peers().to_vec();
    if relay_peers.is_empty() {
        return Err(anyhow!("cannot add server without relay peers"));
    }
    let relay_prefixes = next_prefix_for_peers(&relay_peers);
    if relay_prefixes.is_empty() {
        return Err(anyhow!("no relay prefixes available"));
    }

    let e2ee_peers = client_e2ee.peers().to_vec();
    let mut next_addrs = next_prefix_for_peers(&e2ee_peers);
    if next_addrs.is_empty() {
        return Err(anyhow!("no existing e2ee peers to base allocation on"));
    }

    let api_addr = next_addrs
        .pop()
        .ok_or_else(|| anyhow!("missing api allocation"))?;

    let mut server_relay = Config::new()?;
    let mut server_e2ee = Config::new()?;
    let port = match args.port {
        Some(port) => port,
        None => {
            if let Some(outbound) = &args.outbound_endpoint {
                port_from_endpoint(outbound)?
            } else if !args.endpoint.is_empty() {
                port_from_endpoint(&args.endpoint)?
            } else {
                constants::DEFAULT_PORT
            }
        }
    };
    server_relay.set_port(port)?;
    if let Some(localhost_ip) = &args.localhost_ip {
        server_relay.set_localhost_ip(localhost_ip)?;
    }

    let mut relay_address_strings = Vec::new();
    for prefix in &relay_prefixes {
        match prefix {
            IpNet::V4(net) => {
                let addr = constants::increment_v4(net.addr(), 2);
                relay_address_strings.push(format!("{}/32", addr));
            }
            IpNet::V6(net) => {
                if !args.disable_ipv6 {
                    let addr = constants::increment_v6(net.addr(), 2);
                    relay_address_strings.push(format!("{}/128", addr));
                }
            }
        }
    }
    if relay_address_strings.is_empty() {
        return Err(anyhow!("no relay addresses available"));
    }
    server_relay.set_addresses(&relay_address_strings)?;

    let relay_peer_endpoint = if !args.endpoint.is_empty() {
        Some(args.endpoint.clone())
    } else {
        None
    };
    let relay_peer_args = PeerConfigArgs {
        public_key: Some(client_relay.public_key().to_string()),
        endpoint: relay_peer_endpoint,
        allowed_ips: client_relay
            .peers()
            .first()
            .map(|peer| peer.allowed_ips().iter().map(|ip| ip.to_string()).collect())
            .unwrap_or_default(),
        ..Default::default()
    };

    server_relay.add_peer(crate::peer::PeerConfig::from_args(relay_peer_args)?);

    let e2ee_peer_args = PeerConfigArgs {
        public_key: Some(client_e2ee.public_key().to_string()),
        endpoint: Some(format!("{}:51821", client_relay.addresses()[0].addr())),
        ..Default::default()
    };
    server_e2ee.add_peer(crate::peer::PeerConfig::from_args(e2ee_peer_args)?);

    let server_api_addr = match api_addr {
        IpNet::V4(net) => IpAddr::V4(net.addr()),
        IpNet::V6(net) => IpAddr::V6(net.addr()),
    };
    if args.disable_ipv6 && server_api_addr.is_ipv6() {
        return Err(anyhow!(
            "api address requires ipv6 but --disable-ipv6 was set"
        ));
    }
    let server_api_cidr = match server_api_addr {
        IpAddr::V4(addr) => format!("{}/32", addr),
        IpAddr::V6(addr) => format!("{}/128", addr),
    };
    server_e2ee.add_address(&server_api_cidr)?;

    let mut relay_allowed = Vec::new();
    for prefix in relay_prefixes {
        match prefix {
            IpNet::V4(_) => relay_allowed.push(prefix.to_string()),
            IpNet::V6(_) => {
                if !args.disable_ipv6 {
                    relay_allowed.push(prefix.to_string());
                }
            }
        }
    }
    let mut client_relay_peer_args = PeerConfigArgs {
        public_key: Some(server_relay.public_key().to_string()),
        allowed_ips: relay_allowed,
        ..Default::default()
    };
    if let Some(outbound) = &args.outbound_endpoint {
        client_relay_peer_args.endpoint = Some(outbound.clone());
        client_relay_peer_args.persistent_keepalive = Some(args.keepalive);
    }
    client_relay.add_peer(crate::peer::PeerConfig::from_args(client_relay_peer_args)?);

    // Update client e2ee config with new peer
    let mut new_allowed_strs = new_allowed
        .iter()
        .map(|net| net.to_string())
        .collect::<Vec<_>>();
    new_allowed_strs.push(match server_api_addr {
        IpAddr::V4(addr) => format!("{}/32", addr),
        IpAddr::V6(addr) => format!("{}/128", addr),
    });

    let mut client_peer_args = PeerConfigArgs {
        public_key: Some(server_e2ee.public_key().to_string()),
        allowed_ips: new_allowed_strs,
        ..Default::default()
    };
    if let Some(nickname) = &args.nickname {
        client_peer_args.nickname = Some(nickname.clone());
    }
    client_e2ee.add_peer(crate::peer::PeerConfig::from_args(client_peer_args)?);

    let client_e2ee_update = client_e2ee.as_file();
    let client_relay_update = client_relay.as_file();
    let server_relay_config = create_server_file(&server_relay, &server_e2ee, false);
    let server_e2ee_config = server_e2ee.as_file();

    let server_command_posix = create_server_command(
        &server_relay,
        &server_e2ee,
        Shell::Posix,
        false,
        args.disable_ipv6,
    );
    let server_command_powershell = create_server_command(
        &server_relay,
        &server_e2ee,
        Shell::PowerShell,
        false,
        args.disable_ipv6,
    );

    Ok(AddServerPlan {
        client_relay_update,
        client_e2ee_update,
        server_relay_config,
        server_e2ee_config: format!("[E2EE.Interface]\n{}", server_e2ee_config),
        server_command_posix,
        server_command_powershell,
    })
}

pub fn build_add_client_plan_with_api(
    relay_contents: &str,
    e2ee_contents: &str,
    leaf_relay: &Config,
    allocation: &crate::transport::api::NetworkState,
    args: &AddClientApiArgs,
) -> Result<AddClientApiPlan> {
    if args.endpoint.is_none() && args.outbound_endpoint.is_none() {
        return Err(anyhow!("endpoint required"));
    }

    let base_relay = parse_config(relay_contents)?;
    let base_e2ee = parse_config(e2ee_contents)?;
    let disable_v6 = args.disable_ipv6 || base_e2ee.addresses().len() == 1;

    let port = match args.port {
        Some(port) => port,
        None => {
            if let Some(outbound) = &args.outbound_endpoint {
                port_from_endpoint(outbound)?
            } else if let Some(endpoint) = &args.endpoint {
                port_from_endpoint(endpoint)?
            } else {
                constants::DEFAULT_PORT
            }
        }
    };

    let mut client_relay = Config::new()?;
    client_relay.set_port(port)?;
    let mut relay_addrs = vec![format!("{}/32", allocation.next_client_relay_addr4)];
    if !disable_v6 {
        relay_addrs.push(format!("{}/128", allocation.next_client_relay_addr6));
    }
    client_relay.set_addresses(&relay_addrs)?;

    let mut client_e2ee = Config::new()?;
    client_e2ee.set_port(constants::DEFAULT_E2EE_PORT)?;
    let mut e2ee_addrs = vec![format!("{}/32", allocation.next_client_e2ee_addr4)];
    if !disable_v6 {
        e2ee_addrs.push(format!("{}/128", allocation.next_client_e2ee_addr6));
    }
    client_e2ee.set_addresses(&e2ee_addrs)?;

    let leaf_addr = leaf_relay
        .addresses()
        .first()
        .map(|net| net.addr())
        .ok_or_else(|| anyhow!("leaf relay config missing address"))?;

    let mut leaf_peer = leaf_relay.as_peer()?;
    let mut found = false;
    for peer in base_relay.peers() {
        if peer
            .allowed_ips()
            .iter()
            .any(|net| net.contains(&leaf_addr))
        {
            let allowed = peer
                .allowed_ips()
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>();
            leaf_peer.set_allowed_ips(&allowed)?;
            found = true;
            break;
        }
    }
    if !found {
        return Err(anyhow!("failed to copy routes from leaf server"));
    }
    if let Some(outbound) = &args.outbound_endpoint {
        leaf_peer.set_endpoint(outbound)?;
        leaf_peer.set_keepalive(args.keepalive)?;
    }
    client_relay.add_peer(leaf_peer);

    for peer in base_e2ee.peers() {
        client_e2ee.add_peer(peer.clone());
    }

    let relay_allowed = client_relay
        .addresses()
        .iter()
        .map(|net| net.to_string())
        .collect::<Vec<_>>();
    let mut relay_peer_args = PeerConfigArgs {
        public_key: Some(client_relay.public_key().to_string()),
        allowed_ips: relay_allowed,
        ..Default::default()
    };
    if args.outbound_endpoint.is_none() {
        if let Some(endpoint) = &args.endpoint {
            relay_peer_args.endpoint = Some(endpoint.clone());
        }
        relay_peer_args.persistent_keepalive = Some(args.keepalive);
    }
    let client_relay_peer = crate::peer::PeerConfig::from_args(relay_peer_args)?;

    let e2ee_allowed = client_e2ee
        .addresses()
        .iter()
        .map(|net| net.to_string())
        .collect::<Vec<_>>();
    let mut e2ee_peer_args = PeerConfigArgs {
        public_key: Some(client_e2ee.public_key().to_string()),
        allowed_ips: e2ee_allowed,
        ..Default::default()
    };
    if let Some(addr) = client_e2ee.addresses().first() {
        e2ee_peer_args.endpoint = Some(format!("{}:{}", addr.addr(), constants::DEFAULT_E2EE_PORT));
    }
    let client_e2ee_peer = crate::peer::PeerConfig::from_args(e2ee_peer_args)?;

    Ok(AddClientApiPlan {
        plan: AddClientPlan {
            relay_config: client_relay.as_file(),
            e2ee_config: client_e2ee.as_file(),
        },
        client_relay_peer,
        client_e2ee_peer,
        leaf_addr,
    })
}

pub fn build_add_server_plan_with_api(
    relay_contents: &str,
    e2ee_contents: &str,
    leaf_relay: &Config,
    allocation: &crate::transport::api::NetworkState,
    args: &AddServerArgs,
) -> Result<AddServerApiPlan> {
    let client_relay = parse_config(relay_contents)?;
    let mut client_e2ee = parse_config(e2ee_contents)?;

    if args.routes.is_empty() {
        return Err(anyhow!("routes required"));
    }

    let new_allowed = parse_routes(&args.routes)?;

    let port = match args.port {
        Some(port) => port,
        None => {
            if let Some(outbound) = &args.outbound_endpoint {
                port_from_endpoint(outbound)?
            } else if !args.endpoint.is_empty() {
                port_from_endpoint(&args.endpoint)?
            } else {
                constants::DEFAULT_PORT
            }
        }
    };

    let mut server_relay = Config::new()?;
    server_relay.set_port(port)?;
    if let Some(localhost_ip) = &args.localhost_ip {
        server_relay.set_localhost_ip(localhost_ip)?;
    }

    let mut relay_address_strings = Vec::new();
    relay_address_strings.push(format!("{}/32", allocation.next_server_relay_addr4));
    if !args.disable_ipv6 {
        relay_address_strings.push(format!("{}/128", allocation.next_server_relay_addr6));
    }
    server_relay.set_addresses(&relay_address_strings)?;

    let mut leaf_peer = leaf_relay.as_peer()?;
    let mut leaf_allowed = leaf_relay
        .peers()
        .iter()
        .flat_map(|peer| peer.allowed_ips().iter())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();
    leaf_allowed.extend(leaf_relay.addresses().iter().map(|ip| ip.to_string()));
    leaf_peer.set_allowed_ips(&leaf_allowed)?;
    if !args.endpoint.is_empty() {
        leaf_peer.set_endpoint(&args.endpoint)?;
    }
    server_relay.add_peer(leaf_peer);

    let mut server_e2ee = Config::new()?;
    let api_addr = allocation.api_addr;
    if args.disable_ipv6 && api_addr.is_ipv6() {
        return Err(anyhow!(
            "api address requires ipv6 but --disable-ipv6 was set"
        ));
    }
    let api_cidr = match api_addr {
        IpAddr::V4(addr) => format!("{}/32", addr),
        IpAddr::V6(addr) => format!("{}/128", addr),
    };
    server_e2ee.add_address(&api_cidr)?;

    let mut client_peer_e2ee = client_e2ee.as_peer()?;
    if !args.endpoint.is_empty() {
        let relay_addr = client_relay
            .addresses()
            .first()
            .ok_or_else(|| anyhow!("missing relay interface address"))?
            .addr();
        client_peer_e2ee.set_endpoint(&format!(
            "{}:{}",
            relay_addr,
            constants::DEFAULT_E2EE_PORT
        ))?;
    }
    server_e2ee.add_peer(client_peer_e2ee);

    let mut new_allowed_strs = new_allowed
        .iter()
        .map(|net| net.to_string())
        .collect::<Vec<_>>();
    new_allowed_strs.push(api_cidr);

    let mut client_peer_args = PeerConfigArgs {
        public_key: Some(server_e2ee.public_key().to_string()),
        allowed_ips: new_allowed_strs,
        endpoint: Some(format!(
            "{}:{}",
            allocation.next_server_relay_addr4,
            constants::DEFAULT_E2EE_PORT
        )),
        ..Default::default()
    };
    if let Some(nickname) = &args.nickname {
        client_peer_args.nickname = Some(nickname.clone());
    }
    client_e2ee.add_peer(crate::peer::PeerConfig::from_args(client_peer_args)?);

    let mut server_relay_peer_args = PeerConfigArgs {
        public_key: Some(server_relay.public_key().to_string()),
        allowed_ips: relay_address_strings.clone(),
        endpoint: args.outbound_endpoint.clone(),
        ..Default::default()
    };
    if args.outbound_endpoint.is_some() {
        server_relay_peer_args.persistent_keepalive = Some(args.keepalive);
    }
    let server_relay_peer = crate::peer::PeerConfig::from_args(server_relay_peer_args)?;

    let client_e2ee_update = client_e2ee.as_file();
    let client_relay_update = client_relay.as_file();
    let server_relay_config = create_server_file(&server_relay, &server_e2ee, false);
    let server_e2ee_config = server_e2ee.as_file();
    let server_command_posix = create_server_command(
        &server_relay,
        &server_e2ee,
        Shell::Posix,
        false,
        args.disable_ipv6,
    );
    let server_command_powershell = create_server_command(
        &server_relay,
        &server_e2ee,
        Shell::PowerShell,
        false,
        args.disable_ipv6,
    );

    Ok(AddServerApiPlan {
        plan: AddServerPlan {
            client_relay_update,
            client_e2ee_update,
            server_relay_config,
            server_e2ee_config: format!("[E2EE.Interface]\n{}", server_e2ee_config),
            server_command_posix,
            server_command_powershell,
        },
        server_relay_peer,
    })
}

pub fn build_add_server_plan_from_files(
    relay_path: &str,
    e2ee_path: &str,
    args: &AddServerArgs,
) -> Result<AddServerPlan> {
    let relay_contents = std::fs::read_to_string(relay_path)?;
    let e2ee_contents = std::fs::read_to_string(e2ee_path)?;
    build_add_server_plan(&relay_contents, &e2ee_contents, args)
}

pub fn resolve_server_address(e2ee_contents: &str, server_address: &str) -> Result<IpAddr> {
    if let Ok(addr) = server_address.parse::<IpAddr>() {
        return Ok(addr);
    }

    let config = parse_config(e2ee_contents)?;
    let matches = config
        .peers()
        .iter()
        .filter(|peer| peer.nickname() == Some(server_address))
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(anyhow!(
            "there are multiple servers with the nickname {}",
            server_address
        ));
    }
    let peer = matches
        .first()
        .ok_or_else(|| anyhow!("server nickname not found"))?;
    peer.api_addr()
        .ok_or_else(|| anyhow!("server api address missing"))
}

fn port_from_endpoint(endpoint: &str) -> Result<u16> {
    if let Ok(addr) = SocketAddr::from_str(endpoint) {
        return Ok(addr.port());
    }

    if endpoint.starts_with('[') {
        if let Some(end) = endpoint.find(']') {
            let rest = &endpoint[end + 1..];
            let port = rest.trim_start_matches(':').parse::<u16>()?;
            return Ok(port);
        }
    }

    let parts: Vec<&str> = endpoint.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("invalid endpoint"));
    }
    Ok(parts[0].parse::<u16>()?)
}

fn parse_routes(routes: &[String]) -> Result<Vec<IpNet>> {
    let mut parsed = Vec::new();
    for route in routes {
        let trimmed = route.trim();
        if trimmed.is_empty() {
            continue;
        }
        parsed.push(IpNet::from_str(trimmed)?);
    }
    if parsed.is_empty() {
        return Err(anyhow!("routes required"));
    }
    Ok(parsed)
}
