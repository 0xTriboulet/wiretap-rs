use wiretap_rs::add::{AddServerArgs, build_add_server_plan_with_api, resolve_server_address};
use wiretap_rs::peer::parse_config;
use wiretap_rs::transport::api::NetworkState;

#[test]
fn add_server_plan_with_api_allocates_addresses_and_sets_endpoints() {
    let relay = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.16.0.1/32\n\
Address = fd:16::1/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.17.0.0/24,fd:17::/48\n";

    let e2ee = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n\
Address = fd:19::1/128\n\
\n\
[Peer]\n\
#@ Nickname = leaf\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let leaf_relay = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.17.0.2/32\n\
Address = fd:17::2/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.16.0.0/16,fd:16::/40\n";

    let allocation = NetworkState {
        next_client_relay_addr4: "172.16.0.2".parse().expect("client relay v4"),
        next_client_relay_addr6: "fd:16::2".parse().expect("client relay v6"),
        next_server_relay_addr4: "172.17.0.3".parse().expect("relay v4"),
        next_server_relay_addr6: "fd:17::3".parse().expect("relay v6"),
        next_client_e2ee_addr4: "172.19.0.2".parse().expect("client e2ee v4"),
        next_client_e2ee_addr6: "fd:19::2".parse().expect("client e2ee v6"),
        next_server_e2ee_addr4: "172.18.0.3".parse().expect("e2ee v4"),
        next_server_e2ee_addr6: "fd:18::3".parse().expect("e2ee v6"),
        api_addr: "::3".parse().expect("api addr"),
        server_relay_subnet4: "172.17.0.0".parse().expect("relay subnet v4"),
        server_relay_subnet6: "fd:17::".parse().expect("relay subnet v6"),
    };

    let args = AddServerArgs {
        endpoint: "10.0.0.2:51820".to_string(),
        routes: vec!["10.0.1.0/24".to_string()],
        outbound_endpoint: None,
        port: None,
        keepalive: 25,
        server_address: Some("::2".to_string()),
        localhost_ip: None,
        nickname: Some("new".to_string()),
        disable_ipv6: false,
    };

    let leaf_relay = parse_config(leaf_relay).expect("leaf relay config");
    let plan =
        build_add_server_plan_with_api(relay, e2ee, &leaf_relay, &allocation, &args).expect("plan");

    assert!(plan.plan.client_e2ee_update.contains("10.0.1.0/24"));
    assert!(plan.plan.client_e2ee_update.contains("::3/128"));
    assert!(
        plan.plan
            .client_e2ee_update
            .contains("Endpoint = 172.17.0.3:51821")
    );
    assert!(plan.plan.server_relay_config.contains("IPv4 = 172.17.0.3"));
    assert!(plan.plan.server_relay_config.contains("IPv6 = fd:17::3"));
    assert!(
        plan.plan
            .server_relay_config
            .contains("Endpoint = 10.0.0.2:51820")
    );
}

#[test]
fn resolve_server_address_prefers_ip_or_unique_nickname() {
    let e2ee = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n\
Address = fd:19::1/128\n\
\n\
[Peer]\n\
#@ Nickname = alpha\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n\
\n\
[Peer]\n\
#@ Nickname = beta\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.1.0/24,::3/128\n";

    let ip = resolve_server_address(e2ee, "::4").expect("ip");
    assert_eq!(ip, "::4".parse::<std::net::IpAddr>().expect("ip addr"));

    let nick = resolve_server_address(e2ee, "beta").expect("nickname");
    assert_eq!(nick, "::3".parse::<std::net::IpAddr>().expect("api addr"));
}

#[test]
fn resolve_server_address_rejects_duplicate_nickname() {
    let e2ee = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n\
Address = fd:19::1/128\n\
\n\
[Peer]\n\
#@ Nickname = dup\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n\
\n\
[Peer]\n\
#@ Nickname = dup\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.1.0/24,::3/128\n";

    let err = resolve_server_address(e2ee, "dup").expect_err("duplicate");
    assert!(err.to_string().contains("multiple servers"));
}

#[test]
fn add_server_plan_with_api_uses_outbound_endpoint_for_relay_peer() {
    let relay = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.16.0.1/32\n\
Address = fd:16::1/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.17.0.0/24,fd:17::/48\n";

    let e2ee = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n\
Address = fd:19::1/128\n\
\n\
[Peer]\n\
#@ Nickname = leaf\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let leaf_relay = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.17.0.2/32\n\
Address = fd:17::2/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.16.0.0/16,fd:16::/40\n";

    let allocation = NetworkState {
        next_client_relay_addr4: "172.16.0.2".parse().expect("client relay v4"),
        next_client_relay_addr6: "fd:16::2".parse().expect("client relay v6"),
        next_server_relay_addr4: "172.17.0.3".parse().expect("relay v4"),
        next_server_relay_addr6: "fd:17::3".parse().expect("relay v6"),
        next_client_e2ee_addr4: "172.19.0.2".parse().expect("client e2ee v4"),
        next_client_e2ee_addr6: "fd:19::2".parse().expect("client e2ee v6"),
        next_server_e2ee_addr4: "172.18.0.3".parse().expect("e2ee v4"),
        next_server_e2ee_addr6: "fd:18::3".parse().expect("e2ee v6"),
        api_addr: "::3".parse().expect("api addr"),
        server_relay_subnet4: "172.17.0.0".parse().expect("relay subnet v4"),
        server_relay_subnet6: "fd:17::".parse().expect("relay subnet v6"),
    };

    let args = AddServerArgs {
        endpoint: String::new(),
        routes: vec!["10.0.1.0/24".to_string()],
        outbound_endpoint: Some("10.0.0.9:60000".to_string()),
        port: None,
        keepalive: 25,
        server_address: Some("::2".to_string()),
        localhost_ip: None,
        nickname: None,
        disable_ipv6: false,
    };

    let leaf_relay = parse_config(leaf_relay).expect("leaf relay config");
    let plan =
        build_add_server_plan_with_api(relay, e2ee, &leaf_relay, &allocation, &args).expect("plan");

    assert!(plan.plan.server_relay_config.contains("Port = 60000"));
    assert_eq!(
        plan.server_relay_peer.endpoint().unwrap().to_string(),
        "10.0.0.9:60000"
    );
    assert_eq!(plan.server_relay_peer.keepalive(), Some(25));
}

#[test]
fn add_server_plan_with_api_rejects_ipv6_api_when_disabled() {
    let relay = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.16.0.1/32\n\
Address = fd:16::1/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.17.0.0/24,fd:17::/48\n";

    let e2ee = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n\
Address = fd:19::1/128\n\
\n\
[Peer]\n\
#@ Nickname = leaf\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let leaf_relay = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.17.0.2/32\n\
Address = fd:17::2/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.16.0.0/16,fd:16::/40\n";

    let allocation = NetworkState {
        next_client_relay_addr4: "172.16.0.2".parse().expect("client relay v4"),
        next_client_relay_addr6: "fd:16::2".parse().expect("client relay v6"),
        next_server_relay_addr4: "172.17.0.3".parse().expect("relay v4"),
        next_server_relay_addr6: "fd:17::3".parse().expect("relay v6"),
        next_client_e2ee_addr4: "172.19.0.2".parse().expect("client e2ee v4"),
        next_client_e2ee_addr6: "fd:19::2".parse().expect("client e2ee v6"),
        next_server_e2ee_addr4: "172.18.0.3".parse().expect("e2ee v4"),
        next_server_e2ee_addr6: "fd:18::3".parse().expect("e2ee v6"),
        api_addr: "::3".parse().expect("api addr"),
        server_relay_subnet4: "172.17.0.0".parse().expect("relay subnet v4"),
        server_relay_subnet6: "fd:17::".parse().expect("relay subnet v6"),
    };

    let args = AddServerArgs {
        endpoint: "10.0.0.2:51820".to_string(),
        routes: vec!["10.0.1.0/24".to_string()],
        outbound_endpoint: None,
        port: None,
        keepalive: 25,
        server_address: Some("::2".to_string()),
        localhost_ip: None,
        nickname: None,
        disable_ipv6: true,
    };

    let leaf_relay = parse_config(leaf_relay).expect("leaf relay config");
    let err = build_add_server_plan_with_api(relay, e2ee, &leaf_relay, &allocation, &args)
        .expect_err("should reject ipv6");
    assert!(err.to_string().contains("disable-ipv6"));
}
