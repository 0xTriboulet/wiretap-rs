use wiretap_rs::add::{AddClientApiArgs, build_add_client_plan_with_api};
use wiretap_rs::peer::parse_config;
use wiretap_rs::transport::api::NetworkState;

fn base_relay_config() -> &'static str {
    "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.16.0.1/32\n\
Address = fd:16::1/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.17.0.0/24,fd:17::/48\n"
}

fn base_e2ee_config() -> &'static str {
    "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n\
Address = fd:19::1/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n"
}

fn leaf_relay_config() -> &'static str {
    "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.17.0.2/32\n\
Address = fd:17::2/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 172.16.0.0/16,fd:16::/40\n"
}

fn allocation_state() -> NetworkState {
    NetworkState {
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
    }
}

#[test]
fn add_client_api_plan_sets_outbound_endpoint_and_keepalive() {
    let leaf = parse_config(leaf_relay_config()).expect("leaf relay");
    let plan = build_add_client_plan_with_api(
        base_relay_config(),
        base_e2ee_config(),
        &leaf,
        &allocation_state(),
        &AddClientApiArgs {
            endpoint: None,
            outbound_endpoint: Some("10.0.0.9:60000".to_string()),
            port: None,
            keepalive: 25,
            disable_ipv6: false,
        },
    )
    .expect("plan");

    assert!(plan.plan.relay_config.contains("Endpoint = 10.0.0.9:60000"));
    assert!(plan.plan.relay_config.contains("PersistentKeepalive = 25"));
    assert!(plan.client_relay_peer.endpoint().is_none());
    assert!(plan.client_relay_peer.keepalive().is_none());
}

#[test]
fn add_client_api_plan_sets_server_peer_on_inbound() {
    let leaf = parse_config(leaf_relay_config()).expect("leaf relay");
    let plan = build_add_client_plan_with_api(
        base_relay_config(),
        base_e2ee_config(),
        &leaf,
        &allocation_state(),
        &AddClientApiArgs {
            endpoint: Some("10.0.0.3:1337".to_string()),
            outbound_endpoint: None,
            port: None,
            keepalive: 25,
            disable_ipv6: false,
        },
    )
    .expect("plan");

    assert!(!plan.plan.relay_config.contains("Endpoint = 10.0.0.3:1337"));
    assert_eq!(
        plan.client_relay_peer.endpoint().unwrap().to_string(),
        "10.0.0.3:1337"
    );
    assert_eq!(plan.client_relay_peer.keepalive(), Some(25));
}
