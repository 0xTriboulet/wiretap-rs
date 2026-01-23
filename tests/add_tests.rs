use wiretap_rs::add::{AddServerArgs, build_add_server_plan};

#[test]
fn add_server_plan_allocates_new_server_addresses() {
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
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let args = AddServerArgs {
        endpoint: "10.0.0.2:51820".to_string(),
        routes: vec!["10.0.1.0/24".to_string()],
        outbound_endpoint: None,
        port: None,
        keepalive: 25,
        server_address: None,
        localhost_ip: None,
        nickname: None,
        disable_ipv6: false,
    };

    let plan = build_add_server_plan(relay, e2ee, &args).expect("plan");
    assert!(plan.client_e2ee_update.contains("10.0.1.0/24"));
    assert!(plan.client_relay_update.contains("172.17.1.0/24"));
    assert!(plan.server_relay_config.contains("[Relay.Interface]"));
    assert!(plan.server_relay_config.contains("IPv4 = 172.17.1.2"));
    assert!(plan.server_relay_config.contains("Port = 51820"));
    assert!(plan.server_e2ee_config.contains("[E2EE.Interface]"));
}

#[test]
fn add_server_plan_defaults_port_from_endpoint() {
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
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let args = AddServerArgs {
        endpoint: "10.0.0.2:42424".to_string(),
        routes: vec!["10.0.1.0/24".to_string()],
        outbound_endpoint: None,
        port: None,
        keepalive: 25,
        server_address: None,
        localhost_ip: None,
        nickname: None,
        disable_ipv6: false,
    };

    let plan = build_add_server_plan(relay, e2ee, &args).expect("plan");
    assert!(plan.server_relay_config.contains("Port = 42424"));
}

#[test]
fn add_server_plan_uses_outbound_endpoint_for_server_peer() {
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
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let args = AddServerArgs {
        endpoint: "".to_string(),
        routes: vec!["10.0.1.0/24".to_string()],
        outbound_endpoint: Some("10.0.0.9:60000".to_string()),
        port: None,
        keepalive: 25,
        server_address: None,
        localhost_ip: None,
        nickname: None,
        disable_ipv6: false,
    };

    let plan = build_add_server_plan(relay, e2ee, &args).expect("plan");
    assert!(
        !plan
            .server_command_posix
            .contains("WIRETAP_RELAY_PEER_ENDPOINT=10.0.0.9:60000")
    );
    assert!(plan.server_relay_config.contains("Port = 60000"));
    assert!(
        plan.client_relay_update
            .contains("Endpoint = 10.0.0.9:60000")
    );
    assert!(
        plan.client_relay_update
            .contains("PersistentKeepalive = 25")
    );
}

#[test]
fn add_server_plan_sets_localhost_ip() {
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
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let args = AddServerArgs {
        endpoint: "10.0.0.2:51820".to_string(),
        routes: vec!["10.0.1.0/24".to_string()],
        outbound_endpoint: None,
        port: None,
        keepalive: 25,
        server_address: None,
        localhost_ip: Some("192.168.137.137".to_string()),
        nickname: None,
        disable_ipv6: false,
    };

    let plan = build_add_server_plan(relay, e2ee, &args).expect("plan");
    assert!(
        plan.server_relay_config
            .contains("LocalhostIP = 192.168.137.137")
    );
}

#[test]
fn add_server_plan_ignores_empty_routes() {
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
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let args = AddServerArgs {
        endpoint: "10.0.0.2:51820".to_string(),
        routes: vec!["".to_string(), "10.0.1.0/24".to_string(), "  ".to_string()],
        outbound_endpoint: None,
        port: None,
        keepalive: 25,
        server_address: None,
        localhost_ip: None,
        nickname: None,
        disable_ipv6: false,
    };

    let plan = build_add_server_plan(relay, e2ee, &args).expect("plan");
    assert!(plan.client_e2ee_update.contains("10.0.1.0/24"));
}
