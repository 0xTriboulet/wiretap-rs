use wiretap_rs::add::{
    AddClientArgs, AddServerArgs, build_add_client_plan_from_files,
    build_add_server_plan_from_files,
};

#[test]
fn add_server_plan_from_files_reads_configs() {
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

    let temp_dir = std::env::temp_dir();
    let relay_path = temp_dir.join("wiretap_add_server_relay.conf");
    let e2ee_path = temp_dir.join("wiretap_add_server_e2ee.conf");
    std::fs::write(&relay_path, relay).expect("write relay config");
    std::fs::write(&e2ee_path, e2ee).expect("write e2ee config");

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

    let plan = build_add_server_plan_from_files(
        relay_path.to_str().unwrap(),
        e2ee_path.to_str().unwrap(),
        &args,
    )
    .expect("plan");
    assert!(plan.client_e2ee_update.contains("10.0.1.0/24"));
    assert!(plan.server_relay_config.contains("[Relay.Interface]"));
}

#[test]
fn add_client_plan_from_files_reads_configs() {
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

    let temp_dir = std::env::temp_dir();
    let relay_path = temp_dir.join("wiretap_add_client_relay.conf");
    let e2ee_path = temp_dir.join("wiretap_add_client_e2ee.conf");
    std::fs::write(&relay_path, relay).expect("write relay config");
    std::fs::write(&e2ee_path, e2ee).expect("write e2ee config");

    let args = AddClientArgs {
        endpoint: "10.0.0.3:1337".to_string(),
        port: Some(1337),
        disable_ipv6: false,
    };

    let plan = build_add_client_plan_from_files(
        relay_path.to_str().unwrap(),
        e2ee_path.to_str().unwrap(),
        &args,
    )
    .expect("plan");
    assert!(plan.relay_config.contains("[Interface]"));
    assert!(plan.relay_config.contains("Endpoint = 10.0.0.3:1337"));
}
