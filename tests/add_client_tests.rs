use wiretap_rs::add::{AddClientArgs, build_add_client_plan};

#[test]
fn add_client_plan_generates_new_configs() {
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

    let args = AddClientArgs {
        endpoint: "10.0.0.3:1337".to_string(),
        port: Some(1337),
        disable_ipv6: false,
    };

    let plan = build_add_client_plan(relay, e2ee, &args).expect("plan");
    assert!(plan.relay_config.contains("[Interface]"));
    assert!(plan.e2ee_config.contains("[Interface]"));
    assert!(plan.e2ee_config.contains("AllowedIPs"));
    assert!(plan.relay_config.contains("Endpoint = 10.0.0.3:1337"));
}

#[test]
fn add_client_plan_defaults_port_from_endpoint() {
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

    let args = AddClientArgs {
        endpoint: "10.0.0.3:1337".to_string(),
        port: None,
        disable_ipv6: false,
    };

    let plan = build_add_client_plan(relay, e2ee, &args).expect("plan");
    assert!(plan.relay_config.contains("ListenPort = 1337"));
}

#[test]
fn add_client_plan_strips_ipv6_when_disabled() {
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

    let args = AddClientArgs {
        endpoint: "10.0.0.3:1337".to_string(),
        port: None,
        disable_ipv6: true,
    };

    let plan = build_add_client_plan(relay, e2ee, &args).expect("plan");
    assert!(!plan.relay_config.contains("fd:"));
    assert!(!plan.e2ee_config.contains("::2/128"));
}

#[test]
fn add_client_plan_disables_ipv6_when_base_e2ee_is_ipv4_only() {
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
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n";

    let args = AddClientArgs {
        endpoint: "10.0.0.3:1337".to_string(),
        port: None,
        disable_ipv6: false,
    };

    let plan = build_add_client_plan(relay, e2ee, &args).expect("plan");
    assert!(!plan.relay_config.contains("fd:"));
    assert!(!plan.e2ee_config.contains("::2/128"));
}
