use std::collections::HashMap;
use wiretap_rs::serve::delete_config_file;
use wiretap_rs::serve::{ServeOptions, ServerEnv, apply_serve_options, load_server_config};

#[test]
fn load_server_config_prefers_file() {
    let file_contents = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = example.com:51820\n";

    let config = load_server_config(Some(file_contents), &ServerEnv::default())
        .expect("load config from file");
    assert_eq!(config.relay.addresses().len(), 1);
    assert_eq!(config.relay.port(), Some(51820));
}

#[test]
fn load_server_config_uses_env_without_file() {
    let mut env = HashMap::new();
    env.insert(
        "WIRETAP_RELAY_INTERFACE_PRIVATEKEY".to_string(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_INTERFACE_IPV4".to_string(),
        "172.17.0.2".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_INTERFACE_PORT".to_string(),
        "51820".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_PEER_PUBLICKEY".to_string(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_PEER_ALLOWED".to_string(),
        "172.16.0.0/16".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_PEER_ENDPOINT".to_string(),
        "example.com:51820".to_string(),
    );

    let config = load_server_config(None, &ServerEnv::from(env)).expect("load config from env");
    assert_eq!(config.relay.addresses().len(), 1);
    assert_eq!(config.relay.port(), Some(51820));
    assert_eq!(config.relay.peers().len(), 1);
}

#[test]
fn load_server_config_applies_env_overrides() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = example.com:51820\n";

    let mut env = HashMap::new();
    env.insert(
        "WIRETAP_RELAY_INTERFACE_IPV4".to_string(),
        "172.17.0.9".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_PEER_ALLOWED".to_string(),
        "10.0.0.0/8".to_string(),
    );

    let config = load_server_config(Some(input), &ServerEnv::from(env)).expect("load config");
    assert_eq!(config.relay.addresses()[0].addr().to_string(), "172.17.0.9");
    assert_eq!(
        config.relay.peers()[0].allowed_ips()[0].to_string(),
        "10.0.0.0/8"
    );
}

#[test]
fn load_server_config_env_with_e2ee() {
    let mut env = HashMap::new();
    env.insert(
        "WIRETAP_RELAY_INTERFACE_PRIVATEKEY".to_string(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_INTERFACE_IPV4".to_string(),
        "172.17.0.2".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_INTERFACE_PORT".to_string(),
        "51820".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_PEER_PUBLICKEY".to_string(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string(),
    );
    env.insert(
        "WIRETAP_RELAY_PEER_ALLOWED".to_string(),
        "172.16.0.0/16".to_string(),
    );

    env.insert(
        "WIRETAP_E2EE_INTERFACE_PRIVATEKEY".to_string(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string(),
    );
    env.insert("WIRETAP_E2EE_INTERFACE_API".to_string(), "::2".to_string());
    env.insert(
        "WIRETAP_E2EE_PEER_PUBLICKEY".to_string(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string(),
    );
    env.insert(
        "WIRETAP_E2EE_PEER_ENDPOINT".to_string(),
        "172.16.0.1:51821".to_string(),
    );

    let config = load_server_config(None, &ServerEnv::from(env)).expect("load config from env");
    assert!(config.e2ee.is_some());
    let e2ee = config.e2ee.unwrap();
    assert_eq!(e2ee.addresses().len(), 1);
    assert_eq!(e2ee.peers().len(), 1);
}

#[test]
fn apply_serve_options_strips_ipv6() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
IPv6 = fd:17::2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16,fd:16::/40\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
\n\
[E2EE.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Api = ::2\n\
\n\
[E2EE.Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 172.16.0.1:51821\n";

    let config = load_server_config(Some(input), &ServerEnv::default()).expect("load config");
    let filtered = apply_serve_options(
        config,
        ServeOptions {
            simple: false,
            quiet: false,
            api_addr: None,
            api_port: wiretap_rs::constants::API_PORT,
            disable_ipv6: true,
            delete_config: false,
            ..ServeOptions::default()
        },
    )
    .expect("apply options");

    assert_eq!(filtered.relay.addresses().len(), 1);
    assert!(filtered.relay.addresses()[0].addr().is_ipv4());
    assert_eq!(filtered.relay.peers().len(), 1);
    assert_eq!(filtered.relay.peers()[0].allowed_ips().len(), 1);
    assert!(filtered.relay.peers()[0].allowed_ips()[0].addr().is_ipv4());
    assert!(filtered.e2ee.is_some());
    let e2ee = filtered.e2ee.unwrap();
    assert_eq!(e2ee.addresses().len(), 1);
    assert!(e2ee.addresses()[0].addr().is_ipv4());
}

#[test]
fn apply_serve_options_deletes_config_file() {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("wiretap_server_test.conf");
    std::fs::write(&path, "test").expect("write temp config");

    delete_config_file(path.to_str().expect("path string")).expect("delete config");
    assert!(!path.exists());
}

#[test]
fn apply_serve_options_drops_e2ee_without_peer() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
\n\
[E2EE.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Api = ::2\n";

    let config = load_server_config(Some(input), &ServerEnv::default()).expect("load config");
    let filtered = apply_serve_options(config, ServeOptions::default()).expect("apply options");
    assert!(filtered.e2ee.is_none());
}

#[test]
fn apply_serve_options_simple_drops_e2ee() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
\n\
[E2EE.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Api = ::2\n\
\n\
[E2EE.Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 172.16.0.1:51821\n";

    let config = load_server_config(Some(input), &ServerEnv::default()).expect("load config");
    let filtered = apply_serve_options(
        config,
        ServeOptions {
            simple: true,
            quiet: false,
            ..ServeOptions::default()
        },
    )
    .expect("apply options");
    assert!(filtered.e2ee.is_none());
}

#[test]
fn apply_serve_options_propagates_keepalive_to_e2ee() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
\n\
[E2EE.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Api = ::2\n\
\n\
[E2EE.Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 172.16.0.1:51821\n";

    let config = load_server_config(Some(input), &ServerEnv::default()).expect("load config");
    let filtered = apply_serve_options(
        config,
        ServeOptions {
            quiet: false,
            wireguard_keepalive_secs: 42,
            ..ServeOptions::default()
        },
    )
    .expect("apply options");

    let relay_keepalive = filtered
        .relay
        .peers()
        .first()
        .and_then(|peer| peer.keepalive());
    assert_eq!(relay_keepalive, Some(42));

    let e2ee_keepalive = filtered
        .e2ee
        .as_ref()
        .and_then(|e2ee| e2ee.peers().first().and_then(|peer| peer.keepalive()));
    assert_eq!(e2ee_keepalive, Some(42));
}

#[test]
fn apply_serve_options_defaults_allowed_ips_when_missing() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
IPv6 = fd:17::2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 203.0.113.1:51820\n\
\n\
[E2EE.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Api = ::2\n\
\n\
[E2EE.Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 172.16.0.1:51821\n";

    let config = load_server_config(Some(input), &ServerEnv::default()).expect("load config");
    let filtered = apply_serve_options(config, ServeOptions::default()).expect("apply options");

    let relay_peer = &filtered.relay.peers()[0];
    assert!(relay_peer
        .allowed_ips()
        .iter()
        .any(|net| net.to_string() == "172.16.0.1/32"));
    assert!(relay_peer
        .allowed_ips()
        .iter()
        .any(|net| net.to_string() == "fd:16::1/128"));

    let e2ee = filtered.e2ee.expect("e2ee");
    let e2ee_peer = &e2ee.peers()[0];
    assert!(e2ee_peer
        .allowed_ips()
        .iter()
        .any(|net| net.to_string() == "172.19.0.1/32"));
    assert!(e2ee_peer
        .allowed_ips()
        .iter()
        .any(|net| net.to_string() == "fd:19::1/128"));
}

#[test]
fn apply_serve_options_adds_default_e2ee_addresses() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
\n\
[E2EE.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Api = ::2\n\
\n\
[E2EE.Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 172.16.0.1:51821\n";

    let config = load_server_config(Some(input), &ServerEnv::default()).expect("load config");
    let filtered = apply_serve_options(config, ServeOptions::default()).expect("apply options");
    let e2ee = filtered.e2ee.expect("e2ee");
    assert!(e2ee
        .addresses()
        .iter()
        .any(|net| net.to_string() == "172.18.0.2/32"));
    assert!(e2ee
        .addresses()
        .iter()
        .any(|net| net.to_string() == "fd:18::2/128"));
}

#[test]
fn server_env_parses_disable_ipv6_flag() {
    let mut values = HashMap::new();
    values.insert("WIRETAP_DISABLEIPV6".to_string(), "true".to_string());
    let env = ServerEnv::from(values);
    assert_eq!(env.get_bool("WIRETAP_DISABLEIPV6"), Some(true));

    let mut values = HashMap::new();
    values.insert("WIRETAP_DISABLEIPV6".to_string(), "0".to_string());
    let env = ServerEnv::from(values);
    assert_eq!(env.get_bool("WIRETAP_DISABLEIPV6"), Some(false));
}
