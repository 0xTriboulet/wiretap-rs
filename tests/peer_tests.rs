use wiretap_rs::peer::{create_server_command, PeerConfig, Shell};
use wiretap_rs::peer::{parse_config, Config, ConfigArgs, Key, PeerConfigArgs};

#[test]
fn key_parses_base64_and_hex() {
    let hex_key = "0000000000000000000000000000000000000000000000000000000000000000";
    let base64_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    let from_hex = Key::parse(hex_key).expect("hex key parses");
    let from_b64 = Key::parse(base64_key).expect("base64 key parses");

    assert_eq!(from_hex.to_string(), base64_key);
    assert_eq!(from_b64.to_string(), base64_key);
}

#[test]
fn config_serializes_with_peer_fields() {
    let private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let peer_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    let config = Config::from_args(ConfigArgs {
        private_key: Some(private_key.to_string()),
        listen_port: Some(51820),
        addresses: vec!["10.0.0.1/32".to_string()],
        peers: vec![PeerConfigArgs {
            public_key: Some(peer_key.to_string()),
            preshared_key: Some(peer_key.to_string()),
            endpoint: Some("example.com:51820".to_string()),
            allowed_ips: vec!["10.0.0.0/24".to_string()],
            nickname: Some("server".to_string()),
            persistent_keepalive: Some(25),
            ..Default::default()
        }],
        ..Default::default()
    })
    .expect("config builds");

    let text = config.as_file();
    assert!(text.contains("[Interface]"));
    assert!(text.contains("PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assert!(text.contains("Address = 10.0.0.1/32"));
    assert!(text.contains("ListenPort = 51820"));

    assert!(text.contains("[Peer]"));
    assert!(text.contains("#@ Nickname = server"));
    assert!(text.contains("PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assert!(text.contains("PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assert!(text.contains("AllowedIPs = 10.0.0.0/24"));
    assert!(text.contains("Endpoint = example.com:51820"));
    assert!(text.contains("PersistentKeepalive = 25"));
}

#[test]
fn parse_config_reads_nickname_and_endpoint() {
    let input = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 10.0.0.1/32\n\
ListenPort = 51820\n\
\n\
[Peer]\n\
#@ Nickname = server\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24\n\
Endpoint = example.com:51820\n\
PersistentKeepalive = 25\n";

    let config = parse_config(input).expect("parse config");
    assert_eq!(config.addresses().len(), 1);
    assert_eq!(config.peers().len(), 1);

    let peer = &config.peers()[0];
    assert_eq!(peer.nickname(), Some("server"));
    assert_eq!(peer.endpoint_dns(), Some("example.com:51820"));
    assert_eq!(peer.allowed_ips().len(), 1);
}

#[test]
fn server_command_prefers_first_relay_addresses() {
    let mut relay = Config::new().expect("relay config");
    relay.add_address("172.17.1.2/32").expect("relay v4");
    relay.add_address("192.0.2.10/32").expect("api v4");
    relay.add_address("fd:17::2/128").expect("relay v6");
    let args = PeerConfigArgs {
        public_key: Some(relay.public_key().to_string()),
        ..Default::default()
    };
    relay.add_peer(PeerConfig::from_args(args).expect("peer"));

    let mut e2ee = Config::new().expect("e2ee config");
    let e2ee_args = PeerConfigArgs {
        public_key: Some(e2ee.public_key().to_string()),
        ..Default::default()
    };
    e2ee.add_peer(PeerConfig::from_args(e2ee_args).expect("e2ee peer"));

    let cmd = create_server_command(&relay, &e2ee, Shell::Posix, true, false);
    assert!(cmd.contains("WIRETAP_RELAY_INTERFACE_IPV4=172.17.1.2"));
    assert!(cmd.contains("WIRETAP_RELAY_INTERFACE_IPV6=fd:17::2"));
}
