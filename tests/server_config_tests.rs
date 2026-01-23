use wiretap_rs::peer::parse_server_config;

#[test]
fn parse_server_config_reads_relay_and_e2ee() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
IPv6 = fd:17::2\n\
Port = 51820\n\
MTU = 1420\n\
LocalhostIP = 192.168.1.10\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16,fd:16::/40\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
PresharedKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = example.com:51820\n\
\n\
[E2EE.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Api = ::2\n\
\n\
[E2EE.Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 172.16.0.1:51821\n";

    let parsed = parse_server_config(input).expect("parse server config");
    assert_eq!(parsed.relay.addresses().len(), 2);
    assert_eq!(parsed.relay.peers().len(), 1);
    assert_eq!(parsed.relay.port(), Some(51820));
    assert_eq!(parsed.relay.mtu(), Some(1420));
    assert!(parsed.relay.preshared_key().is_none());
    assert!(parsed.relay.peers()[0].preshared_key().is_some());
    assert_eq!(
        parsed.relay.localhost_ip().unwrap().to_string(),
        "192.168.1.10"
    );
    assert!(parsed.e2ee.is_some());
}

#[test]
fn parse_server_config_allows_relay_only() {
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

    let parsed = parse_server_config(input).expect("parse relay-only server config");
    assert_eq!(parsed.relay.addresses().len(), 1);
    assert_eq!(parsed.relay.peers().len(), 1);
    assert!(parsed.e2ee.is_none());
}

#[test]
fn parse_server_config_ignores_trailing_comment_block() {
    let input = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 172.16.0.0/16\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = example.com:51820\n\
\n\
# POSIX Shell: WIRETAP_RELAY_INTERFACE_PRIVATEKEY=...\n\
# Powershell: $env:WIRETAP_RELAY_INTERFACE_PRIVATEKEY=...\n";

    let parsed = parse_server_config(input).expect("parse server config");
    assert_eq!(parsed.relay.addresses().len(), 1);
    assert_eq!(parsed.relay.peers().len(), 1);
    assert!(parsed.e2ee.is_none());
}
