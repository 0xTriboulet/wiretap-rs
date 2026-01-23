use std::str::FromStr;
use wiretap_rs::transport::TransportProtocol;

#[test]
fn transport_protocol_from_str() {
    assert_eq!(
        TransportProtocol::from_str("tcp").unwrap(),
        TransportProtocol::Tcp
    );
    assert_eq!(
        TransportProtocol::from_str("udp").unwrap(),
        TransportProtocol::Udp
    );
    assert_eq!(
        TransportProtocol::from_str("icmp").unwrap(),
        TransportProtocol::Icmp
    );
    assert!(TransportProtocol::from_str("sctp").is_err());
}
