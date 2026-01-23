use std::net::SocketAddr;
use wiretap_rs::peer::Key;
use wiretap_rs::transport::packet::build_ipv4_header;
use wiretap_rs::transport::wireguard::{MultiPeerSession, OutboundDatagram, PeerConfig};

fn deliver(
    session: &mut MultiPeerSession,
    src: SocketAddr,
    datagrams: Vec<OutboundDatagram>,
) -> (Vec<Vec<u8>>, Vec<OutboundDatagram>) {
    let mut packets = Vec::new();
    let mut outbound = Vec::new();
    for datagram in datagrams {
        let output = session
            .decapsulate_from(src, &datagram.bytes)
            .expect("decapsulate");
        packets.extend(output.packets);
        outbound.extend(output.datagrams);
    }
    (packets, outbound)
}

#[test]
fn multip_peer_session_encrypts_and_decrypts() {
    let priv_a = Key::generate_private().expect("priv a");
    let priv_b = Key::generate_private().expect("priv b");
    let pub_a = priv_a.public_key();
    let pub_b = priv_b.public_key();

    let addr_a: SocketAddr = "127.0.0.1:41111".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:42222".parse().unwrap();

    let allowed = vec!["10.0.0.0/24".parse().unwrap()];
    let peer_a = PeerConfig {
        public_key: pub_b,
        preshared_key: None,
        keepalive: None,
        endpoint: Some(addr_b),
        allowed_ips: allowed.clone(),
    };
    let peer_b = PeerConfig {
        public_key: pub_a,
        preshared_key: None,
        keepalive: None,
        endpoint: Some(addr_a),
        allowed_ips: allowed,
    };

    let mut a = MultiPeerSession::new(&priv_a, vec![peer_a]).expect("session a");
    let mut b = MultiPeerSession::new(&priv_b, vec![peer_b]).expect("session b");

    let payload = b"hello-session";
    let mut packet = build_ipv4_header(
        [10, 0, 0, 1].into(),
        [10, 0, 0, 2].into(),
        17,
        payload.len(),
    );
    packet.extend_from_slice(payload);

    let mut to_b = a.send_ip_packet(&packet).expect("send");
    let mut to_a = Vec::new();
    let mut received = None;

    for _ in 0..100 {
        let (packets_b, outbound_a) = deliver(&mut b, addr_a, to_b);
        if let Some(pkt) = packets_b.into_iter().find(|p| p.ends_with(payload)) {
            received = Some(pkt);
            break;
        }
        to_a.extend(outbound_a);

        let (packets_a, outbound_b) = deliver(&mut a, addr_b, to_a);
        if let Some(pkt) = packets_a.into_iter().find(|p| p.ends_with(payload)) {
            received = Some(pkt);
            break;
        }
        to_b = outbound_b;

        let timers_a = a.update_timers().expect("timers a");
        to_b.extend(timers_a.datagrams);
        let timers_b = b.update_timers().expect("timers b");
        to_a = timers_b.datagrams;
    }

    assert!(received.is_some(), "expected decrypted payload");
}
