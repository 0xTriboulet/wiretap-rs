use std::thread;
use std::time::Duration;
use wiretap_rs::peer::Key;
use wiretap_rs::transport::packet::build_ipv4_header;
use wiretap_rs::transport::wireguard::WireguardTunnel;

#[test]
fn wireguard_tunnel_encrypts_and_decrypts() {
    let priv_a = Key::generate_private().expect("priv a");
    let priv_b = Key::generate_private().expect("priv b");
    let pub_a = priv_a.public_key();
    let pub_b = priv_b.public_key();

    let mut a = WireguardTunnel::new(
        &priv_a,
        &pub_b,
        None,
        None,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:1".parse().unwrap(),
    )
    .expect("tunnel a");
    let mut b = WireguardTunnel::new(
        &priv_b,
        &pub_a,
        None,
        None,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:1".parse().unwrap(),
    )
    .expect("tunnel b");

    let addr_a = a.local_addr().expect("addr a");
    let addr_b = b.local_addr().expect("addr b");
    a.set_peer_addr(addr_b);
    b.set_peer_addr(addr_a);

    let payload = b"hello";
    let mut packet = build_ipv4_header(
        [10, 0, 0, 1].into(),
        [10, 0, 0, 2].into(),
        17,
        payload.len(),
    );
    packet.extend_from_slice(payload);

    a.send_ip_packet(&packet).expect("send");

    let mut received = None;
    for _ in 0..100 {
        let pkts = b.recv_packets().expect("recv b");
        if let Some(pkt) = pkts.into_iter().find(|p| p.ends_with(payload)) {
            received = Some(pkt);
            break;
        }

        let _ = a.recv_packets().expect("recv a");
        thread::sleep(Duration::from_millis(10));
    }

    let received = received.expect("packet");
    assert!(received.ends_with(payload));
}
