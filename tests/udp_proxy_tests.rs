use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use wiretap_rs::transport::icmp::build_icmpv4_port_unreachable;
use wiretap_rs::transport::packet::{
    build_ipv4_header, build_udp_header, parse_ip_packet, udp_checksum_ipv4,
};
use wiretap_rs::transport::udp::UdpProxy;

fn build_ipv4_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let src_ip = match src.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("ipv4 only"),
    };
    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("ipv4 only"),
    };
    let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), 0);
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&udp_header);
    segment.extend_from_slice(payload);
    let checksum = udp_checksum_ipv4(src_ip, dst_ip, &segment);
    let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), checksum);

    let mut packet = build_ipv4_header(src_ip, dst_ip, 17, 8 + payload.len());
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn udp_proxy_forwards_and_replies() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp bind");
    let addr = socket.local_addr().expect("addr");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");

    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        if let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], peer);
        }
    });

    let src: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let dst = addr;
    let packet = build_ipv4_udp_packet(src, dst, b"ping");

    let mut proxy = UdpProxy::new();
    let mut responses = proxy.handle_packet(&packet).expect("udp");
    for _ in 0..5 {
        if !responses.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
        responses = proxy.poll().expect("poll");
    }
    assert!(!responses.is_empty());

    let response = &responses[0];
    let parsed = parse_ip_packet(response).expect("parse");
    assert_eq!(parsed.src, dst.ip());
    assert_eq!(parsed.dst, src.ip());
    assert_eq!(&response[response.len() - 4..], b"ping");
}

#[test]
fn icmp_unreachable_includes_original_header() {
    let src: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "192.0.2.10:4321".parse().unwrap();
    let packet = build_ipv4_udp_packet(src, dst, b"data");

    let response = build_icmpv4_port_unreachable(&packet).expect("icmp unreachable");
    let parsed = parse_ip_packet(&response).expect("parse");
    assert_eq!(parsed.src, dst.ip());
    assert_eq!(parsed.dst, src.ip());

    let icmp_offset = parsed.header_len;
    assert_eq!(response[icmp_offset], 3);
    assert_eq!(response[icmp_offset + 1], 3);

    let original = parse_ip_packet(&packet).expect("parse original");
    let orig_len = original.header_len + 8;
    let embedded = &response[icmp_offset + 8..icmp_offset + 8 + orig_len];
    assert_eq!(embedded, &packet[..orig_len]);
}
