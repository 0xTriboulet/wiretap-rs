use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use wiretap_rs::transport::icmp::{build_icmpv6_port_unreachable, handle_icmp_packet};
use wiretap_rs::transport::packet::{
    build_ipv6_header, build_udp_header, icmpv6_checksum, parse_ip_packet, udp_checksum_ipv6,
};

fn build_ipv6_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let src_ip = match src.ip() {
        IpAddr::V6(ip) => ip,
        _ => panic!("ipv6 only"),
    };
    let dst_ip = match dst.ip() {
        IpAddr::V6(ip) => ip,
        _ => panic!("ipv6 only"),
    };

    let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), 0);
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&udp_header);
    segment.extend_from_slice(payload);
    let checksum = udp_checksum_ipv6(src_ip, dst_ip, &segment);
    let udp_header = build_udp_header(src.port(), dst.port(), payload.len(), checksum);

    let mut packet = build_ipv6_header(src_ip, dst_ip, 17, 8 + payload.len());
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn icmpv6_echo_reply_swaps_addresses() {
    let src: Ipv6Addr = "fd00::1".parse().unwrap();
    let dst: Ipv6Addr = "fd00::2".parse().unwrap();
    let mut icmp = vec![0u8; 8];
    icmp[0] = 128;
    icmp[4] = 0x12;
    icmp[5] = 0x34;
    icmp[6] = 0x00;
    icmp[7] = 0x01;
    let csum = icmpv6_checksum(src, dst, &icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut packet = build_ipv6_header(src, dst, 58, icmp.len());
    packet.extend_from_slice(&icmp);

    let response = handle_icmp_packet(&packet)
        .expect("icmp")
        .expect("response");
    let parsed = parse_ip_packet(&response).expect("parse");
    assert_eq!(parsed.src, IpAddr::V6(dst));
    assert_eq!(parsed.dst, IpAddr::V6(src));

    let icmp_offset = parsed.header_len;
    assert_eq!(response[icmp_offset], 129);
}

#[test]
fn icmpv6_unreachable_contains_original_header() {
    let src: SocketAddr = "[fd00::1]:1234".parse().unwrap();
    let dst: SocketAddr = "[fd00::2]:4321".parse().unwrap();
    let packet = build_ipv6_udp_packet(src, dst, b"data");

    let response = build_icmpv6_port_unreachable(&packet).expect("icmp unreachable");
    let parsed = parse_ip_packet(&response).expect("parse");
    assert_eq!(parsed.src, dst.ip());
    assert_eq!(parsed.dst, src.ip());

    let icmp_offset = parsed.header_len;
    assert_eq!(response[icmp_offset], 1);
    assert_eq!(response[icmp_offset + 1], 4);

    let original = parse_ip_packet(&packet).expect("parse original");
    let orig_len = original.header_len + 8;
    let embedded = &response[icmp_offset + 8..icmp_offset + 8 + orig_len];
    assert_eq!(embedded, &packet[..orig_len]);
}
