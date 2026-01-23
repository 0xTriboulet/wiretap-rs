use std::net::IpAddr;
use wiretap_rs::transport::TransportProtocol;
use wiretap_rs::transport::packet::{
    build_ipv4_header, build_tcp_header, build_udp_packet, parse_ip_packet, parse_tcp_header,
    parse_udp_packet, tcp_checksum_ipv4,
};
use wiretap_rs::transport::smoltcp::SmoltcpTcpProxy;

#[test]
fn udp_packet_roundtrip_extracts_payload() {
    let payload = b"hello-world";
    let src = IpAddr::from([10, 0, 0, 1]);
    let dst = IpAddr::from([10, 0, 0, 2]);
    let src_port = 51821;
    let dst_port = 51821;

    let packet = build_udp_packet(src, dst, src_port, dst_port, payload).expect("udp packet");
    let parsed = parse_ip_packet(&packet).expect("ip");
    assert_eq!(parsed.protocol, TransportProtocol::Udp);
    let udp = parse_udp_packet(&packet, parsed.header_len).expect("udp");
    assert_eq!(udp.src_port, src_port);
    assert_eq!(udp.dst_port, dst_port);
    let extracted = &packet[udp.payload_offset..udp.payload_offset + udp.payload_len];
    assert_eq!(extracted, payload);
}

#[test]
fn relay_wrapped_packet_reaches_smoltcp() {
    let mut proxy = SmoltcpTcpProxy::new(&[IpAddr::from([10, 0, 0, 2])], None).expect("proxy");

    let src_ip = [10, 0, 0, 1].into();
    let dst_ip = [10, 0, 0, 2].into();
    let src_port = 50000;
    let dst_port = 80;
    let flags = 0x02;
    let tcp_header = build_tcp_header(src_port, dst_port, flags, 64240, 0);
    let mut segment = Vec::from(tcp_header);
    let checksum = tcp_checksum_ipv4(src_ip, dst_ip, &segment);
    let tcp_header = build_tcp_header(src_port, dst_port, flags, 64240, checksum);
    segment = Vec::from(tcp_header);

    let mut inner_packet = build_ipv4_header(src_ip, dst_ip, 6, segment.len());
    inner_packet.extend_from_slice(&segment);

    let outer = build_udp_packet(
        IpAddr::from([172, 17, 0, 2]),
        IpAddr::from([172, 17, 0, 3]),
        51821,
        51821,
        &inner_packet,
    )
    .expect("outer udp");

    let parsed = parse_ip_packet(&outer).expect("outer ip");
    let udp = parse_udp_packet(&outer, parsed.header_len).expect("outer udp");
    let wrapped = &outer[udp.payload_offset..udp.payload_offset + udp.payload_len];

    let outbound = proxy.handle_ip_packet(wrapped).expect("smoltcp");
    assert!(!outbound.is_empty());
    let response = &outbound[0];
    let parsed = parse_tcp_header(response, 20).expect("parse tcp");
    assert_eq!(parsed.src_port, dst_port);
    assert_eq!(parsed.dst_port, src_port);
    assert!(parsed.flags & 0x12 != 0);
}

#[test]
fn udp_packet_roundtrip_ipv6_extracts_payload() {
    let payload = b"v6-payload";
    let src = "fd00::1".parse::<IpAddr>().expect("src");
    let dst = "fd00::2".parse::<IpAddr>().expect("dst");
    let src_port = 51821;
    let dst_port = 51821;

    let packet = build_udp_packet(src, dst, src_port, dst_port, payload).expect("udp packet");
    let parsed = parse_ip_packet(&packet).expect("ip");
    assert_eq!(parsed.protocol, TransportProtocol::Udp);
    let udp = parse_udp_packet(&packet, parsed.header_len).expect("udp");
    assert_eq!(udp.src_port, src_port);
    assert_eq!(udp.dst_port, dst_port);
    let extracted = &packet[udp.payload_offset..udp.payload_offset + udp.payload_len];
    assert_eq!(extracted, payload);
}
