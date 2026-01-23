use std::net::IpAddr;
use wiretap_rs::transport::packet::{
    build_ipv4_header, build_tcp_header, parse_tcp_header, tcp_checksum_ipv4,
};
use wiretap_rs::transport::smoltcp::SmoltcpTcpProxy;

#[test]
fn smoltcp_tcp_proxy_responds_to_syn() {
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

    let mut packet = build_ipv4_header(src_ip, dst_ip, 6, segment.len());
    packet.extend_from_slice(&segment);

    let outbound = proxy.handle_ip_packet(&packet).expect("handle");
    assert!(!outbound.is_empty());

    let response = &outbound[0];
    let parsed = parse_tcp_header(response, 20).expect("parse tcp");
    assert_eq!(parsed.src_port, dst_port);
    assert_eq!(parsed.dst_port, src_port);
    assert!(parsed.flags & 0x12 != 0);
}

#[test]
fn smoltcp_tcp_proxy_accepts_bad_checksum() {
    let mut proxy = SmoltcpTcpProxy::new(&[IpAddr::from([10, 0, 0, 2])], None).expect("proxy");

    let src_ip = [10, 0, 0, 1].into();
    let dst_ip = [10, 0, 0, 2].into();
    let src_port = 50001;
    let dst_port = 80;
    let flags = 0x02;
    let tcp_header = build_tcp_header(src_port, dst_port, flags, 64240, 0);
    let segment = Vec::from(tcp_header);

    let mut packet = build_ipv4_header(src_ip, dst_ip, 6, segment.len());
    packet.extend_from_slice(&segment);

    let outbound = proxy.handle_ip_packet(&packet).expect("handle");
    assert!(!outbound.is_empty());
}
