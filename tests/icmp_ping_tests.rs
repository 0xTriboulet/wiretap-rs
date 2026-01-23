use std::net::SocketAddr;

use wiretap_rs::transport::icmp::{Ping, handle_icmp_packet_with_ping};
use wiretap_rs::transport::packet::build_ipv4_header;

struct AlwaysFailPing;

impl Ping for AlwaysFailPing {
    fn ping(&self, _dst: std::net::IpAddr) -> bool {
        false
    }
}

#[test]
fn icmp_ping_failure_suppresses_reply() {
    let src: SocketAddr = "10.0.0.1:0".parse().unwrap();
    let dst: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut icmp = vec![0u8; 8];
    icmp[0] = 8;
    icmp[4] = 0x12;
    icmp[5] = 0x34;
    icmp[6] = 0x00;
    icmp[7] = 0x01;
    let src_ip = match src.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("ipv4 only"),
    };
    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("ipv4 only"),
    };
    let mut packet = build_ipv4_header(src_ip, dst_ip, 1, icmp.len());
    packet.extend_from_slice(&icmp);

    let response = handle_icmp_packet_with_ping(&packet, &AlwaysFailPing).expect("icmp");
    assert!(response.is_none());
}
