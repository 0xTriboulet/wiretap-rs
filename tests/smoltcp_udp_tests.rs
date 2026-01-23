use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use wiretap_rs::transport::packet::{
    build_ipv4_header, build_udp_header, parse_ip_packet, udp_checksum_ipv4,
};
use wiretap_rs::transport::smoltcp::SmoltcpTcpProxy;

fn build_ipv4_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let src_ip = match src.ip() {
        IpAddr::V4(ip) => ip,
        _ => panic!("ipv4 only"),
    };
    let dst_ip = match dst.ip() {
        IpAddr::V4(ip) => ip,
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

fn parse_udp_ports(packet: &[u8], header_len: usize) -> (u16, u16) {
    let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
    let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    (src_port, dst_port)
}

fn collect_udp_responses(proxy: &mut SmoltcpTcpProxy, attempts: usize) -> Vec<Vec<u8>> {
    let mut responses = Vec::new();
    for _ in 0..attempts {
        if proxy.poll().is_ok() {
            responses.extend(proxy.drain_outbound());
        }
        thread::sleep(Duration::from_millis(10));
    }
    responses
}

#[test]
fn smoltcp_udp_proxy_echo_roundtrip() {
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

    let mut proxy = SmoltcpTcpProxy::new(&[IpAddr::from([127, 0, 0, 1])], None).expect("proxy");
    let src: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let dst = addr;
    let packet = build_ipv4_udp_packet(src, dst, b"ping");

    let mut responses = proxy.handle_ip_packet(&packet).expect("handle");
    if responses.is_empty() {
        responses = collect_udp_responses(&mut proxy, 10);
    }
    assert!(!responses.is_empty());

    let response = &responses[0];
    let parsed = parse_ip_packet(response).expect("parse");
    assert_eq!(parsed.src, dst.ip());
    assert_eq!(parsed.dst, src.ip());
    assert_eq!(&response[response.len() - 4..], b"ping");
}

#[test]
fn smoltcp_udp_proxy_handles_multiple_sources() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp bind");
    let addr = socket.local_addr().expect("addr");

    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            if let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..n], peer);
            }
        }
    });

    let mut proxy = SmoltcpTcpProxy::new(&[IpAddr::from([127, 0, 0, 1])], None).expect("proxy");
    let src1: SocketAddr = "10.0.0.1:40001".parse().unwrap();
    let src2: SocketAddr = "10.0.0.2:40002".parse().unwrap();
    let packet1 = build_ipv4_udp_packet(src1, addr, b"one");
    let packet2 = build_ipv4_udp_packet(src2, addr, b"two");

    let mut responses = proxy.handle_ip_packet(&packet1).expect("handle1");
    responses.extend(proxy.handle_ip_packet(&packet2).expect("handle2"));
    for _ in 0..5 {
        if responses.len() >= 2 {
            break;
        }
        let extra = collect_udp_responses(&mut proxy, 10);
        responses.extend(extra);
    }

    let mut found = Vec::new();
    for response in responses {
        let parsed = parse_ip_packet(&response).expect("parse");
        if parsed.protocol != wiretap_rs::transport::TransportProtocol::Udp {
            continue;
        }
        let (src_port, dst_port) = parse_udp_ports(&response, parsed.header_len);
        let payload = &response[response.len() - 3..];
        found.push((src_port, dst_port, payload.to_vec()));
    }

    assert!(found.iter().any(|(src, dst, payload)| *src == addr.port()
        && *dst == src1.port()
        && payload == b"one"));
    assert!(found.iter().any(|(src, dst, payload)| *src == addr.port()
        && *dst == src2.port()
        && payload == b"two"));
}
