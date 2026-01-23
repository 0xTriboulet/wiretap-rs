use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;
use wiretap_rs::transport::icmp::handle_icmp_packet;
use wiretap_rs::transport::packet::{
    build_ipv4_header, build_tcp_header, build_udp_header, parse_ip_packet, tcp_checksum_ipv4,
    udp_checksum_ipv4,
};
use wiretap_rs::transport::tcp::handle_tcp_packet;
use wiretap_rs::transport::udp::handle_udp_packet;

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

fn build_ipv4_tcp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let src_ip = match src.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("ipv4 only"),
    };
    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("ipv4 only"),
    };
    let flags = 0x18u16;
    let tcp_header = build_tcp_header(src.port(), dst.port(), flags, 65535, 0);
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&tcp_header);
    segment.extend_from_slice(payload);
    let checksum = tcp_checksum_ipv4(src_ip, dst_ip, &segment);
    let tcp_header = build_tcp_header(src.port(), dst.port(), flags, 65535, checksum);

    let mut packet = build_ipv4_header(src_ip, dst_ip, 6, 20 + payload.len());
    packet.extend_from_slice(&tcp_header);
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn udp_handler_forwards_and_replies() {
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

    let response = handle_udp_packet(&packet).expect("udp").expect("response");
    let parsed = parse_ip_packet(&response).expect("parse");
    assert_eq!(parsed.src, dst.ip());
    assert_eq!(parsed.dst, src.ip());
    assert_eq!(&response[response.len() - 4..], b"ping");
}

#[test]
fn tcp_handler_forwards_and_replies() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("tcp bind");
    let addr = listener.local_addr().expect("addr");

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                let _ = stream.write_all(&buf[..n]);
            }
        }
    });

    let src: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let dst = addr;
    let packet = build_ipv4_tcp_packet(src, dst, b"hello");

    let response = handle_tcp_packet(&packet).expect("tcp").expect("response");
    let parsed = parse_ip_packet(&response).expect("parse");
    assert_eq!(parsed.src, dst.ip());
    assert_eq!(parsed.dst, src.ip());
    assert_eq!(&response[response.len() - 5..], b"hello");
}

#[test]
fn icmp_handler_replies_to_echo() {
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
        _ => Ipv4Addr::LOCALHOST,
    };
    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => Ipv4Addr::LOCALHOST,
    };
    let mut packet = build_ipv4_header(src_ip, dst_ip, 1, icmp.len());
    packet.extend_from_slice(&icmp);

    let response = handle_icmp_packet(&packet)
        .expect("icmp")
        .expect("response");
    assert_eq!(response[20], 0);
}
