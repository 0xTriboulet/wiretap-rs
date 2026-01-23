use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use wiretap_rs::transport::api::ExposeTuple;
use wiretap_rs::transport::packet::{parse_ip_packet, parse_tcp_header, parse_udp_packet};
use wiretap_rs::transport::smoltcp::SmoltcpTcpProxy;
use wiretap_rs::transport::TransportProtocol;

fn collect_outbound(proxy: &mut SmoltcpTcpProxy, attempts: usize) -> Vec<Vec<u8>> {
    let mut outbound = Vec::new();
    for _ in 0..attempts {
        let _ = proxy.poll();
        outbound.extend(proxy.drain_outbound());
        if !outbound.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    outbound
}

#[test]
fn smoltcp_host_tcp_bridge_emits_syn() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let client = TcpStream::connect(addr).expect("connect client");
    let (server_stream, _) = listener.accept().expect("accept stream");
    drop(listener);

    let mut proxy = SmoltcpTcpProxy::new(&[IpAddr::from([10, 0, 0, 2])], None).expect("proxy");
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
    proxy
        .register_host_tcp_bridge(server_stream, remote)
        .expect("register bridge");

    let outbound = collect_outbound(&mut proxy, 10);
    assert!(!outbound.is_empty());

    let mut found = false;
    for packet in outbound {
        let parsed = parse_ip_packet(&packet).expect("parse ip");
        if parsed.protocol != TransportProtocol::Tcp || parsed.dst != remote.ip() {
            continue;
        }
        let tcp = parse_tcp_header(&packet, parsed.header_len).expect("parse tcp");
        if tcp.dst_port == remote.port() && (tcp.flags & 0x02) != 0 {
            found = true;
            break;
        }
    }

    assert!(found, "expected outbound TCP SYN");
    drop(client);
}

#[test]
fn smoltcp_udp_expose_forwards_host_datagram() {
    let mut proxy = SmoltcpTcpProxy::new(&[IpAddr::from([10, 0, 0, 2])], None).expect("proxy");

    let remote_port = UdpSocket::bind("127.0.0.1:0")
        .expect("bind port")
        .local_addr()
        .expect("port")
        .port();

    let tuple = ExposeTuple {
        remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        local_port: 9000,
        remote_port,
        protocol: "udp".into(),
    };
    proxy.add_udp_expose(tuple).expect("add expose");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), remote_port);
    sender
        .send_to(b"hello", listen_addr)
        .expect("send datagram");

    let outbound = collect_outbound(&mut proxy, 20);
    assert!(!outbound.is_empty());

    let mut found = false;
    for packet in outbound {
        let parsed = parse_ip_packet(&packet).expect("parse ip");
        if parsed.protocol != TransportProtocol::Udp {
            continue;
        }
        let udp = parse_udp_packet(&packet, parsed.header_len).expect("parse udp");
        let payload = &packet[udp.payload_offset..udp.payload_offset + udp.payload_len];
        if parsed.dst == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
            && udp.dst_port == 9000
            && payload == b"hello"
        {
            found = true;
            break;
        }
    }

    assert!(found, "expected outbound UDP expose packet");
}
