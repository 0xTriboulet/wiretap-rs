use std::net::{IpAddr, SocketAddr};
use wiretap_rs::peer::Key;
use wiretap_rs::transport::packet::{
    build_ipv4_header, build_tcp_header, build_udp_packet, parse_ip_packet, parse_tcp_header,
    parse_udp_packet, tcp_checksum_ipv4,
};
use wiretap_rs::transport::smoltcp::SmoltcpTcpProxy;
use wiretap_rs::transport::wireguard::{MultiPeerSession, OutboundDatagram, PeerConfig};
use wiretap_rs::transport::TransportProtocol;

fn wrap_datagrams(
    datagrams: &[OutboundDatagram],
    relay_src: IpAddr,
    relay_dst: IpAddr,
    e2ee_port: u16,
) -> Vec<Vec<u8>> {
    datagrams
        .iter()
        .map(|datagram| {
            build_udp_packet(
                relay_src,
                relay_dst,
                e2ee_port,
                datagram.endpoint.port(),
                &datagram.bytes,
            )
            .expect("wrap udp")
        })
        .collect()
}

fn deliver_outer(
    session: &mut MultiPeerSession,
    packets: &[Vec<u8>],
    e2ee_port: u16,
) -> (Vec<Vec<u8>>, Vec<OutboundDatagram>) {
    let mut inbound = Vec::new();
    let mut outbound = Vec::new();
    for packet in packets {
        let parsed = parse_ip_packet(packet).expect("ip");
        if parsed.protocol != TransportProtocol::Udp {
            continue;
        }
        let udp = parse_udp_packet(packet, parsed.header_len).expect("udp");
        if udp.dst_port != e2ee_port {
            continue;
        }
        let payload = packet[udp.payload_offset..udp.payload_offset + udp.payload_len].to_vec();
        let src = SocketAddr::new(parsed.src, udp.src_port);
        let output = session.decapsulate_from(src, &payload).expect("decap");
        inbound.extend(output.packets);
        outbound.extend(output.datagrams);
    }
    (inbound, outbound)
}

#[test]
fn e2ee_over_relay_loop_returns_syn_ack() {
    let priv_client = Key::generate_private().expect("client key");
    let priv_server = Key::generate_private().expect("server key");
    let pub_client = priv_client.public_key();
    let pub_server = priv_server.public_key();

    let e2ee_port = 51821;
    let relay_src = IpAddr::from([172, 17, 0, 2]);
    let relay_dst = IpAddr::from([172, 17, 0, 3]);
    let client_endpoint = SocketAddr::new(relay_src, e2ee_port);
    let server_endpoint = SocketAddr::new(relay_dst, e2ee_port);

    let allowed = vec!["10.0.0.0/24".parse().unwrap()];
    let peer_client = PeerConfig {
        public_key: pub_server,
        preshared_key: None,
        keepalive: None,
        endpoint: Some(server_endpoint),
        allowed_ips: allowed.clone(),
    };
    let peer_server = PeerConfig {
        public_key: pub_client,
        preshared_key: None,
        keepalive: None,
        endpoint: Some(client_endpoint),
        allowed_ips: allowed,
    };

    let mut client = MultiPeerSession::new(&priv_client, vec![peer_client]).expect("client");
    let mut server = MultiPeerSession::new(&priv_server, vec![peer_server]).expect("server");
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

    let mut to_server = client.send_ip_packet(&inner_packet).expect("send");
    let mut received = None;

    for _ in 0..200 {
        let outer = wrap_datagrams(&to_server, relay_src, relay_dst, e2ee_port);
        let (server_packets, server_outbound) = deliver_outer(&mut server, &outer, e2ee_port);

        let mut to_client = server_outbound;
        for packet in server_packets {
            let outgoing = proxy.handle_ip_packet(&packet).expect("smoltcp");
            for out in outgoing {
                to_client.extend(server.send_ip_packet(&out).expect("reply"));
            }
        }
        proxy.poll().expect("poll");
        for out in proxy.drain_outbound() {
            to_client.extend(server.send_ip_packet(&out).expect("reply"));
        }

        let timers = server.update_timers().expect("timers");
        to_client.extend(timers.datagrams);

        let outer_back = wrap_datagrams(&to_client, relay_dst, relay_src, e2ee_port);
        let (client_packets, mut client_outbound) =
            deliver_outer(&mut client, &outer_back, e2ee_port);
        for packet in client_packets {
            let parsed = parse_ip_packet(&packet).expect("client ip");
            if parsed.protocol != TransportProtocol::Tcp {
                continue;
            }
            let tcp = parse_tcp_header(&packet, parsed.header_len).expect("client tcp");
            if tcp.src_port == dst_port && tcp.dst_port == src_port && (tcp.flags & 0x12 != 0) {
                received = Some(packet);
                break;
            }
        }
        if received.is_some() {
            break;
        }

        let timers = client.update_timers().expect("timers");
        client_outbound.extend(timers.datagrams);
        to_server = client_outbound;
    }

    assert!(received.is_some(), "expected SYN-ACK response");
}
