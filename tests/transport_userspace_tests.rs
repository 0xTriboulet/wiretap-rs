use ipnet::IpNet;
use std::net::IpAddr;
use wiretap_rs::peer::{PeerConfig, PeerConfigArgs};
use wiretap_rs::transport::userspace::{
    NullBind, Packet, PacketRouter, Route, UserspaceStack, WireguardPacket, packet_to_flow,
    parse_ip_header,
};
use wiretap_rs::transport::{FlowTuple, TransportProtocol};

#[test]
fn userspace_stack_boots() {
    let stack = UserspaceStack::new(NullBind::default()).expect("stack");
    assert!(stack.router().routes().is_empty());
}

#[test]
fn packet_router_selects_longest_prefix() {
    let mut router = PacketRouter::new();
    router.add_route(Route {
        destination: "10.0.0.0/8".parse::<IpNet>().unwrap(),
        next_hop: None,
        peer_endpoint: None,
    });
    router.add_route(Route {
        destination: "10.1.0.0/16".parse::<IpNet>().unwrap(),
        next_hop: None,
        peer_endpoint: None,
    });

    let dst = IpAddr::from([10, 1, 2, 3]);
    let route = router.route(dst).expect("route");
    assert_eq!(route.destination.prefix_len(), 16);
}

#[test]
fn packet_router_returns_none_for_miss() {
    let router = PacketRouter::new();
    let dst = IpAddr::from([192, 0, 2, 1]);
    assert!(router.route(dst).is_none());
}

#[test]
fn packet_struct_roundtrip() {
    let packet = Packet {
        flow: FlowTuple {
            src: "10.0.0.1:1000".parse().unwrap(),
            dst: "10.0.0.2:2000".parse().unwrap(),
        },
        protocol: TransportProtocol::Tcp,
        payload: vec![1, 2, 3],
    };

    assert_eq!(packet.payload.len(), 3);
}

#[test]
fn packet_router_loads_allowed_routes() {
    let mut router = PacketRouter::new();
    router
        .add_routes_from_allowed(&["10.0.0.0/24".to_string(), "10.1.0.0/16".to_string()])
        .expect("routes");
    assert_eq!(router.routes().len(), 2);
}

#[test]
fn parse_ipv4_header_reads_addresses() {
    let mut packet = vec![0u8; 40 + 20];
    packet[0] = 0x45;
    packet[9] = 6;
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 2;

    let header = parse_ip_header(&packet).expect("header");
    assert_eq!(header.protocol, TransportProtocol::Tcp);
    assert_eq!(header.src, IpAddr::from([10, 0, 0, 1]));
    assert_eq!(header.dst, IpAddr::from([10, 0, 0, 2]));
}

#[test]
fn parse_ipv6_header_reads_addresses() {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[6] = 17;
    packet[8] = 0xfd;
    packet[24] = 0xfd;
    packet[23] = 1;
    packet[39] = 2;

    let header = parse_ip_header(&packet).expect("header");
    assert_eq!(header.protocol, TransportProtocol::Udp);
    assert!(header.src.is_ipv6());
    assert!(header.dst.is_ipv6());
}

#[test]
fn packet_to_flow_sets_zero_ports() {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[9] = 1;
    packet[12] = 192;
    packet[13] = 0;
    packet[14] = 2;
    packet[15] = 1;
    packet[16] = 192;
    packet[17] = 0;
    packet[18] = 2;
    packet[19] = 2;

    let flow = packet_to_flow(&packet).expect("flow");
    assert_eq!(flow.src.port(), 0);
    assert_eq!(flow.dst.port(), 0);
}

#[test]
fn userspace_process_routes_packet() {
    let mut packet = vec![0u8; 40 + 20];
    packet[0] = 0x45;
    packet[9] = 1;
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 2;

    let bind = NullBind::with_packets(vec![WireguardPacket::from_bytes(packet)]);
    let mut stack = UserspaceStack::new(bind).expect("stack");
    stack
        .sync_routes_from_allowed(&["10.0.0.0/24".to_string()])
        .expect("routes");

    let route = stack.process_next().expect("next").expect("route");
    assert_eq!(route.destination.prefix_len(), 24);
}

#[test]
fn userspace_routes_packet_to_peer_endpoint() {
    let mut packet = vec![0u8; 40 + 20];
    packet[0] = 0x45;
    packet[9] = 6;
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 2;

    let mut args = PeerConfigArgs::default();
    args.public_key = Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string());
    args.allowed_ips = vec!["10.0.0.0/24".to_string()];
    args.endpoint = Some("203.0.113.1:51820".to_string());
    let peer = PeerConfig::from_args(args).expect("peer");

    let mut stack = UserspaceStack::new(NullBind::default()).expect("stack");
    stack.sync_routes_from_peers(&[peer]).expect("routes");

    let routed = stack.route_packet_to_peer(&packet).expect("routed");
    assert_eq!(
        routed.dst.expect("dst"),
        "203.0.113.1:51820".parse().unwrap()
    );
}

#[test]
fn userspace_send_packet_uses_peer_endpoint() {
    let mut packet = vec![0u8; 40 + 20];
    packet[0] = 0x45;
    packet[9] = 1;
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 2;

    let mut args = PeerConfigArgs::default();
    args.public_key = Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string());
    args.allowed_ips = vec!["10.0.0.0/24".to_string()];
    args.endpoint = Some("203.0.113.5:51820".to_string());
    let peer = PeerConfig::from_args(args).expect("peer");

    let bind = NullBind::default();
    let mut stack = UserspaceStack::new(bind).expect("stack");
    stack.sync_routes_from_peers(&[peer]).expect("routes");
    stack.send_packet(&packet).expect("send");

    let sent = stack.bind().sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].dst.expect("dst"),
        "203.0.113.5:51820".parse().unwrap()
    );
}
