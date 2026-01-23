use std::net::SocketAddr;
use wiretap_rs::peer::parse_server_config;
use wiretap_rs::serve;
use wiretap_rs::transport::userspace::{NullBind, UserspaceStack, WireguardPacket};

#[test]
fn serve_run_once_processes_packet() {
    let mut packet = vec![0u8; 40 + 20];
    packet[0] = 0x45; // ipv4, no options
    packet[9] = 1; // ICMP
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
        .sync_routes_from_allowed(&["10.0.0.0/24".into()])
        .expect("routes");

    let route = serve::run_once(&mut stack).expect("run").expect("route");
    assert_eq!(route.destination.to_string(), "10.0.0.0/24");
}

#[test]
fn build_userspace_stack_binds_udp_and_routes_peers() {
    let config = "\
[Relay.Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
IPv4 = 172.17.0.2\n\
Port = 51820\n\
\n\
[Relay.Peer]\n\
Allowed = 10.0.0.0/24\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Endpoint = 203.0.113.1:51820\n";

    let server_config = parse_server_config(config).expect("server config");
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let stack = serve::build_userspace_stack(&server_config, Some(bind_addr)).expect("stack");

    let route = stack.router().routes().first().expect("route");
    assert_eq!(
        route.peer_endpoint.expect("peer"),
        "203.0.113.1:51820".parse().unwrap()
    );
    let bound = stack.bind().local_addr().expect("addr");
    assert_ne!(bound.port(), 0);
}
