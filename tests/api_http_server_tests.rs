use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use wiretap_rs::api;
use wiretap_rs::transport::api::{ApiService, HostInterface, PeerType, run_http_api};

fn start_server() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let relay = wiretap_rs::peer::Config::new().expect("relay");
    let e2ee = wiretap_rs::peer::Config::new().expect("e2ee");
    let mut service = ApiService::with_configs(Some(relay), Some(e2ee));
    service = service.with_interfaces(vec![HostInterface {
        name: "lo".into(),
        addrs: vec!["127.0.0.1/8".into()],
    }]);
    let service = Arc::new(Mutex::new(service));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    // tiny_http owns the listener internally, so drop this one and let server bind same addr.
    drop(listener);
    let handle = run_http_api(addr, service).expect("run api");
    (addr, handle)
}

#[test]
fn http_ping_works() {
    let (addr, handle) = start_server();
    let body = api::ping(addr).expect("ping");
    assert_eq!(body, "pong");
    drop(handle);
}

#[test]
fn http_expose_roundtrip() {
    let (addr, handle) = start_server();
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());

    api::expose(api_addr, Some(8080), 9000, "tcp", false).expect("expose");
    let rules = api::expose_list(api_addr).expect("list");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].remote_port, 9000);

    api::expose_remove(api_addr, Some(8080), 9000, "tcp", false).expect("remove");
    let rules = api::expose_list(api_addr).expect("list empty");
    assert!(rules.is_empty());

    drop(handle);
}

#[test]
fn http_expose_dynamic_socks5_roundtrip() {
    let (addr, handle) = start_server();
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());

    let echo_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let echo_port = echo_listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = echo_listener.accept() {
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        }
    });

    let port_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("port bind");
    let socks_port = port_listener.local_addr().unwrap().port();
    drop(port_listener);

    api::expose(api_addr, None, socks_port, "tcp", true).expect("expose dynamic");

    let mut client = connect_with_retry(("127.0.0.1", socks_port)).expect("connect socks");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    client
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();

    // Greeting: version 5, 1 method, no auth.
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // Connect request (host ignored by server, port is used).
    let port_bytes = echo_port.to_be_bytes();
    let request = [
        0x05,
        0x01,
        0x00,
        0x01,
        1,
        2,
        3,
        4,
        port_bytes[0],
        port_bytes[1],
    ];
    client.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);

    let payload = b"hello";
    client.write_all(payload).unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, payload);

    api::expose_remove(api_addr, None, socks_port, "tcp", true).expect("remove dynamic");
    drop(handle);
}

#[test]
fn http_allocate_get_works() {
    let (addr, handle) = start_server();
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());
    let url = format!("http://{api_addr}/allocate?type=1");
    let body = ureq::get(&url)
        .call()
        .expect("allocate get")
        .into_string()
        .unwrap();
    let state: wiretap_rs::transport::api::NetworkState =
        serde_json::from_str(&body).expect("state");
    let _ = state.next_server_relay_addr4;
    drop(handle);
}

#[test]
fn http_add_peer_query_param() {
    let (addr, handle) = start_server();
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());
    let url = format!("http://{api_addr}/addpeer?interface=0");

    let mut peer = wiretap_rs::peer::PeerConfig::new().expect("peer");
    peer.add_allowed_ip("10.0.0.0/24").expect("allowed");
    let payload = serde_json::to_string(&peer).expect("json");

    ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .expect("addpeer");

    let (relay, _e2ee) = api::server_info(api_addr).expect("serverinfo");
    assert_eq!(relay.peers().len(), 1);
    drop(handle);
}

#[test]
fn http_serverinfo_and_allocate_work() {
    let (addr, handle) = start_server();
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());

    let (_relay, _e2ee) = api::server_info(api_addr).expect("serverinfo");
    let _ifaces = api::server_interfaces(api_addr).expect("ifaces");
    let _state = api::allocate(api_addr, PeerType::Server).expect("allocate");

    drop(handle);
}

fn connect_with_retry<A: std::net::ToSocketAddrs>(addr: A) -> std::io::Result<std::net::TcpStream> {
    let mut last = None;
    for _ in 0..20 {
        match std::net::TcpStream::connect(&addr) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last = Some(err);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    Err(last
        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "connect retry failed")))
}
