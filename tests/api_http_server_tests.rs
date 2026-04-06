use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::sync::{Arc, Mutex};
use wiretap_rs::api;
use wiretap_rs::transport::api::{run_http_api, ApiService, HostInterface, PeerType};

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

fn raw_http_request(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = connect_with_retry(addr).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set write timeout");
    stream.write_all(request.as_bytes()).expect("write request");
    stream.shutdown(Shutdown::Write).expect("shutdown write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let (headers, body) = response
        .split_once("\r\n\r\n")
        .expect("response must contain header separator");
    let status_line = headers.lines().next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse::<u16>()
        .expect("numeric status");
    (status, body.to_string())
}

fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

#[test]
fn http_ping_works() {
    let (addr, handle) = start_server();
    let body = api::ping(addr).expect("ping");
    assert_eq!(body, "pong");
    drop(handle);
}

#[test]
fn http_ping_accepts_post_method() {
    let (addr, handle) = start_server();
    let request = format!(
        "POST /ping HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let (status, body) = raw_http_request(addr, &request);
    assert_eq!(status, 200);
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

    let socks_port = free_tcp_port();

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
fn http_expose_dynamic_rejects_unsupported_auth_method() {
    let (addr, handle) = start_server();
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());
    let socks_port = free_tcp_port();
    api::expose(api_addr, None, socks_port, "tcp", true).expect("expose dynamic");

    let mut client = connect_with_retry(("127.0.0.1", socks_port)).expect("connect socks");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");
    client
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set write timeout");

    client
        .write_all(&[0x05, 0x01, 0x02])
        .expect("write greeting");
    let mut response = [0u8; 2];
    client.read_exact(&mut response).expect("read response");
    assert_eq!(response, [0x05, 0xFF]);

    api::expose_remove(api_addr, None, socks_port, "tcp", true).expect("remove dynamic");
    drop(handle);
}

#[test]
fn http_expose_dynamic_rejects_non_connect_command() {
    let (addr, handle) = start_server();
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());
    let socks_port = free_tcp_port();
    api::expose(api_addr, None, socks_port, "tcp", true).expect("expose dynamic");

    let mut client = connect_with_retry(("127.0.0.1", socks_port)).expect("connect socks");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");
    client
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set write timeout");

    client
        .write_all(&[0x05, 0x01, 0x00])
        .expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);

    client
        .write_all(&[
            0x05, 0x02, 0x00, 0x01, // bind command (unsupported)
            1, 2, 3, 4, // address (ignored)
            0, 80, // port (ignored)
        ])
        .expect("write command");
    let mut failure = [0u8; 10];
    client.read_exact(&mut failure).expect("read failure");
    assert_eq!(failure[0], 0x05);
    assert_eq!(failure[1], 0x07);

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

#[test]
fn http_wrong_method_returns_405() {
    let (addr, handle) = start_server();
    let request = format!(
        "POST /serverinfo HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let (status, body) = raw_http_request(addr, &request);
    assert_eq!(status, 405);
    assert!(body.contains("method not allowed"));
    drop(handle);
}

#[test]
fn http_allocate_invalid_type_returns_400() {
    let (addr, handle) = start_server();
    let request =
        format!("GET /allocate?type=9 HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    let (status, body) = raw_http_request(addr, &request);
    assert_eq!(status, 400);
    assert!(body.contains("invalid type"));
    drop(handle);
}

#[test]
fn http_unknown_path_returns_404() {
    let (addr, handle) = start_server();
    let request =
        format!("GET /does-not-exist HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    let (status, body) = raw_http_request(addr, &request);
    assert_eq!(status, 404);
    assert!(body.contains("not found"));
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
    Err(last.unwrap_or_else(|| std::io::Error::other("connect retry failed")))
}
