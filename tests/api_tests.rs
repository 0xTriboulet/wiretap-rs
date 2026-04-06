use serde::Deserialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use wiretap_rs::api;

#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    path: String,
    body: String,
}

#[derive(Debug, Clone)]
struct TestResponse {
    status: u16,
    body: String,
}

impl TestResponse {
    fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
        }
    }

    fn error(body: impl Into<String>) -> Self {
        Self {
            status: 500,
            body: body.into(),
        }
    }
}

fn start_test_server<F>(handler: F) -> (SocketAddr, thread::JoinHandle<()>)
where
    F: Fn(HttpRequest) -> TestResponse + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("local addr");

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

            let mut request_line = String::new();
            if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                return;
            }
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            let method = parts.first().unwrap_or(&"").to_string();
            let path = parts.get(1).unwrap_or(&"").to_string();

            let mut headers = HashMap::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                }
            }

            let length = headers
                .get("content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let mut body_bytes = vec![0u8; length];
            if length > 0 {
                let _ = reader.read_exact(&mut body_bytes);
            }
            let body = String::from_utf8_lossy(&body_bytes).into_owned();

            let response = handler(HttpRequest { method, path, body });

            let response_text = format!(
                "HTTP/1.1 {} OK\r\nContent-Length: {}\r\n\r\n{}",
                response.status,
                response.body.len(),
                response.body
            );
            let _ = stream.write_all(response_text.as_bytes());
        }
    });

    (addr, handle)
}

#[test]
fn ping_returns_pong() {
    let seen = Arc::new(Mutex::new(Vec::<HttpRequest>::new()));
    let seen_clone = seen.clone();
    let (addr, handle) = start_test_server(move |req| {
        seen_clone.lock().unwrap().push(req);
        TestResponse::ok("pong")
    });

    let response = api::ping(addr).expect("ping");
    handle.join().expect("server thread");

    assert_eq!(response, "pong");
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/ping");
}

#[test]
fn ping_bubbles_up_error_body() {
    let (addr, handle) = start_test_server(|_| TestResponse::error("boom"));

    let err = api::ping(addr).expect_err("expected ping error");
    handle.join().expect("server thread");

    assert!(err.to_string().contains("boom"));
}

#[derive(Deserialize)]
struct ExposeRequestBody {
    #[serde(rename = "Action")]
    action: u8,
    #[serde(rename = "LocalPort")]
    local_port: u16,
    #[serde(rename = "RemotePort")]
    remote_port: u16,
    #[serde(rename = "Protocol")]
    protocol: String,
    #[serde(rename = "Dynamic")]
    dynamic: bool,
}

#[test]
fn expose_sends_static_request_payload() {
    let seen = Arc::new(Mutex::new(Vec::<HttpRequest>::new()));
    let seen_clone = seen.clone();
    let (addr, handle) = start_test_server(move |req| {
        seen_clone.lock().unwrap().push(req);
        TestResponse::ok("")
    });

    api::expose(addr, Some(8080), 9000, "tcp", false).expect("expose");
    handle.join().expect("server thread");

    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/expose");

    let payload: ExposeRequestBody =
        serde_json::from_str(&requests[0].body).expect("parse expose payload");
    assert_eq!(payload.action, 0);
    assert_eq!(payload.local_port, 8080);
    assert_eq!(payload.remote_port, 9000);
    assert_eq!(payload.protocol, "tcp");
    assert!(!payload.dynamic);
}

#[test]
fn expose_remove_uses_delete_action() {
    let seen = Arc::new(Mutex::new(Vec::<HttpRequest>::new()));
    let seen_clone = seen.clone();
    let (addr, handle) = start_test_server(move |req| {
        seen_clone.lock().unwrap().push(req);
        TestResponse::ok("")
    });

    api::expose_remove(addr, None, 5353, "udp", true).expect("remove");
    handle.join().expect("server thread");

    let payload: ExposeRequestBody =
        serde_json::from_str(&seen.lock().unwrap()[0].body).expect("parse payload");
    assert_eq!(payload.action, 2);
    assert_eq!(payload.local_port, 0); // dynamic requests omit local port
    assert_eq!(payload.remote_port, 5353);
    assert_eq!(payload.protocol, "udp");
    assert!(payload.dynamic);
}

#[test]
fn expose_list_parses_response() {
    let response_body = r#"
        [
            {"RemoteAddr":"127.0.0.1","LocalPort":8080,"RemotePort":9000,"Protocol":"tcp"},
            {"RemoteAddr":"127.0.0.1","LocalPort":0,"RemotePort":5353,"Protocol":"udp"}
        ]
    "#;

    let (addr, handle) = start_test_server(move |req| {
        let payload: ExposeRequestBody =
            serde_json::from_str(&req.body).expect("parse list payload");
        assert_eq!(payload.action, 1);
        TestResponse::ok(response_body)
    });

    let rules = api::expose_list(addr).expect("list");
    handle.join().expect("server thread");

    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0].remote_addr,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(rules[0].local_port, Some(8080));
    assert_eq!(rules[0].remote_port, 9000);
    assert_eq!(rules[0].protocol, "tcp");

    assert_eq!(rules[1].local_port, None);
    assert_eq!(rules[1].remote_port, 5353);
    assert_eq!(rules[1].protocol, "udp");
}

#[test]
fn serverinfo_roundtrip_client() {
    // minimal stub server responding with serverinfo
    let relay = wiretap_rs::peer::Config::new().expect("relay");
    let e2ee = wiretap_rs::peer::Config::new().expect("e2ee");
    let configs_json = serde_json::to_string(&wiretap_rs::transport::api::ServerConfigs {
        relay_config: relay.clone(),
        e2ee_config: e2ee.clone(),
    })
    .unwrap();

    let (addr, handle) = start_test_server(move |_req| TestResponse::ok(configs_json.clone()));
    let api_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), addr.port());

    let (relay_out, e2ee_out) = api::server_info(api_addr).expect("serverinfo");
    handle.join().expect("server thread");
    assert_eq!(relay_out.public_key(), relay.public_key());
    assert_eq!(e2ee_out.public_key(), e2ee.public_key());
}
