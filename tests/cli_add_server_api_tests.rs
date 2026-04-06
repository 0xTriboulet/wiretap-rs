use std::fs;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use wiretap_rs::peer::Config;
use wiretap_rs::transport::api::{run_http_api, ApiService};

fn unique_temp_dir() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    dir.push(format!("wiretap-rs-test-{}", nanos));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn add_server_with_api_does_not_rewrite_relay_file() {
    let temp = unique_temp_dir();
    let relay_path = temp.join("wiretap_relay.conf");
    let e2ee_path = temp.join("wiretap.conf");
    let server_output = temp.join("wiretap_server.conf");

    let relay_contents = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.16.0.1/32\n";

    let e2ee_contents = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n";

    fs::write(&relay_path, relay_contents).expect("write relay");
    fs::write(&e2ee_path, e2ee_contents).expect("write e2ee");

    let before = fs::read_to_string(&relay_path).expect("read relay");

    let mut server_relay = Config::new().expect("relay config");
    server_relay
        .add_address("172.17.0.2/32")
        .expect("relay addr");
    let mut server_e2ee = Config::new().expect("e2ee config");
    server_e2ee.add_address("192.0.2.2/32").expect("e2ee addr");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let service = Arc::new(Mutex::new(ApiService::with_configs(
        Some(server_relay),
        Some(server_e2ee),
    )));
    let _handle = run_http_api(addr, service).expect("api server");

    let status = Command::new(env!("CARGO_BIN_EXE_wiretap-rs"))
        .arg("add")
        .arg("server")
        .arg("--server-address")
        .arg("127.0.0.1")
        .arg("--api-port")
        .arg(addr.port().to_string())
        .arg("--routes")
        .arg("10.0.1.0/24")
        .arg("--relay-input")
        .arg(&relay_path)
        .arg("--e2ee-input")
        .arg(&e2ee_path)
        .arg("--server-output")
        .arg(&server_output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run");
    assert!(status.success());

    let after = fs::read_to_string(&relay_path).expect("read relay after");
    assert_eq!(before, after);
    assert!(server_output.exists());

    let _ = fs::remove_dir_all(&temp);
}
