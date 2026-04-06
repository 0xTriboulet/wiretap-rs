use ipnet::IpNet;
use std::net::IpAddr;
use wiretap_rs::status::{load_status_summary, split_routes_and_api, StatusSummary};

#[test]
fn split_routes_and_api_uses_last_allowed_ip_as_api() {
    let allowed = vec![
        "10.0.0.0/24".parse::<IpNet>().unwrap(),
        "10.1.0.0/24".parse::<IpNet>().unwrap(),
        "fd00::2/128".parse::<IpNet>().unwrap(),
    ];

    let (routes, api) = split_routes_and_api(&allowed);
    assert_eq!(routes.len(), 2);
    assert_eq!(
        api,
        Some(IpAddr::from([
            0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        ]))
    );
}

#[test]
fn status_summary_collects_servers_from_e2ee_peers() {
    let relay = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.16.0.1/32\n";

    let e2ee = "\
[Interface]\n\
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
Address = 172.19.0.1/32\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.0.0.0/24,::2/128\n\
\n\
[Peer]\n\
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
AllowedIPs = 10.1.0.0/24,::3/128\n";

    let summary = StatusSummary::from_configs(relay, e2ee).expect("summary");
    assert_eq!(summary.servers.len(), 2);
    assert_eq!(summary.servers[0].routes.len(), 1);
    assert!(summary.servers[0].api.is_some());
}

#[test]
fn status_summary_errors_on_missing_config() {
    let relay = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n";
    let result = StatusSummary::from_configs(relay, "");
    assert!(result.is_err());
}

#[test]
fn load_status_summary_missing_files_returns_error() {
    let result = load_status_summary("missing_relay.conf", "missing_e2ee.conf");
    assert!(result.is_err());
}

#[test]
fn load_status_summary_reads_temp_files() {
    let temp_dir = std::env::temp_dir();
    let relay_path = temp_dir.join("wiretap_status_relay.conf");
    let e2ee_path = temp_dir.join("wiretap_status_e2ee.conf");

    let relay = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n";
    let e2ee = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n";
    std::fs::write(&relay_path, relay).expect("write relay config");
    std::fs::write(&e2ee_path, e2ee).expect("write e2ee config");

    let summary = load_status_summary(relay_path.to_str().unwrap(), e2ee_path.to_str().unwrap())
        .expect("load summary");
    assert!(!summary.client_relay_public.is_empty());
}
