use std::net::IpAddr;
use wiretap_rs::expose::{format_expose_rules, resolve_api_addrs, validate_expose_request};

#[test]
fn resolve_api_addrs_from_config() {
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

    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("wiretap_expose_e2ee.conf");
    std::fs::write(&path, e2ee).expect("write e2ee config");

    let addrs = resolve_api_addrs(path.to_str().unwrap(), "").expect("resolve");
    assert_eq!(addrs.len(), 2);
    assert!(addrs.contains(&IpAddr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
    ])));
}

#[test]
fn resolve_api_addrs_from_flag() {
    let addrs = resolve_api_addrs("ignored.conf", "::2").expect("resolve");
    assert_eq!(addrs.len(), 1);
}

#[test]
fn validate_expose_request_dynamic() {
    let api = vec![IpAddr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ])];
    let request =
        validate_expose_request(api, 80, Some(80), Some(8080), "tcp", true).expect("request");
    assert!(request.dynamic);
    assert_eq!(request.local_port, None);
    assert_eq!(request.remote_port, 8080);
}

#[test]
fn validate_expose_request_static_defaults_remote() {
    let api = vec![IpAddr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ])];
    let request = validate_expose_request(api, 80, Some(443), None, "tcp", false).expect("request");
    assert_eq!(request.local_port, Some(443));
    assert_eq!(request.remote_port, 443);
}

#[test]
fn validate_expose_request_rejects_protocol() {
    let api = vec![IpAddr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ])];
    let result = validate_expose_request(api, 80, Some(443), Some(8443), "icmp", false);
    assert!(result.is_err());
}

#[test]
fn format_expose_rules_formats_wildcard() {
    let rules = vec![
        wiretap_rs::api::ExposeRule {
            remote_addr: IpAddr::from([127, 0, 0, 1]),
            local_port: Some(8080),
            remote_port: 9000,
            protocol: "tcp".into(),
        },
        wiretap_rs::api::ExposeRule {
            remote_addr: IpAddr::from([127, 0, 0, 1]),
            local_port: None,
            remote_port: 5353,
            protocol: "udp".into(),
        },
    ];

    let lines = format_expose_rules(&rules);
    assert_eq!(lines[0], "local 8080 <- remote 9000/tcp");
    assert_eq!(lines[1], "local * <- remote 5353/udp");
}
