use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use wiretap_rs::transport::smoltcp::SmoltcpTcpProxy;

#[test]
fn smoltcp_udp_idle_timeout_can_be_overridden() {
    let mut proxy = SmoltcpTcpProxy::new(&[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))], None)
        .expect("create smoltcp proxy");
    assert_eq!(proxy.udp_idle_timeout(), Duration::from_secs(60));

    proxy.set_udp_idle_timeout(Duration::from_secs(17));
    assert_eq!(proxy.udp_idle_timeout(), Duration::from_secs(17));
}
