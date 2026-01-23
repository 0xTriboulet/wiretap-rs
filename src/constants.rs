use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const VERSION: &str = "v0.0.0";

pub const DEFAULT_PORT: u16 = 51820;
pub const DEFAULT_E2EE_PORT: u16 = 51821;
pub const DEFAULT_KEEPALIVE: u16 = 25;
pub const DEFAULT_MTU: u16 = 1420;
pub const DEFAULT_COMPLETION_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_CONN_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_KEEPALIVE_IDLE_SECS: u64 = 60;
pub const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_KEEPALIVE_COUNT: u32 = 3;

pub const SUBNET_V4_BITS: u8 = 24;
pub const SUBNET_V6_BITS: u8 = 48;

pub const DEFAULT_CONFIG_RELAY: &str = "wiretap_relay.conf";
pub const DEFAULT_CONFIG_E2EE: &str = "wiretap.conf";
pub const DEFAULT_CONFIG_SERVER: &str = "wiretap_server.conf";

pub const API_PORT: u16 = 80;

pub fn api_subnet_v6() -> Ipv6Net {
    "::/8".parse().expect("valid api subnet v6")
}

pub fn api_subnet_v4() -> Ipv4Net {
    "192.0.2.0/24".parse().expect("valid api subnet v4")
}

pub fn client_relay_subnet_v4() -> Ipv4Net {
    "172.16.0.0/16"
        .parse()
        .expect("valid client relay v4 subnet")
}

pub fn client_relay_subnet_v6() -> Ipv6Net {
    "fd:16::/40".parse().expect("valid client relay v6 subnet")
}

pub fn relay_subnet_v4() -> Ipv4Net {
    "172.17.0.0/16".parse().expect("valid relay v4 subnet")
}

pub fn relay_subnet_v6() -> Ipv6Net {
    "fd:17::/40".parse().expect("valid relay v6 subnet")
}

pub fn e2ee_subnet_v4() -> Ipv4Net {
    "172.18.0.0/16".parse().expect("valid e2ee v4 subnet")
}

pub fn e2ee_subnet_v6() -> Ipv6Net {
    "fd:18::/40".parse().expect("valid e2ee v6 subnet")
}

pub fn client_e2ee_subnet_v4() -> Ipv4Net {
    "172.19.0.0/16"
        .parse()
        .expect("valid client e2ee v4 subnet")
}

pub fn client_e2ee_subnet_v6() -> Ipv6Net {
    "fd:19::/40".parse().expect("valid client e2ee v6 subnet")
}

pub fn default_client_relay_v4() -> Ipv4Addr {
    increment_v4(client_relay_subnet_v4().network(), 1)
}

pub fn default_client_relay_v6() -> Ipv6Addr {
    increment_v6(client_relay_subnet_v6().network(), 1)
}

pub fn default_client_e2ee_v4() -> Ipv4Addr {
    increment_v4(client_e2ee_subnet_v4().network(), 1)
}

pub fn default_client_e2ee_v6() -> Ipv6Addr {
    increment_v6(client_e2ee_subnet_v6().network(), 1)
}

pub fn default_server_relay_v4() -> Ipv4Addr {
    increment_v4(relay_subnet_v4().network(), 2)
}

pub fn default_server_relay_v6() -> Ipv6Addr {
    increment_v6(relay_subnet_v6().network(), 2)
}

pub fn default_server_e2ee_v4() -> Ipv4Addr {
    increment_v4(e2ee_subnet_v4().network(), 2)
}

pub fn default_server_e2ee_v6() -> Ipv6Addr {
    increment_v6(e2ee_subnet_v6().network(), 2)
}

pub fn default_api_v6() -> Ipv6Addr {
    increment_v6(api_subnet_v6().network(), 2)
}

pub fn default_api_v4() -> Ipv4Addr {
    increment_v4(api_subnet_v4().network(), 2)
}

pub fn increment_v4(base: Ipv4Addr, delta: u32) -> Ipv4Addr {
    let value = u32::from(base).saturating_add(delta);
    Ipv4Addr::from(value)
}

pub fn increment_v6(base: Ipv6Addr, delta: u128) -> Ipv6Addr {
    let value = u128::from(base).saturating_add(delta);
    Ipv6Addr::from(value)
}
