use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};
use wiretap_rs::constants::{increment_v4, increment_v6};
use wiretap_rs::transport::api::{
    ApiMessage, ApiRequest, ApiResponse, ApiService, ExposeAction, ExposeCommand, ExposeRequest,
    ExposeTuple, InterfaceType, PeerType, ServerConfigs,
};

fn serialize(req: ApiRequest) -> ApiMessage {
    ApiMessage {
        payload: serde_json::to_vec(&req).expect("serialize"),
    }
}

fn temp_state_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "wiretap_alloc_state_{label}_{}_{}.json",
        std::process::id(),
        nanos
    ));
    path
}

#[test]
fn ping_returns_pong() {
    let mut service = ApiService::new();
    let resp = service
        .handle_message(serialize(ApiRequest::Ping))
        .expect("resp");
    assert_eq!(resp, ApiResponse::Pong("pong".into()));
}

#[test]
fn expose_adds_and_lists_ports() {
    let mut service = ApiService::new();
    let request = ExposeRequest {
        action: ExposeAction::Expose,
        local_port: 8080,
        remote_port: 9000,
        protocol: "tcp".into(),
        dynamic: false,
        remote_addr: Some(IpAddr::from([127, 0, 0, 1])),
    };

    service
        .handle_message(serialize(ApiRequest::Expose(request.clone())))
        .expect("add");

    let list = service
        .handle_message(serialize(ApiRequest::Expose(ExposeRequest {
            action: ExposeAction::List,
            local_port: 0,
            remote_port: 0,
            protocol: String::new(),
            dynamic: false,
            remote_addr: None,
        })))
        .expect("list");

    match list {
        ApiResponse::ExposeList(entries) => {
            assert_eq!(
                entries,
                vec![ExposeTuple {
                    remote_addr: request.remote_addr.unwrap(),
                    local_port: 8080,
                    remote_port: 9000,
                    protocol: "tcp".into()
                }]
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[test]
fn expose_rejects_duplicate() {
    let mut service = ApiService::new();
    let request = ExposeRequest {
        action: ExposeAction::Expose,
        local_port: 8080,
        remote_port: 9000,
        protocol: "tcp".into(),
        dynamic: false,
        remote_addr: Some(IpAddr::from([127, 0, 0, 1])),
    };

    service
        .handle_message(serialize(ApiRequest::Expose(request.clone())))
        .expect("first");
    let err = service
        .handle_message(serialize(ApiRequest::Expose(request)))
        .expect_err("dup should err");
    assert!(err.to_string().contains("already"));
}

#[test]
fn delete_removes_entry() {
    let mut service = ApiService::new();
    let base = ExposeRequest {
        action: ExposeAction::Expose,
        local_port: 8080,
        remote_port: 9000,
        protocol: "tcp".into(),
        dynamic: false,
        remote_addr: Some(IpAddr::from([10, 0, 0, 1])),
    };
    service
        .handle_message(serialize(ApiRequest::Expose(base.clone())))
        .expect("add");

    service
        .handle_message(serialize(ApiRequest::Expose(ExposeRequest {
            action: ExposeAction::Delete,
            local_port: base.local_port,
            remote_port: base.remote_port,
            protocol: base.protocol.clone(),
            dynamic: false,
            remote_addr: base.remote_addr,
        })))
        .expect("delete");

    let list = service
        .handle_message(serialize(ApiRequest::Expose(ExposeRequest {
            action: ExposeAction::List,
            local_port: 0,
            remote_port: 0,
            protocol: String::new(),
            dynamic: false,
            remote_addr: None,
        })))
        .expect("list");

    match list {
        ApiResponse::ExposeList(entries) => assert!(entries.is_empty()),
        other => panic!("unexpected response: {:?}", other),
    }
}

#[test]
fn expose_emits_commands_when_channel_configured() {
    let (tx, rx) = mpsc::channel::<ExposeCommand>();
    let (seen_tx, seen_rx) = mpsc::channel::<(String, ExposeTuple, bool)>();

    std::thread::spawn(move || {
        for _ in 0..2 {
            if let Ok(cmd) = rx.recv() {
                match cmd {
                    ExposeCommand::Add {
                        tuple,
                        dynamic,
                        respond,
                    } => {
                        let _ = seen_tx.send(("add".to_string(), tuple, dynamic));
                        let _ = respond.send(Ok(()));
                    }
                    ExposeCommand::Remove { tuple, respond } => {
                        let _ = seen_tx.send(("remove".to_string(), tuple, false));
                        let _ = respond.send(Ok(()));
                    }
                }
            }
        }
    });

    let mut service = ApiService::new().with_expose_tx(tx);
    let base = ExposeRequest {
        action: ExposeAction::Expose,
        local_port: 8080,
        remote_port: 9000,
        protocol: "tcp".into(),
        dynamic: false,
        remote_addr: Some(IpAddr::from([127, 0, 0, 1])),
    };

    service
        .handle_message(serialize(ApiRequest::Expose(base.clone())))
        .expect("add");

    let (action, tuple, dynamic) = seen_rx.recv().expect("command");
    assert_eq!(action, "add");
    assert_eq!(tuple.remote_addr, base.remote_addr.unwrap());
    assert_eq!(tuple.local_port, base.local_port);
    assert_eq!(tuple.remote_port, base.remote_port);
    assert_eq!(tuple.protocol, "tcp");
    assert!(!dynamic);

    service
        .handle_message(serialize(ApiRequest::Expose(ExposeRequest {
            action: ExposeAction::Delete,
            local_port: base.local_port,
            remote_port: base.remote_port,
            protocol: base.protocol.clone(),
            dynamic: false,
            remote_addr: base.remote_addr,
        })))
        .expect("delete");

    let (action, tuple, _) = seen_rx.recv().expect("command");
    assert_eq!(action, "remove");
    assert_eq!(tuple.remote_addr, base.remote_addr.unwrap());
    assert_eq!(tuple.local_port, base.local_port);
    assert_eq!(tuple.remote_port, base.remote_port);
    assert_eq!(tuple.protocol, "tcp");
}

#[test]
fn server_info_roundtrip() {
    let relay = wiretap_rs::peer::Config::new().expect("relay");
    let e2ee = wiretap_rs::peer::Config::new().expect("e2ee");
    let mut service = ApiService::with_configs(Some(relay.clone()), Some(e2ee.clone()));
    let resp = service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::ServerInfo).unwrap(),
        })
        .expect("resp");
    match resp {
        ApiResponse::ServerInfo(ServerConfigs {
            relay_config,
            e2ee_config,
        }) => {
            assert_eq!(relay_config.public_key(), relay.public_key());
            assert_eq!(e2ee_config.public_key(), e2ee.public_key());
        }
        _ => panic!("wrong response"),
    }
}

#[test]
fn server_info_allows_relay_only() {
    let relay = wiretap_rs::peer::Config::new().expect("relay");
    let mut service = ApiService::with_configs(Some(relay.clone()), None);
    let resp = service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::ServerInfo).unwrap(),
        })
        .expect("resp");
    match resp {
        ApiResponse::ServerInfo(ServerConfigs {
            relay_config,
            e2ee_config,
        }) => {
            assert_eq!(relay_config.public_key(), relay.public_key());
            assert!(e2ee_config.peers().is_empty());
            assert!(e2ee_config.addresses().is_empty());
        }
        _ => panic!("wrong response"),
    }
}

#[test]
fn allocation_state_persists_across_restarts() {
    let path = temp_state_path("persist");
    let mut service = ApiService::new();
    service.set_allocation_state_path(&path).expect("set path");

    let first = service
        .handle_message(serialize(ApiRequest::Allocate(PeerType::Server)))
        .expect("allocate");
    let first_state = match first {
        ApiResponse::Allocated(state) => state,
        other => panic!("unexpected response: {:?}", other),
    };
    drop(service);

    let mut service = ApiService::new();
    service.set_allocation_state_path(&path).expect("load path");

    let second = service
        .handle_message(serialize(ApiRequest::Allocate(PeerType::Server)))
        .expect("allocate");
    let second_state = match second {
        ApiResponse::Allocated(state) => state,
        other => panic!("unexpected response: {:?}", other),
    };

    assert_eq!(
        second_state.next_server_relay_addr4,
        increment_v4(first_state.next_server_relay_addr4, 1)
    );
    assert_eq!(
        second_state.next_server_relay_addr6,
        increment_v6(first_state.next_server_relay_addr6, 1)
    );
    assert_eq!(
        second_state.next_server_e2ee_addr4,
        increment_v4(first_state.next_server_e2ee_addr4, 1)
    );
    assert_eq!(
        second_state.next_server_e2ee_addr6,
        increment_v6(first_state.next_server_e2ee_addr6, 1)
    );
    assert_eq!(
        second_state.api_addr,
        match first_state.api_addr {
            IpAddr::V4(addr) => IpAddr::V4(increment_v4(addr, 1)),
            IpAddr::V6(addr) => IpAddr::V6(increment_v6(addr, 1)),
        }
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn allocation_state_creates_file_on_allocate() {
    let path = temp_state_path("create");
    let mut service = ApiService::new();
    service.set_allocation_state_path(&path).expect("set path");

    service
        .handle_message(serialize(ApiRequest::Allocate(PeerType::Client)))
        .expect("allocate");

    let metadata = std::fs::metadata(&path).expect("state file");
    assert!(metadata.len() > 0);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn allocate_advances_addresses() {
    let mut service = ApiService::new();
    let first = match service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::Allocate(PeerType::Server)).unwrap(),
        })
        .expect("alloc")
    {
        ApiResponse::Allocated(state) => state,
        _ => panic!("expected allocation"),
    };
    let second = match service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::Allocate(PeerType::Server)).unwrap(),
        })
        .expect("alloc2")
    {
        ApiResponse::Allocated(state) => state,
        _ => panic!("expected allocation"),
    };
    assert_ne!(
        first.next_server_relay_addr4,
        second.next_server_relay_addr4
    );

    let first_client = match service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::Allocate(PeerType::Client)).unwrap(),
        })
        .expect("alloc client")
    {
        ApiResponse::Allocated(state) => state,
        _ => panic!("expected allocation"),
    };
    let second_client = match service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::Allocate(PeerType::Client)).unwrap(),
        })
        .expect("alloc client2")
    {
        ApiResponse::Allocated(state) => state,
        _ => panic!("expected allocation"),
    };
    assert_ne!(
        first_client.next_client_relay_addr4,
        second_client.next_client_relay_addr4
    );
}

#[test]
fn add_peer_and_allowed_ips_update_config() {
    let mut relay = wiretap_rs::peer::Config::new().expect("relay");
    let peer = wiretap_rs::peer::PeerConfig::new().expect("peer");
    let pubkey = peer.public_key().to_string();
    relay.add_peer(peer);

    let mut service =
        ApiService::with_configs(Some(relay), Some(wiretap_rs::peer::Config::new().unwrap()));

    // addpeer appends
    let resp = service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::AddPeer({
                let mut peer = wiretap_rs::peer::PeerConfig::new().expect("peer2");
                peer.add_allowed_ip("10.1.0.0/24").expect("allowed");
                wiretap_rs::transport::api::AddPeerRequest {
                    interface: InterfaceType::Relay,
                    config: peer,
                }
            }))
            .unwrap(),
        })
        .expect("addpeer");
    assert!(matches!(resp, ApiResponse::Ack));

    // addallowedips modifies first peer
    let resp = service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::AddAllowedIps(
                wiretap_rs::transport::api::AddAllowedIpsRequest {
                    public_key: pubkey.clone(),
                    allowed_ips: vec!["10.0.0.0/24".into()],
                },
            ))
            .unwrap(),
        })
        .expect("addallowed");
    assert!(matches!(resp, ApiResponse::Ack));

    let relay_after = service
        .handle_message(ApiMessage {
            payload: serde_json::to_vec(&ApiRequest::ServerInfo).unwrap(),
        })
        .unwrap();
    if let ApiResponse::ServerInfo(ServerConfigs { relay_config, .. }) = relay_after {
        let first_peer = relay_config.peers().first().unwrap();
        assert_eq!(first_peer.allowed_ips().len(), 1);
    } else {
        panic!("expected server info");
    }
}

#[test]
fn add_peer_rejects_empty_allowed_ips() {
    let relay = wiretap_rs::peer::Config::new().expect("relay");
    let mut service =
        ApiService::with_configs(Some(relay), Some(wiretap_rs::peer::Config::new().unwrap()));

    let peer = wiretap_rs::peer::PeerConfig::new().expect("peer");
    let add_peer = wiretap_rs::transport::api::AddPeerRequest {
        interface: InterfaceType::Relay,
        config: peer,
    };

    let err = service
        .handle_message(serialize(ApiRequest::AddPeer(add_peer)))
        .expect_err("empty allowed should error");
    assert!(err.to_string().contains("allowed"));
}
