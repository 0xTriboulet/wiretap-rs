use clap::Parser;
use wiretap_rs::cli::{AddCommand, Cli, Command, ExposeCommand};
use wiretap_rs::constants;

#[test]
fn parse_expose_defaults() {
    let cli = Cli::try_parse_from([
        "wiretap",
        "expose",
        "--local",
        "80",
        "--remote",
        "8080",
        "--protocol",
        "udp",
        "--dynamic",
        "--server-address",
        "::2",
        "--config",
        "custom.conf",
        "--api-port",
        "1234",
    ])
    .expect("parse expose");

    match cli.command {
        Some(Command::Expose(args)) => {
            assert!(args.command.is_none());
            assert_eq!(args.common.local_port, Some(80));
            assert_eq!(args.common.remote_port, Some(8080));
            assert_eq!(args.common.protocol, "udp");
            assert!(args.common.dynamic);
            assert_eq!(args.common.server_address, "::2");
            assert_eq!(args.common.config, "custom.conf");
            assert_eq!(args.common.api_port, 1234);
        }
        _ => panic!("expected expose command"),
    }
}

#[test]
fn parse_expose_list() {
    let cli = Cli::try_parse_from(["wiretap", "expose", "list"]).expect("parse expose list");

    match cli.command {
        Some(Command::Expose(args)) => match args.command {
            Some(ExposeCommand::List(list)) => {
                assert_eq!(list.common.protocol, "tcp");
                assert!(!list.common.dynamic);
                assert_eq!(list.common.config, constants::DEFAULT_CONFIG_E2EE);
                assert_eq!(list.common.api_port, constants::API_PORT);
            }
            _ => panic!("expected expose list command"),
        },
        _ => panic!("expected expose list command"),
    }
}

#[test]
fn parse_expose_remove() {
    let cli = Cli::try_parse_from([
        "wiretap", "expose", "remove", "--local", "443", "--remote", "8443",
    ])
    .expect("parse expose remove");

    match cli.command {
        Some(Command::Expose(args)) => match args.command {
            Some(ExposeCommand::Remove(remove)) => {
                assert_eq!(remove.common.local_port, Some(443));
                assert_eq!(remove.common.remote_port, Some(8443));
            }
            _ => panic!("expected expose remove command"),
        },
        _ => panic!("expected expose remove command"),
    }
}

#[test]
fn parse_ping_api() {
    let cli = Cli::try_parse_from(["wiretap", "ping", "--api", "::2", "--api-port", "1234"])
        .expect("parse ping");

    match cli.command {
        Some(Command::Ping(args)) => {
            assert_eq!(args.api, "::2");
            assert_eq!(args.api_port, 1234);
        }
        _ => panic!("expected ping command"),
    }
}

#[test]
fn parse_serve_with_api_overrides() {
    let cli = Cli::try_parse_from([
        "wiretap",
        "serve",
        "--config-file",
        "wiretap_server.conf",
        "--simple",
        "--api",
        "127.0.0.1",
        "--api-port",
        "8081",
        "--disable-ipv6",
        "--delete-config",
    ])
    .expect("parse serve");

    match cli.command {
        Some(Command::Serve(args)) => {
            assert_eq!(args.config_file.as_deref(), Some("wiretap_server.conf"));
            assert!(args.simple);
            assert_eq!(args.api.as_deref(), Some("127.0.0.1"));
            assert_eq!(args.api_port, 8081);
            assert!(args.disable_ipv6);
            assert!(args.delete_config);
        }
        _ => panic!("expected serve command"),
    }
}

#[test]
fn parse_serve_quiet_flag() {
    let cli = Cli::try_parse_from(["wiretap", "serve", "--quiet"]).expect("parse serve quiet");

    match cli.command {
        Some(Command::Serve(args)) => {
            assert!(args.quiet);
        }
        _ => panic!("expected serve command"),
    }
}

#[test]
fn parse_add_server_server_address() {
    let cli = Cli::try_parse_from([
        "wiretap",
        "add",
        "server",
        "--routes",
        "10.0.0.0/24",
        "--server-address",
        "::2",
        "--endpoint",
        "10.0.0.2:51820",
    ])
    .expect("parse add server");

    match cli.command {
        Some(Command::Add(args)) => match args.command {
            AddCommand::Server(server) => {
                assert_eq!(server.server_address.as_deref(), Some("::2"));
            }
            _ => panic!("expected add server"),
        },
        _ => panic!("expected add command"),
    }
}

#[test]
fn parse_status_network_info() {
    let cli = Cli::try_parse_from([
        "wiretap",
        "status",
        "--network-info",
        "--relay",
        "relay.conf",
        "--e2ee",
        "e2ee.conf",
    ])
    .expect("parse status");

    match cli.command {
        Some(Command::Status(args)) => {
            assert!(args.network_info);
            assert_eq!(args.relay.as_deref(), Some("relay.conf"));
            assert_eq!(args.e2ee.as_deref(), Some("e2ee.conf"));
        }
        _ => panic!("expected status command"),
    }
}
