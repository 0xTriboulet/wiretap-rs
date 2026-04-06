use crate::clipboard;
use crate::constants;
use crate::peer::{
    create_server_command, create_server_file, find_available_filename, Config, ConfigArgs,
    PeerConfigArgs, Shell,
};
use anyhow::{anyhow, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use owo_colors::OwoColorize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "wiretap", version = constants::VERSION)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(long = "show-hidden", short = 'H', default_value_t = false)]
    show_hidden: bool,
}

#[derive(Subcommand)]
pub enum Command {
    Configure(ConfigureArgs),
    Serve(ServeArgs),
    Status(StatusArgs),
    Add(AddArgs),
    Expose(ExposeArgs),
    Ping(PingArgs),
}

#[derive(Parser, Debug)]
pub struct ConfigureArgs {
    #[arg(long = "routes", short = 'r', required = true)]
    routes: Vec<String>,

    #[arg(long = "endpoint", short = 'e')]
    endpoint: Option<String>,

    #[arg(long = "outbound-endpoint", short = 'o')]
    outbound_endpoint: Option<String>,

    #[arg(long = "port", short = 'p')]
    port: Option<u16>,

    #[arg(long = "sport", short = 'S')]
    sport: Option<u16>,

    #[arg(long = "nickname", short = 'n', default_value = "")]
    nickname: String,

    #[arg(long = "relay-output", default_value = constants::DEFAULT_CONFIG_RELAY)]
    relay_output: String,

    #[arg(long = "e2ee-output", default_value = constants::DEFAULT_CONFIG_E2EE)]
    e2ee_output: String,

    #[arg(long = "server-output", short = 's', default_value = constants::DEFAULT_CONFIG_SERVER)]
    server_output: String,

    #[arg(long = "clipboard", short = 'c', default_value_t = false)]
    clipboard: bool,

    #[arg(long = "simple", default_value_t = false)]
    simple: bool,

    #[arg(long = "api", short = '0', default_value_t = default_api_v6())]
    api_addr: String,

    #[arg(long = "keepalive", short = 'k', default_value_t = constants::DEFAULT_KEEPALIVE)]
    keepalive: u16,

    #[arg(long = "mtu", short = 'm', default_value_t = constants::DEFAULT_MTU)]
    mtu: u16,

    #[arg(long = "disable-ipv6", default_value_t = false)]
    disable_ipv6: bool,

    #[arg(long = "ipv4-relay", default_value_t = default_client_relay_v4())]
    client_addr4_relay: String,

    #[arg(long = "ipv6-relay", default_value_t = default_client_relay_v6())]
    client_addr6_relay: String,

    #[arg(long = "ipv4-e2ee", default_value_t = default_client_e2ee_v4())]
    client_addr4_e2ee: String,

    #[arg(long = "ipv6-e2ee", default_value_t = default_client_e2ee_v6())]
    client_addr6_e2ee: String,

    #[arg(long = "ipv4-relay-server", default_value_t = default_server_relay_v4())]
    server_addr4_relay: String,

    #[arg(long = "ipv6-relay-server", default_value_t = default_server_relay_v6())]
    server_addr6_relay: String,

    #[arg(long = "localhost-ip", short = 'i', default_value = "")]
    localhost_ip: String,

    #[arg(long = "PSK", short = 'K', default_value_t = false)]
    generate_psk: bool,
}

#[derive(Parser, Debug, Default)]
pub struct ServeArgs {
    #[arg(long = "config-file", short = 'f')]
    pub config_file: Option<String>,

    #[arg(long = "quiet", short = 'q', default_value_t = false)]
    pub quiet: bool,

    #[arg(long = "simple", default_value_t = false)]
    pub simple: bool,

    #[arg(long = "api", short = '0')]
    pub api: Option<String>,

    #[arg(long = "api-port", short = 'P', default_value_t = constants::API_PORT)]
    pub api_port: u16,

    #[arg(long = "disable-ipv6", default_value_t = false)]
    pub disable_ipv6: bool,

    #[arg(long = "delete-config", short = 'D', default_value_t = false)]
    pub delete_config: bool,

    #[arg(long = "keepalive", short = 'k', default_value_t = constants::DEFAULT_KEEPALIVE)]
    pub keepalive: u16,

    #[arg(long = "completion-timeout", default_value_t = constants::DEFAULT_COMPLETION_TIMEOUT_MS)]
    pub completion_timeout_ms: u64,

    #[arg(long = "conn-timeout", default_value_t = constants::DEFAULT_CONN_TIMEOUT_MS)]
    pub conn_timeout_ms: u64,

    #[arg(long = "keepalive-idle", default_value_t = constants::DEFAULT_KEEPALIVE_IDLE_SECS)]
    pub keepalive_idle_secs: u64,

    #[arg(
        long = "keepalive-interval",
        default_value_t = constants::DEFAULT_KEEPALIVE_INTERVAL_SECS
    )]
    pub keepalive_interval_secs: u64,

    #[arg(long = "keepalive-count", default_value_t = constants::DEFAULT_KEEPALIVE_COUNT)]
    pub keepalive_count: u32,

    #[arg(long = "udp-timeout", default_value_t = constants::DEFAULT_UDP_TIMEOUT_SECS)]
    pub udp_timeout_secs: u64,
}

#[derive(Parser, Debug, Default)]
pub struct StatusArgs {
    #[arg(long = "relay", short = '1')]
    pub relay: Option<String>,

    #[arg(long = "e2ee", short = '2')]
    pub e2ee: Option<String>,

    #[arg(long = "network-info", default_value_t = false)]
    pub network_info: bool,
}

#[derive(Parser, Debug)]
pub struct AddArgs {
    #[command(subcommand)]
    pub command: AddCommand,
}

#[derive(Subcommand, Debug)]
pub enum AddCommand {
    Server(AddServerCliArgs),
    Client(AddClientCliArgs),
}

#[derive(Parser, Debug)]
pub struct AddServerCliArgs {
    #[arg(long = "routes", short = 'r', required = true)]
    routes: Vec<String>,

    #[arg(long = "endpoint", short = 'e')]
    endpoint: Option<String>,

    #[arg(long = "outbound-endpoint", short = 'o')]
    outbound_endpoint: Option<String>,

    #[arg(long = "server-address", short = 's')]
    pub server_address: Option<String>,

    #[arg(long = "port", short = 'p')]
    port: Option<u16>,

    #[arg(long = "keepalive", short = 'k', default_value_t = constants::DEFAULT_KEEPALIVE, hide = true)]
    keepalive: u16,

    #[arg(long = "localhost-ip", short = 'i')]
    localhost_ip: Option<String>,

    #[arg(long = "nickname", short = 'n')]
    nickname: Option<String>,

    #[arg(long = "disable-ipv6", default_value_t = false)]
    disable_ipv6: bool,

    #[arg(long = "relay-input", default_value = constants::DEFAULT_CONFIG_RELAY, hide = true)]
    relay_input: String,

    #[arg(long = "e2ee-input", default_value = constants::DEFAULT_CONFIG_E2EE, hide = true)]
    e2ee_input: String,

    #[arg(long = "server-output", default_value = constants::DEFAULT_CONFIG_SERVER, hide = true)]
    server_output: String,

    #[arg(long = "clipboard", short = 'c', default_value_t = false)]
    clipboard: bool,

    #[arg(long = "api-port", default_value_t = constants::API_PORT, hide = true)]
    api_port: u16,
}

#[derive(Parser, Debug)]
pub struct AddClientCliArgs {
    #[arg(long = "endpoint", short = 'e')]
    endpoint: Option<String>,

    #[arg(long = "outbound-endpoint", short = 'o')]
    outbound_endpoint: Option<String>,

    #[arg(long = "server-address", short = 's')]
    server_address: Option<String>,

    #[arg(long = "port", short = 'p')]
    port: Option<u16>,

    #[arg(long = "keepalive", short = 'k', default_value_t = constants::DEFAULT_KEEPALIVE, hide = true)]
    keepalive: u16,

    #[arg(long = "disable-ipv6", default_value_t = false)]
    disable_ipv6: bool,

    #[arg(long = "relay-input", default_value = constants::DEFAULT_CONFIG_RELAY, hide = true)]
    relay_input: String,

    #[arg(long = "e2ee-input", default_value = constants::DEFAULT_CONFIG_E2EE, hide = true)]
    e2ee_input: String,

    #[arg(long = "relay-output", default_value = constants::DEFAULT_CONFIG_RELAY, hide = true)]
    relay_output: String,

    #[arg(long = "e2ee-output", default_value = constants::DEFAULT_CONFIG_E2EE, hide = true)]
    e2ee_output: String,

    #[arg(long = "api-port", default_value_t = constants::API_PORT, hide = true)]
    api_port: u16,
}

#[derive(Parser, Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposeCommonArgs {
    #[arg(long = "server-address", short = 's', default_value = "")]
    pub server_address: String,

    #[arg(long = "config", short = 'c', default_value = constants::DEFAULT_CONFIG_E2EE)]
    pub config: String,

    #[arg(long = "api-port", short = 'P', default_value_t = default_api_port())]
    pub api_port: u16,

    #[arg(long = "local", short = 'l')]
    pub local_port: Option<u16>,

    #[arg(long = "remote", short = 'r')]
    pub remote_port: Option<u16>,

    #[arg(long = "protocol", short = 'p', default_value = "tcp")]
    pub protocol: String,

    #[arg(long = "dynamic", short = 'd', default_value_t = false)]
    pub dynamic: bool,
}

#[derive(Parser, Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposeListArgs {
    #[command(flatten)]
    pub common: ExposeCommonArgs,
}

#[derive(Parser, Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposeRemoveArgs {
    #[command(flatten)]
    pub common: ExposeCommonArgs,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ExposeCommand {
    List(ExposeListArgs),
    Remove(ExposeRemoveArgs),
}

#[derive(Parser, Debug)]
pub struct ExposeArgs {
    #[command(subcommand)]
    pub command: Option<ExposeCommand>,

    #[command(flatten)]
    pub common: ExposeCommonArgs,
}

#[derive(Parser, Debug)]
pub struct PingArgs {
    #[arg(long = "api", short = '0', default_value_t = default_ping_api())]
    pub api: String,

    #[arg(long = "api-port", short = 'P', default_value_t = default_api_port())]
    pub api_port: u16,
}

fn build_cli_command(show_hidden: bool) -> clap::Command {
    let mut cmd = Cli::command();
    if show_hidden {
        cmd = unhide_command(cmd);
    }
    cmd
}

fn unhide_command(mut cmd: clap::Command) -> clap::Command {
    cmd = cmd.mut_args(|arg| arg.hide(false));
    cmd = cmd.mut_subcommands(unhide_command);
    cmd
}

pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    run_with_args(&args)
}

pub fn run_with_args(args: &[String]) -> Result<()> {
    let show_hidden = args.iter().any(|arg| arg == "--show-hidden" || arg == "-H");
    let cmd = build_cli_command(show_hidden);

    let matches = match cmd.try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(err) => {
            use clap::error::ErrorKind;
            match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    err.print()?;
                    return Ok(());
                }
                _ => return Err(err.into()),
            }
        }
    };

    let cli = Cli::from_arg_matches(&matches)?;
    match cli.command {
        Some(Command::Configure(args)) => configure(args),
        Some(Command::Serve(args)) => serve(args),
        Some(Command::Status(args)) => status(args),
        Some(Command::Add(args)) => add(args),
        Some(Command::Expose(args)) => expose(args),
        Some(Command::Ping(args)) => ping(args),
        None => {
            let mut cmd = build_cli_command(cli.show_hidden);
            cmd.print_help()?;
            println!();
            Ok(())
        }
    }
}

fn configure(mut args: ConfigureArgs) -> Result<()> {
    if args.endpoint.is_some() == args.outbound_endpoint.is_some() {
        return Err(anyhow!(
            "must specify either --endpoint or --outbound-endpoint"
        ));
    }

    if !args.localhost_ip.is_empty() {
        args.routes.push(format!("{}/32", args.localhost_ip));
    }

    if args.disable_ipv6 && args.api_addr.contains(':') {
        args.api_addr = default_api_v4();
    }
    args.routes.push(args.api_addr.clone());

    let client_port = match args.port {
        Some(port) => port,
        None => match &args.endpoint {
            Some(endpoint) => port_from_endpoint(endpoint)?,
            None => constants::DEFAULT_PORT,
        },
    };

    let server_port = match args.sport {
        Some(port) => port,
        None => match &args.outbound_endpoint {
            Some(endpoint) => port_from_endpoint(endpoint)?,
            None => constants::DEFAULT_PORT,
        },
    };

    let relay_subnet4 = subnet_from_host(&args.server_addr4_relay, constants::SUBNET_V4_BITS)?;
    let relay_subnet6 = subnet_v6_from_host(&args.server_addr6_relay, constants::SUBNET_V6_BITS)?;

    let relay_subnets = if args.disable_ipv6 {
        vec![IpNet::V4(relay_subnet4)]
    } else {
        vec![IpNet::V4(relay_subnet4), IpNet::V6(relay_subnet6)]
    };

    let mut client_relay_addrs = vec![args.client_addr4_relay.clone()];
    if !args.disable_ipv6 {
        client_relay_addrs.push(args.client_addr6_relay.clone());
    }

    let mut client_e2ee_addrs = vec![args.client_addr4_e2ee.clone()];
    if !args.disable_ipv6 {
        client_e2ee_addrs.push(args.client_addr6_e2ee.clone());
    }

    let mut server_config_relay = Config::new()?;
    let mut server_config_e2ee = Config::new()?;
    server_config_relay.set_port(server_port)?;
    server_config_relay.add_address(&args.server_addr4_relay)?;
    if !args.disable_ipv6 {
        server_config_relay.add_address(&args.server_addr6_relay)?;
    }
    if args.simple {
        server_config_relay.add_address(&args.api_addr)?;
    } else {
        server_config_e2ee.add_address(&args.api_addr)?;
    }

    let mut relay_peer_args = PeerConfigArgs {
        public_key: Some(server_config_relay.public_key().to_string()),
        allowed_ips: if args.simple {
            args.routes.clone()
        } else {
            relay_subnets.iter().map(|net| net.to_string()).collect()
        },
        ..Default::default()
    };
    if let Some(outbound) = &args.outbound_endpoint {
        relay_peer_args.endpoint = Some(outbound.clone());
        relay_peer_args.persistent_keepalive = Some(args.keepalive);
    }
    if args.generate_psk {
        server_config_relay.gen_preshared_key()?;
        relay_peer_args.preshared_key = server_config_relay
            .preshared_key()
            .map(|key| key.to_string());
    }

    let client_config_relay = Config::from_args(ConfigArgs {
        listen_port: Some(client_port),
        peers: vec![relay_peer_args],
        addresses: client_relay_addrs,
        ..Default::default()
    })?;

    let relay_endpoint_ip = constants::increment_v4(relay_subnet4.network(), 2);
    let mut e2ee_peer_args = PeerConfigArgs {
        public_key: Some(server_config_e2ee.public_key().to_string()),
        allowed_ips: args.routes.clone(),
        endpoint: Some(format!(
            "{}:{}",
            relay_endpoint_ip,
            constants::DEFAULT_E2EE_PORT
        )),
        ..Default::default()
    };
    if !args.nickname.is_empty() {
        e2ee_peer_args.nickname = Some(args.nickname.clone());
    }

    let client_config_e2ee = Config::from_args(ConfigArgs {
        listen_port: Some(constants::DEFAULT_E2EE_PORT),
        peers: vec![e2ee_peer_args],
        addresses: client_e2ee_addrs,
        mtu: Some(args.mtu.saturating_sub(80)),
        ..Default::default()
    })?;

    let mut client_peer_relay = client_config_relay.as_peer()?;
    if let Some(endpoint) = &args.endpoint {
        client_peer_relay.set_endpoint(endpoint)?;
    }

    let mut client_peer_e2ee = client_config_e2ee.as_peer()?;
    let relay_ip = client_config_relay
        .addresses()
        .first()
        .map(|net| net.addr())
        .ok_or_else(|| anyhow!("client relay address missing"))?;
    client_peer_e2ee.set_endpoint(&format!("{}:{}", relay_ip, constants::DEFAULT_E2EE_PORT))?;

    server_config_relay.add_peer(client_peer_relay);
    server_config_e2ee.add_peer(client_peer_e2ee);

    if args.mtu != constants::DEFAULT_MTU {
        server_config_relay.set_mtu(args.mtu)?;
    }

    if !args.localhost_ip.is_empty() {
        server_config_relay.set_localhost_ip(&args.localhost_ip)?;
    }

    let mut relay_output = find_available_filename(&args.relay_output);
    let e2ee_output = find_available_filename(&args.e2ee_output);
    let server_output = find_available_filename(&args.server_output);

    if args.simple {
        relay_output = e2ee_output.clone();
    }

    let file_status_relay = write_secure_file(&relay_output, &client_config_relay.as_file())
        .map(|_| format!("{} {}", "config:".bold().green(), relay_output.green()))
        .unwrap_or_else(|err| format!("{} {}", "config:".bold().red(), err.to_string().red()));

    let file_status_e2ee = if args.simple {
        None
    } else {
        Some(
            write_secure_file(&e2ee_output, &client_config_e2ee.as_file())
                .map(|_| format!("{} {}", "config:".bold().green(), e2ee_output.green()))
                .unwrap_or_else(|err| {
                    format!("{} {}", "config:".bold().red(), err.to_string().red())
                }),
        )
    };

    let server_command_posix = create_server_command(
        &server_config_relay,
        &server_config_e2ee,
        Shell::Posix,
        args.simple,
        args.disable_ipv6,
    );
    let server_command_powershell = create_server_command(
        &server_config_relay,
        &server_config_e2ee,
        Shell::PowerShell,
        args.simple,
        args.disable_ipv6,
    );

    let server_payload = format!(
        "{}\n\n# POSIX Shell: {}\n\n# Powershell: {}\n",
        create_server_file(&server_config_relay, &server_config_e2ee, args.simple),
        server_command_posix,
        server_command_powershell
    );

    let server_status = write_secure_file(&server_output, &server_payload)
        .map(|_| {
            format!(
                "{} {}",
                "server config:".bold().green(),
                server_output.green()
            )
        })
        .unwrap_or_else(|err| {
            format!(
                "{} {}",
                "server config:".bold().red(),
                err.to_string().red()
            )
        });

    let mut server_config_cmd = format!("./wiretap serve -f {}", server_output);
    if args.disable_ipv6 {
        server_config_cmd.push_str(" --disable-ipv6");
    }

    println!();
    println!("{}", "Configurations successfully generated.".bold());
    println!(
        "Import the config(s) into WireGuard locally and pass the arguments below to Wiretap on the remote machine."
    );
    println!();
    println!("{}", file_status_relay);
    println!("{}", "─".repeat(32).green());
    print!("{}", client_config_relay.as_file().bold());
    println!("{}", "─".repeat(32).green());
    println!();
    if let Some(status) = file_status_e2ee {
        println!("{}", status);
        println!("{}", "─".repeat(32).green());
        print!("{}", client_config_e2ee.as_file().bold());
        println!("{}", "─".repeat(32).green());
        println!();
    }
    println!("{}", server_status);
    println!();
    println!("{}", "server command:".bold().green());
    println!("{} {}", "POSIX Shell:".cyan(), server_command_posix.green());
    println!(
        "{} {}",
        "PowerShell:".cyan(),
        server_command_powershell.green()
    );
    println!("{} {}", "Config File:".cyan(), server_config_cmd.green());
    println!();

    if args.clipboard {
        let status = match clipboard::copy_to_clipboard(&server_command_posix) {
            Ok(()) => format!(
                "{} {}",
                "clipboard:".bold().green(),
                "successfully copied".green()
            ),
            Err(err) => format!(
                "{} {}",
                "clipboard:".bold().red(),
                format!("error copying to clipboard: {err}").red()
            ),
        };
        println!("{status}");
        println!();
    }

    Ok(())
}

fn serve(args: ServeArgs) -> Result<()> {
    let file_contents = if let Some(path) = &args.config_file {
        Some(std::fs::read_to_string(path)?)
    } else {
        None
    };

    let env = crate::serve::ServerEnv::from_env();
    let config = crate::serve::load_server_config(file_contents.as_deref(), &env)?;
    let api_addr = match args.api {
        Some(addr) => Some(addr.parse()?),
        None => None,
    };
    let disable_ipv6 = args.disable_ipv6 || env.get_bool("WIRETAP_DISABLEIPV6").unwrap_or(false);
    let allocation_state_path = crate::serve::resolve_allocation_state_path(&env);
    let options = crate::serve::ServeOptions {
        simple: args.simple,
        quiet: args.quiet,
        api_addr,
        api_port: args.api_port,
        disable_ipv6,
        delete_config: args.delete_config,
        wireguard_keepalive_secs: args.keepalive,
        completion_timeout_ms: args.completion_timeout_ms,
        conn_timeout_ms: args.conn_timeout_ms,
        keepalive_idle_secs: args.keepalive_idle_secs,
        keepalive_interval_secs: args.keepalive_interval_secs,
        keepalive_count: args.keepalive_count,
        udp_timeout_secs: args.udp_timeout_secs,
        allocation_state_path,
    };
    let config = crate::serve::apply_serve_options(config, options.clone())?;

    if args.delete_config {
        if let Some(path) = &args.config_file {
            crate::serve::delete_config_file(path)?;
        }
    }

    if !args.quiet {
        println!(
            "{}",
            "Server config loaded. Starting userspace loop.".green()
        );
    }
    crate::serve::run_loop(&config, None, &options)
}

fn status(args: StatusArgs) -> Result<()> {
    let relay_path = args
        .relay
        .unwrap_or_else(|| constants::DEFAULT_CONFIG_RELAY.to_string());
    let e2ee_path = args
        .e2ee
        .unwrap_or_else(|| constants::DEFAULT_CONFIG_E2EE.to_string());
    let relay_contents = std::fs::read_to_string(&relay_path)?;
    let e2ee_contents = std::fs::read_to_string(&e2ee_path)?;
    let summary = crate::status::StatusSummary::from_configs(&relay_contents, &e2ee_contents)?;
    let relay_config = crate::peer::parse_config(&relay_contents)?;
    let client_relay_addr = relay_config.addresses().first().map(|net| net.addr());
    println!();
    println!("{}", "Wiretap Network Status".bold());
    println!(
        "client relay: {}...",
        &summary.client_relay_public[..8.min(summary.client_relay_public.len())]
    );
    println!(
        " client e2ee: {}...",
        &summary.client_e2ee_public[..8.min(summary.client_e2ee_public.len())]
    );
    println!();

    if summary.servers.is_empty() {
        println!("{}", "No servers found in e2ee config.".yellow());
        return Ok(());
    }

    let mut relay_infos = vec![None; summary.servers.len()];
    let mut relay_addrs: Vec<Vec<std::net::IpAddr>> = vec![Vec::new(); summary.servers.len()];
    let mut localhost_ips: Vec<Option<std::net::Ipv4Addr>> = vec![None; summary.servers.len()];
    let mut interface_infos: Vec<Option<Vec<crate::transport::api::HostInterface>>> =
        vec![None; summary.servers.len()];
    let mut interface_errors: Vec<Option<String>> = vec![None; summary.servers.len()];
    let mut errors = Vec::new();

    for (idx, server) in summary.servers.iter().enumerate() {
        let Some(api) = server.api else {
            errors.push(format!(
                "{}: missing api addr",
                server
                    .nickname
                    .as_deref()
                    .unwrap_or(&server.public_key[..8.min(server.public_key.len())])
            ));
            continue;
        };
        let socket = SocketAddr::new(api, constants::API_PORT);
        match crate::api::server_info(socket) {
            Ok((relay, _e2ee)) => {
                relay_addrs[idx] = relay.addresses().iter().map(|net| net.addr()).collect();
                localhost_ips[idx] = relay.localhost_ip();
                relay_infos[idx] = Some(relay);
            }
            Err(err) => {
                errors.push(format!(
                    "{}: {}",
                    server
                        .nickname
                        .as_deref()
                        .unwrap_or(&server.public_key[..8.min(server.public_key.len())]),
                    err
                ));
            }
        }

        if args.network_info {
            match crate::api::server_interfaces(socket) {
                Ok(ifaces) => {
                    interface_infos[idx] = Some(ifaces);
                }
                Err(err) => {
                    interface_errors[idx] = Some(err.to_string());
                }
            }
        }
    }

    let mut parents = vec![None; summary.servers.len()];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); summary.servers.len()];

    if let Some(client_addr) = client_relay_addr {
        for (idx, relay) in relay_infos.iter().enumerate() {
            let Some(relay) = relay else { continue };
            for peer in relay.peers() {
                if peer
                    .allowed_ips()
                    .iter()
                    .any(|net| net.contains(&client_addr))
                {
                    continue;
                }
                for (child_idx, addrs) in relay_addrs.iter().enumerate() {
                    if child_idx == idx {
                        continue;
                    }
                    if parents[child_idx].is_some() {
                        continue;
                    }
                    if addrs
                        .iter()
                        .any(|addr| peer.allowed_ips().iter().any(|net| net.contains(addr)))
                    {
                        parents[child_idx] = Some(idx);
                        children[idx].push(child_idx);
                    }
                }
            }
        }
    }

    let mut printed = vec![false; summary.servers.len()];
    let mut roots = Vec::new();
    for idx in 0..summary.servers.len() {
        if relay_infos[idx].is_some() && parents[idx].is_none() {
            roots.push(idx);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn print_server(
        idx: usize,
        depth: usize,
        summary: &crate::status::StatusSummary,
        localhost_ips: &[Option<std::net::Ipv4Addr>],
        interface_infos: &[Option<Vec<crate::transport::api::HostInterface>>],
        interface_errors: &[Option<String>],
        children: &[Vec<usize>],
        network_info: bool,
        printed: &mut [bool],
    ) {
        let server = &summary.servers[idx];
        let indent = "  ".repeat(depth);
        println!("{}server", indent);
        if let Some(nickname) = &server.nickname {
            println!("{} nickname: {}", indent, nickname);
        }
        println!(
            "{}     e2ee: {}...",
            indent,
            &server.public_key[..8.min(server.public_key.len())]
        );
        if let Some(api) = server.api {
            println!("{}      api: {}", indent, api);
        }
        if let Some(localhost) = localhost_ips[idx] {
            println!("{} localhost: {}", indent, localhost);
        }
        if !server.routes.is_empty() {
            let routes = server
                .routes
                .iter()
                .map(|net| net.to_string())
                .collect::<Vec<_>>()
                .join(",");
            println!("{}   routes: {}", indent, routes);
        }
        if network_info {
            if let Some(ifaces) = interface_infos[idx].as_ref() {
                if ifaces.is_empty() {
                    println!("{} interfaces: none", indent);
                } else {
                    for iface in ifaces {
                        let addrs = iface.addrs.join(", ");
                        println!("{} interface: {} ({})", indent, iface.name, addrs);
                    }
                }
            } else if let Some(err) = interface_errors[idx].as_ref() {
                println!("{} interfaces: error ({})", indent, err);
            } else {
                println!("{} interfaces: unavailable", indent);
            }
        }
        println!();
        printed[idx] = true;
        for child in &children[idx] {
            print_server(
                *child,
                depth + 1,
                summary,
                localhost_ips,
                interface_infos,
                interface_errors,
                children,
                network_info,
                printed,
            );
        }
    }

    if roots.is_empty() {
        for (idx, server) in summary.servers.iter().enumerate() {
            if printed[idx] {
                continue;
            }
            println!("server");
            if let Some(nickname) = &server.nickname {
                println!(" nickname: {}", nickname);
            }
            println!(
                "     e2ee: {}...",
                &server.public_key[..8.min(server.public_key.len())]
            );
            if let Some(api) = server.api {
                println!("      api: {}", api);
            }
            if !server.routes.is_empty() {
                let routes = server
                    .routes
                    .iter()
                    .map(|net| net.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!("   routes: {}", routes);
            }
            println!();
        }
    } else {
        for root in roots {
            print_server(
                root,
                0,
                &summary,
                &localhost_ips,
                &interface_infos,
                &interface_errors,
                &children,
                args.network_info,
                &mut printed,
            );
        }
    }

    for idx in 0..summary.servers.len() {
        if !printed[idx] && relay_infos[idx].is_some() {
            print_server(
                idx,
                0,
                &summary,
                &localhost_ips,
                &interface_infos,
                &interface_errors,
                &children,
                args.network_info,
                &mut printed,
            );
        }
    }

    if !errors.is_empty() {
        println!("{}", "Peers with Errors".bold());
        for err in errors {
            println!(" - {}", err);
        }
        println!();
    }

    Ok(())
}

fn add(args: AddArgs) -> Result<()> {
    match args.command {
        AddCommand::Server(args) => add_server(args),
        AddCommand::Client(args) => add_client(args),
    }
}

fn add_server(args: AddServerCliArgs) -> Result<()> {
    if args.endpoint.is_some() && args.outbound_endpoint.is_some() {
        return Err(anyhow!(
            "cannot specify both --endpoint and --outbound-endpoint"
        ));
    }
    if args.endpoint.is_none() && args.outbound_endpoint.is_none() && args.server_address.is_none()
    {
        return Err(anyhow!(
            "must specify --endpoint or --outbound-endpoint or --server-address"
        ));
    }

    let relay_contents = std::fs::read_to_string(&args.relay_input)?;
    let e2ee_contents = std::fs::read_to_string(&args.e2ee_input)?;

    let plan = if let Some(server_addr) = &args.server_address {
        let api_ip = crate::add::resolve_server_address(&e2ee_contents, server_addr)?;
        let api_socket = SocketAddr::new(api_ip, args.api_port);

        let (leaf_relay, _leaf_e2ee) = crate::api::server_info(api_socket)?;
        let allocation = crate::api::allocate(api_socket, crate::transport::api::PeerType::Server)?;

        let api_plan = crate::add::build_add_server_plan_with_api(
            &relay_contents,
            &e2ee_contents,
            &leaf_relay,
            &allocation,
            &crate::add::AddServerArgs {
                endpoint: args.endpoint.clone().unwrap_or_default(),
                routes: args.routes.clone(),
                outbound_endpoint: args.outbound_endpoint.clone(),
                port: args.port,
                keepalive: args.keepalive,
                server_address: args.server_address.clone(),
                localhost_ip: args.localhost_ip.clone(),
                nickname: args.nickname.clone(),
                disable_ipv6: args.disable_ipv6,
            },
        )?;

        crate::api::add_peer(
            api_socket,
            crate::transport::api::InterfaceType::Relay,
            api_plan.server_relay_peer.clone(),
        )?;

        let client_e2ee = crate::peer::parse_config(&e2ee_contents)?;
        let leaf_relay_addr = leaf_relay
            .addresses()
            .first()
            .map(|net| net.addr())
            .ok_or_else(|| anyhow!("leaf relay config missing address"))?;
        let new_allowed_ips = api_plan
            .server_relay_peer
            .allowed_ips()
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>();

        for peer in client_e2ee.peers() {
            let Some(peer_api) = peer.api_addr() else {
                continue;
            };
            if peer_api == api_ip || peer_api == allocation.api_addr {
                continue;
            }
            let peer_api_socket = SocketAddr::new(peer_api, args.api_port);
            let (relay_config, _e2ee_config) = match crate::api::server_info(peer_api_socket) {
                Ok(configs) => configs,
                Err(err) => {
                    eprintln!("failed to query server info: {}", err);
                    continue;
                }
            };

            let mut updated = false;
            for relay_peer in relay_config.peers() {
                if relay_peer
                    .allowed_ips()
                    .iter()
                    .any(|net| net.contains(&leaf_relay_addr))
                {
                    crate::api::add_allowed_ips(
                        peer_api_socket,
                        &relay_peer.public_key().to_string(),
                        &new_allowed_ips,
                    )?;
                    updated = true;
                    break;
                }
            }
            if !updated {
                return Err(anyhow!("peer's relay interface has no leaf-facing route"));
            }
        }

        api_plan.plan
    } else {
        crate::add::build_add_server_plan(
            &relay_contents,
            &e2ee_contents,
            &crate::add::AddServerArgs {
                endpoint: args.endpoint.clone().unwrap_or_default(),
                routes: args.routes.clone(),
                outbound_endpoint: args.outbound_endpoint.clone(),
                port: args.port,
                keepalive: args.keepalive,
                server_address: args.server_address.clone(),
                localhost_ip: args.localhost_ip.clone(),
                nickname: args.nickname.clone(),
                disable_ipv6: args.disable_ipv6,
            },
        )?
    };

    let file_status_relay = if args.server_address.is_none() {
        Some(
            write_secure_file(&args.relay_input, &plan.client_relay_update)
                .map(|_| format!("{} {}", "config:".bold().green(), args.relay_input.green()))
                .unwrap_or_else(|err| {
                    format!("{} {}", "config:".bold().red(), err.to_string().red())
                }),
        )
    } else {
        None
    };

    let file_status_e2ee = write_secure_file(&args.e2ee_input, &plan.client_e2ee_update)
        .map(|_| format!("{} {}", "config:".bold().green(), args.e2ee_input.green()))
        .unwrap_or_else(|err| format!("{} {}", "config:".bold().red(), err.to_string().red()));

    let server_output = find_available_filename(&args.server_output);
    let server_payload = format!(
        "{}\n\n# POSIX Shell: {}\n\n# Powershell: {}\n",
        plan.server_relay_config, plan.server_command_posix, plan.server_command_powershell
    );

    let file_status_server = write_secure_file(&server_output, &server_payload)
        .map(|_| {
            format!(
                "{} {}",
                "server config:".bold().green(),
                server_output.green()
            )
        })
        .unwrap_or_else(|err| {
            format!(
                "{} {}",
                "server config:".bold().red(),
                err.to_string().red()
            )
        });

    let mut server_config_cmd = format!("./wiretap serve -f {}", server_output);
    if args.disable_ipv6 {
        server_config_cmd.push_str(" --disable-ipv6");
    }

    println!();
    println!("{}", "Configurations successfully generated.".bold());
    println!(
        "Import the updated config(s) into WireGuard locally and pass the arguments below to Wiretap on the new remote server."
    );
    if let Some(file_status_relay) = file_status_relay {
        println!();
        println!("{}", file_status_relay);
        println!("{}", "─".repeat(32).green());
        print!("{}", plan.client_relay_update.bold());
        println!("{}", "─".repeat(32).green());
        println!();
    }
    println!("{}", file_status_e2ee);
    println!("{}", "─".repeat(32).green());
    print!("{}", plan.client_e2ee_update.bold());
    println!("{}", "─".repeat(32).green());
    println!();
    println!("{}", file_status_server);
    println!();
    println!(
        "{} {}",
        "POSIX Shell:".cyan(),
        plan.server_command_posix.green()
    );
    println!(
        "{} {}",
        "PowerShell:".cyan(),
        plan.server_command_powershell.green()
    );
    println!("{} {}", "Config File:".cyan(), server_config_cmd.green());
    println!();

    if args.clipboard {
        let status = match clipboard::copy_to_clipboard(&plan.server_command_posix) {
            Ok(()) => format!(
                "{} {}",
                "clipboard:".bold().green(),
                "successfully copied".green()
            ),
            Err(err) => format!(
                "{} {}",
                "clipboard:".bold().red(),
                format!("error copying to clipboard: {err}").red()
            ),
        };
        println!("{status}");
        println!();
    }

    Ok(())
}

fn add_client(args: AddClientCliArgs) -> Result<()> {
    if args.endpoint.is_some() && args.outbound_endpoint.is_some() {
        return Err(anyhow!(
            "cannot specify both --endpoint and --outbound-endpoint"
        ));
    }
    if args.endpoint.is_none() && args.outbound_endpoint.is_none() {
        return Err(anyhow!("must specify --endpoint or --outbound-endpoint"));
    }

    let relay_contents = std::fs::read_to_string(&args.relay_input)?;
    let e2ee_contents = std::fs::read_to_string(&args.e2ee_input)?;

    let plan = if let Some(server_addr) = &args.server_address {
        let api_ip = crate::add::resolve_server_address(&e2ee_contents, server_addr)?;
        let api_socket = SocketAddr::new(api_ip, args.api_port);

        let (leaf_relay, _leaf_e2ee) = crate::api::server_info(api_socket)?;
        let allocation = crate::api::allocate(api_socket, crate::transport::api::PeerType::Client)?;

        let api_plan = crate::add::build_add_client_plan_with_api(
            &relay_contents,
            &e2ee_contents,
            &leaf_relay,
            &allocation,
            &crate::add::AddClientApiArgs {
                endpoint: args.endpoint.clone(),
                outbound_endpoint: args.outbound_endpoint.clone(),
                port: args.port,
                keepalive: args.keepalive,
                disable_ipv6: args.disable_ipv6,
            },
        )?;

        let base_relay = crate::peer::parse_config(&relay_contents)?;
        let base_e2ee = crate::peer::parse_config(&e2ee_contents)?;
        let base_relay_pub = base_relay.public_key().to_string();

        for peer in base_e2ee.peers() {
            let Some(peer_api) = peer.api_addr() else {
                continue;
            };
            let peer_socket = SocketAddr::new(peer_api, args.api_port);
            let (relay_config, _e2ee_config) = match crate::api::server_info(peer_socket) {
                Ok(configs) => configs,
                Err(err) => {
                    eprintln!("failed to query server info: {}", err);
                    continue;
                }
            };

            crate::api::add_peer(
                peer_socket,
                crate::transport::api::InterfaceType::E2EE,
                api_plan.client_e2ee_peer.clone(),
            )?;

            let is_relay = if args.server_address.is_none() {
                relay_config
                    .peers()
                    .iter()
                    .any(|rp| rp.public_key().to_string() == base_relay_pub)
            } else {
                peer_api == api_ip
            };

            if is_relay {
                crate::api::add_peer(
                    peer_socket,
                    crate::transport::api::InterfaceType::Relay,
                    api_plan.client_relay_peer.clone(),
                )?;
            } else {
                let mut updated = false;
                let new_allowed = api_plan
                    .client_relay_peer
                    .allowed_ips()
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>();
                for relay_peer in relay_config.peers() {
                    if relay_peer
                        .allowed_ips()
                        .iter()
                        .any(|net| net.contains(&api_plan.leaf_addr))
                    {
                        crate::api::add_allowed_ips(
                            peer_socket,
                            &relay_peer.public_key().to_string(),
                            &new_allowed,
                        )?;
                        updated = true;
                        break;
                    }
                }
                if !updated {
                    return Err(anyhow!("peer's relay interface has no client-facing route"));
                }
            }
        }

        api_plan.plan
    } else {
        let endpoint = args
            .outbound_endpoint
            .clone()
            .or_else(|| args.endpoint.clone())
            .ok_or_else(|| anyhow!("endpoint required"))?;
        crate::add::build_add_client_plan(
            &relay_contents,
            &e2ee_contents,
            &crate::add::AddClientArgs {
                endpoint,
                port: args.port,
                disable_ipv6: args.disable_ipv6,
            },
        )?
    };

    let relay_output = find_available_filename(&args.relay_output);
    let e2ee_output = find_available_filename(&args.e2ee_output);

    let file_status_relay = write_secure_file(&relay_output, &plan.relay_config)
        .map(|_| format!("{} {}", "config:".bold().green(), relay_output.green()))
        .unwrap_or_else(|err| format!("{} {}", "config:".bold().red(), err.to_string().red()));

    let file_status_e2ee = write_secure_file(&e2ee_output, &plan.e2ee_config)
        .map(|_| format!("{} {}", "config:".bold().green(), e2ee_output.green()))
        .unwrap_or_else(|err| format!("{} {}", "config:".bold().red(), err.to_string().red()));

    println!();
    println!("{}", "Configurations successfully generated.".bold());
    println!("Have a friend import these files into WireGuard");
    println!();
    println!("{}", file_status_relay);
    println!("{}", "─".repeat(32).green());
    print!("{}", plan.relay_config.bold());
    println!("{}", "─".repeat(32).green());
    println!();
    println!("{}", file_status_e2ee);
    println!("{}", "─".repeat(32).green());
    print!("{}", plan.e2ee_config.bold());
    println!("{}", "─".repeat(32).green());
    println!();

    Ok(())
}

fn expose(args: ExposeArgs) -> Result<()> {
    let common = match &args.command {
        Some(ExposeCommand::List(list)) => &list.common,
        Some(ExposeCommand::Remove(remove)) => &remove.common,
        None => &args.common,
    };

    let api_addrs = crate::expose::resolve_api_addrs(&common.config, &common.server_address)?;
    let request = crate::expose::validate_expose_request(
        api_addrs,
        common.api_port,
        common.local_port,
        common.remote_port,
        &common.protocol,
        common.dynamic,
    )?;

    let mode = match &args.command {
        Some(ExposeCommand::List(_)) => crate::expose::ExposeMode::List,
        Some(ExposeCommand::Remove(_)) => crate::expose::ExposeMode::Remove,
        None => crate::expose::ExposeMode::Expose,
    };

    crate::expose::run_expose(mode, &request)
}

fn ping(args: PingArgs) -> Result<()> {
    let api: std::net::IpAddr = args.api.parse()?;
    let socket = SocketAddr::new(api, args.api_port);
    match crate::ping::run_ping(socket) {
        Ok(resp) => {
            println!("{}", format!("response: {}", resp.message).green());
            println!("  from: {}", socket);
            println!("  time: {:.3} ms", resp.duration.as_secs_f64() * 1000.0);
        }
        Err(err) => {
            println!("{}", format!("ping failed: {}", err).yellow());
        }
    };
    Ok(())
}

fn port_from_endpoint(endpoint: &str) -> Result<u16> {
    if let Ok(addr) = SocketAddr::from_str(endpoint) {
        return Ok(addr.port());
    }

    if endpoint.starts_with('[') {
        if let Some(end) = endpoint.find(']') {
            let rest = &endpoint[end + 1..];
            let port = rest.trim_start_matches(':').parse::<u16>()?;
            return Ok(port);
        }
    }

    let parts: Vec<&str> = endpoint.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("invalid endpoint"));
    }
    Ok(parts[0].parse::<u16>()?)
}

fn subnet_from_host(host: &str, prefix: u8) -> Result<Ipv4Net> {
    let ipnet = Ipv4Net::from_str(host)?;
    let ip = ipnet.addr();
    let masked = constants::mask_prefix_v4(ip, prefix);
    Ipv4Net::new(masked, prefix).map_err(|err| anyhow!("invalid subnet: {err}"))
}

fn subnet_v6_from_host(host: &str, prefix: u8) -> Result<Ipv6Net> {
    let ipnet = Ipv6Net::from_str(host)?;
    let ip = ipnet.addr();
    let masked = constants::mask_prefix_v6(ip, prefix);
    Ipv6Net::new(masked, prefix).map_err(|err| anyhow!("invalid subnet: {err}"))
}

fn write_secure_file(path: &str, contents: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn default_api_v6() -> String {
    format!("{}/128", constants::default_api_v6())
}

fn default_api_v4() -> String {
    format!("{}/32", constants::default_api_v4())
}

fn default_client_relay_v4() -> String {
    format!("{}/32", constants::default_client_relay_v4())
}

fn default_client_relay_v6() -> String {
    format!("{}/128", constants::default_client_relay_v6())
}

fn default_client_e2ee_v4() -> String {
    format!("{}/32", constants::default_client_e2ee_v4())
}

fn default_client_e2ee_v6() -> String {
    format!("{}/128", constants::default_client_e2ee_v6())
}

fn default_server_relay_v4() -> String {
    format!("{}/32", constants::default_server_relay_v4())
}

fn default_server_relay_v6() -> String {
    format!("{}/128", constants::default_server_relay_v6())
}

fn default_ping_api() -> String {
    constants::default_api_v6().to_string()
}

fn default_api_port() -> u16 {
    constants::API_PORT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn show_hidden_help_reveals_hidden_flags() {
        let mut cmd = build_cli_command(true);
        let add = cmd
            .find_subcommand_mut("add")
            .and_then(|cmd| cmd.find_subcommand_mut("server"))
            .expect("add server command");
        let help = add.render_long_help().to_string();
        assert!(help.contains("--relay-input"));

        let mut cmd = build_cli_command(false);
        let add = cmd
            .find_subcommand_mut("add")
            .and_then(|cmd| cmd.find_subcommand_mut("server"))
            .expect("add server command");
        let help = add.render_long_help().to_string();
        assert!(!help.contains("--relay-input"));
    }

    #[test]
    fn configure_simple_mode_includes_api_addr_on_relay_interface() {
        let temp_dir = std::env::temp_dir().join(format!(
            "wiretap_rs_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).expect("temp dir");

        let relay_output = temp_dir.join("relay.conf");
        let e2ee_output = temp_dir.join("e2ee.conf");
        let server_output = temp_dir.join("server.conf");

        let args = ConfigureArgs {
            routes: vec!["10.0.0.0/24".to_string()],
            endpoint: Some("10.0.0.2:51820".to_string()),
            outbound_endpoint: None,
            port: None,
            sport: None,
            nickname: String::new(),
            relay_output: relay_output.to_string_lossy().to_string(),
            e2ee_output: e2ee_output.to_string_lossy().to_string(),
            server_output: server_output.to_string_lossy().to_string(),
            clipboard: false,
            simple: true,
            api_addr: "192.0.2.10/32".to_string(),
            keepalive: constants::DEFAULT_KEEPALIVE,
            mtu: constants::DEFAULT_MTU,
            disable_ipv6: true,
            client_addr4_relay: default_client_relay_v4(),
            client_addr6_relay: default_client_relay_v6(),
            client_addr4_e2ee: default_client_e2ee_v4(),
            client_addr6_e2ee: default_client_e2ee_v6(),
            server_addr4_relay: default_server_relay_v4(),
            server_addr6_relay: default_server_relay_v6(),
            localhost_ip: String::new(),
            generate_psk: false,
        };

        configure(args).expect("configure");
        let server_contents = fs::read_to_string(&server_output).expect("read server config");
        assert!(server_contents.contains("IPv4 = 192.0.2.10"));

        fs::remove_dir_all(&temp_dir).ok();
    }
}
