# wiretap-rs

[![Release](https://img.shields.io/github/v/release/0xTriboulet/wiretap-rs)](https://github.com/0xTriboulet/wiretap-rs/releases)
[![Build Status](https://github.com/0xTriboulet/wiretap-rs/workflows/Rust/badge.svg)](https://github.com/0xTriboulet/wiretap-rs/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**wiretap-rs** is a Rust port of [Wiretap](https://github.com/sandialabs/wiretap), a transparent, VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.

This project aims to achieve functional parity with the original Go implementation while maintaining idiomatic Rust code and a test-driven development approach. The implementation works both as a library that can be integrated into other Rust projects via `cargo add wiretap-rs`, and as a stand-alone command-line application.

## Overview

Wiretap is a transparent, VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.

In this diagram, the Client has generated and installed WireGuard configuration files that will route traffic destined for `10.0.0.0/24` through a WireGuard interface. Wiretap is then deployed to the Server with a configuration that connects to the Client as a WireGuard peer. The Client can then interact with local network resources as if on the same network as the Server, and optionally chain additional Servers to reach new networks. Access to the Wiretap network can also be shared with other Clients.

### Terminology

**Wiretap Server**: A machine where the Wiretap binary is running the `serve` command. Servers receive and relay network traffic on behalf of Wiretap Clients, acting like a VPN "exit node."

**Wiretap Client**: A machine running the [WireGuard](https://www.wireguard.com/) configurations necessary to send and receive network traffic through a Wiretap Server. It functions much like a client in a VPN connection. Clients are also able to reconfigure parts of the Wiretap network dynamically using the Wiretap binary.

> **Important:** Unlike the typical use of "client" and "server" terms in networking, Wiretap's Client and Server terms have nothing to do with which machine listens for or initiates the initial connection.

### How it Works

Wiretap runs a **relay** WireGuard interface and an optional nested **E2EE** (End-to-End Encrypted) WireGuard interface entirely in user space. It terminates WireGuard tunnels and forwards traffic into the host network using a userspace TCP/UDP stack (smoltcp) plus OS sockets. A small HTTP API manages peer allocation, topology introspection, and port exposure.

**Key Components:**
- **Relay WireGuard tunnel**: Transports packets between peers over UDP
- **E2EE WireGuard tunnel**: Nested over the relay tunnel for end-to-end encryption
- **Userspace data path**: 
  - TCP/UDP packets are handled by smoltcp and bridged to OS TcpStream/UdpSocket
  - ICMP echo is handled by crafting replies when the system ping succeeds
- **API over tunnel**: The HTTP API is served via the tunnel address, not a host-bound socket
- **Expose**: TCP/UDP/Dynamic (SOCKS5) exposure is implemented via the API and routed through the tunnel

## Installation

### Pre-built Binaries

Download pre-built binaries for your platform from the [Releases page](https://github.com/0xTriboulet/wiretap-rs/releases).

Available platforms:
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows (x86_64)

### Building from Source

**Prerequisites:** Rust toolchain (stable). Install from [https://rustup.rs/](https://rustup.rs/)

```bash
# Clone the repository
git clone https://github.com/0xTriboulet/wiretap-rs.git
cd wiretap-rs

# Build the project
cargo build --release

# The binary will be at target/release/wiretap-rs
```

### Using as a Library

Add wiretap-rs to your Rust project:

```bash
cargo add wiretap-rs
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
wiretap-rs = "0.1"
```

## Getting Started

### Prerequisites

**For the Client:**
- [WireGuard](https://www.wireguard.com/install/) installed
- Privileged access to configure WireGuard interfaces (typically root/admin access)

**For the Server:**
- Rust toolchain (stable) if building from source
- Ability to run the Wiretap binary (no special privileges required)
- UDP ports accessible (default: 51820 for relay, 51821 for E2EE)
- `ping` binary available if ICMP echo handling is needed

**Environment Requirements:**
- Bidirectional UDP communication between Server and Client on at least one port
- Any firewalls between them must allow at least one machine to initiate a UDP connection to the other

### Build and Test

```bash
cargo build
cargo test
```

The binary is emitted at `target/debug/wiretap-rs` (or `target/release/wiretap-rs` for release builds). You can add it to your PATH or run it directly from the project root.

### Generate Configuration Files

The `configure` command generates client configurations and a server configuration file.

Default ports are 51820 (relay) and 51821 (E2EE). You can override the server relay port with `--sport` or by setting the port in `--endpoint`/`--outbound-endpoint`.

**Typical inbound connection (Client connects to Server):**

```bash
wiretap-rs configure \
  --endpoint 203.0.113.10:<server-port-number> \
  --routes 10.0.0.0/24 \
  --server-output wiretap_server.conf
```

**Simple mode (relay only, single client configuration):**

```bash
wiretap-rs configure \
  --endpoint 203.0.113.10:<server-port-number> \
  --routes 10.0.0.0/24 \
  --simple
```

### Run the Server

```bash
wiretap-rs serve -f wiretap_server.conf
```

**Quiet mode (no console output or log files):**

```bash
wiretap-rs serve -f wiretap_server.conf --quiet
```

### Bring Up the Client

- **Normal mode**: Bring up relay **first**, then E2EE (both configurations are required)
  ```bash
  wg-quick up wiretap_relay.conf
  wg-quick up wiretap.conf
  ```

- **Simple mode**: Only one configuration
  ```bash
  wg-quick up wiretap.conf
  ```

### API Commands

These commands interact with the API over the tunnel:

```bash
wiretap-rs expose --help
wiretap-rs ping --server-address ::2
wiretap-rs status --help
wiretap-rs add --help
```

## Manual Test Walkthrough

Use this sequence to validate a fresh setup end-to-end.

### 1. Generate Configuration Files

```bash
wiretap-rs configure \
  --endpoint <server-public-ip>:<server-port-number> \
  --routes 10.0.0.0/24 \
  --server-output wiretap_server.conf
```

**Outputs:**
- `wiretap_relay.conf` (client relay configuration)
- `wiretap.conf` (client E2EE configuration)
- `wiretap_server.conf` (server configuration)

### 2. Copy Server Configuration to the Server

```bash
scp wiretap_server.conf user@<server-public-ip>:/path/to/wiretap_server.conf
```

### 3. Start the Server

```bash
wiretap-rs serve -f /path/to/wiretap_server.conf
```

### 4. Bring Up the Client Tunnels

**Normal mode (relay first, then E2EE):**

```bash
wg-quick up wiretap_relay.conf
wg-quick up wiretap.conf
```

**Simple mode:**

```bash
wg-quick up wiretap.conf
```

### 5. Confirm WireGuard Handshakes

```bash
wg show wiretap_relay
wg show wiretap
```

### 6. Test the API Over the Tunnel

- **IPv6 default API:**
  ```bash
  curl http://[::2]/ping
  ```
- **IPv4 API when IPv6 is disabled:**
  ```bash
  curl http://192.0.2.2/ping
  ```

### 7. Test TCP Forwarding with Localhost Mapping

Re-generate configurations with a localhost mapping:

```bash
wiretap-rs configure \
  --outbound-endpoint <server-public-ip>:<server-port-number> \
  --routes 10.0.0.0/24 \
  --localhost-ip 10.0.0.123
```

**On the server:**

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

**From the client:**

```bash
curl http://10.0.0.123:8080
```

### 8. Tear Down

```bash
wg-quick down wiretap.conf
wg-quick down wiretap_relay.conf
```

## Current Limitations

This Rust port is actively being developed to achieve parity with the original Go implementation. Current limitations include:

- **Userspace only**: No kernel WireGuard interface or OS-level routing changes are made; traffic is proxied in user space
- **Protocol coverage**: TCP/UDP/ICMP echo are supported; other protocols are not yet implemented
- **API security**: The API is unauthenticated (matches Go reference implementation)
- **Netstack differences**: smoltcp behavior may differ from gVisor; expect edge-case differences in TCP/UDP handling
- **Operational ergonomics**: No systemd units or automatic firewall/NAT setup

For strict Go-level behavioral compatibility, refer to the tests under `tests/` as the source of truth for parity and open gaps.

## Logging

`wiretap-rs` uses structured logging via `tracing`.

**Defaults:**
- Debug builds write logs to `./logs/wiretap-<epoch>.log` and also log to stdout
- Release builds log to stdout only

**Configuration (all optional):**
- `WIRETAP_LOG_FILE=/path/to/file.log` - Explicit log file path
- `WIRETAP_LOG_DIR=/path/to/dir` - Directory for log file
- `WIRETAP_LOG_LEVEL=info|debug|trace` - Log level (or use `RUST_LOG`)
- `WIRETAP_QUIET=1` - Disable stdout logging (equivalent to `--quiet` flag)

## Project Layout

- `src/` - Rust implementation
- `reference/` - Original Go implementation (for reference)
- `tests/` - Rust integration tests (parity and behavior validation)
- `development_documentation/` - Specification and porting progress notes

## Contributing

This port prioritizes test-driven parity with the original Go reference implementation. If you add new behavior:
1. Add corresponding tests
2. Update `development_documentation/porting_progress.md`

## About the Original Wiretap

This project is based on [Wiretap](https://github.com/sandialabs/wiretap), originally developed by Sandia National Laboratories. The Rust port aims to maintain compatibility and feature parity while leveraging Rust's performance and safety benefits.

For more information about Wiretap's design and capabilities, see the [original project repository](https://github.com/sandialabs/wiretap).
