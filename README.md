# wiretap-rs

Rust port of **wiretap**, a user-space WireGuard relay/proxy system that lets clients route traffic into a target network through a chain of servers. The goal is functional parity with the original Go implementation while staying idiomatic Rust and test-driven.

## What this is

Wiretap runs a **relay** WireGuard interface and an optional nested **E2EE** WireGuard interface entirely in user space. It terminates WireGuard tunnels and forwards traffic into the host network using a userspace TCP/UDP stack (smoltcp) plus OS sockets. A small HTTP API manages peer allocation, topology introspection, and port exposure.

## How it works (high level)

- Relay WG tunnel: transports packets between peers over UDP.
- Optional E2EE WG tunnel: nested over the relay tunnel for end-to-end encryption.
- Userspace data path:
  - TCP/UDP packets are handled by smoltcp and bridged to OS TcpStream/UdpSocket.
  - ICMP echo is handled by crafting replies when the system ping succeeds.
- API over tunnel: the HTTP API is served via the tunnel address, not a host-bound socket.
- Expose: TCP/UDP/Dynamic (SOCKS5) exposure is implemented via the API and routed through the tunnel.

## Getting started

### Prerequisites

- Rust toolchain (stable)
- A WireGuard client on your workstation (for example, wg-quick)
- UDP ports open on the server (default 51820 for relay, 51821 for E2EE)
- ping binary available if you need ICMP echo handling

### Build and test

```bash
cargo build
cargo test
```

The binary is emitted at `target/debug/wiretap-rs` (or `target/release/wiretap-rs` for release builds). Add it to your PATH or run it from the project root.

### Generate configs

configure emits client configs and a server config file.

Default ports are 51820 (relay) and 51821 (E2EE). You can override the server relay port with `--sport` or by setting the port in `--endpoint`/`--outbound-endpoint`.

Typical inbound (client connects to server):

```bash
wiretap-rs configure \
  --endpoint 203.0.113.10:<server-port-number> \
  --routes 10.0.0.0/24 \
  --server-output wiretap_server.conf
```

Simple mode (relay only, single client config):

```bash
wiretap-rs configure \
  --endpoint 203.0.113.10:<server-port-number> \
  --routes 10.0.0.0/24 \
  --simple
```

### Run the server

```bash
wiretap-rs serve -f wiretap_server.conf
```

Quiet mode (no console output or log files):

```bash
wiretap-rs serve -f wiretap_server.conf --quiet
```

### Bring up the client

- Normal mode: bring up relay **first**, then E2EE (both configs are required)
  ```bash
  wg-quick up wiretap_relay.conf
  wg-quick up wiretap.conf
  ```

- Simple mode: only one config
  ```bash
  wg-quick up wiretap.conf
  ```

### Expose / Ping / Status / Add

These are wired to the API (over the tunnel):

```bash
wiretap-rs expose --help
wiretap-rs ping --server-address ::2
wiretap-rs status --help
wiretap-rs add --help
```

## Manual test walkthrough

Use this sequence to validate a fresh setup end-to-end.

### 1) Generate configs

```bash
wiretap-rs configure \
  --endpoint <server-public-ip>:<server-port-number> \
  --routes 10.0.0.0/24 \
  --server-output wiretap_server.conf
```

Outputs:
- `wiretap_relay.conf` (client relay config)
- `wiretap.conf` (client E2EE config)
- `wiretap_server.conf` (server config)

### 2) Copy server config to the server

```bash
scp wiretap_server.conf user@<server-public-ip>:/path/to/wiretap_server.conf
```

### 3) Start the server

```bash
wiretap-rs serve -f /path/to/wiretap_server.conf
```

### 4) Bring up the client tunnels

Normal mode (relay first, then E2EE):

```bash
wg-quick up wiretap_relay.conf
wg-quick up wiretap.conf
```

Simple mode:

```bash
wg-quick up wiretap.conf
```

### 5) Confirm WireGuard handshakes

```bash
wg show wiretap_relay
wg show wiretap
```

### 6) Test the API over the tunnel

- IPv6 default API:
  ```bash
  curl http://[::2]/ping
  ```
- IPv4 API when IPv6 is disabled:
  ```bash
  curl http://192.0.2.2/ping
  ```

### 7) Test TCP forwarding with localhost mapping

Re-generate configs with a localhost mapping:

```bash
wiretap-rs configure \
  --outbound-endpoint <server-public-ip>:<server-port-number> \
  --routes 10.0.0.0/24 \
  --localhost-ip 10.0.0.123
```

On the server:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

From the client:

```bash
curl http://10.0.0.123:8080
```

### 8) Tear down

```bash
wg-quick down wiretap.conf
wg-quick down wiretap_relay.conf
```

## Current limitations (port status)

- Userspace only: no kernel WG interface or OS-level routing changes are made; traffic is proxied in user space.
- Protocol coverage: TCP/UDP/ICMP echo are supported; other protocols are not.
- API security: the API is unauthenticated (matches Go reference).
- Netstack differences: smoltcp behavior differs from gVisor; expect edge-case differences in TCP/UDP handling.
- Operational ergonomics: no systemd units, no automatic firewall/NAT setup.

If you need strict Go-level behavior, use the tests under tests/ as the source of truth for parity and open gaps.

## Logging

`wiretap-rs` uses structured logging via `tracing`.

Defaults:
- Debug builds write logs to `./logs/wiretap-<epoch>.log` and also log to stdout.
- Release builds log to stdout only.

Overrides (all optional):
- `WIRETAP_LOG_FILE=/path/to/file.log` (explicit log file)
- `WIRETAP_LOG_DIR=/path/to/dir` (directory for log file)
- `WIRETAP_LOG_LEVEL=info|debug|trace` (or `RUST_LOG`)
- `WIRETAP_QUIET=1` (disable stdout logging; equivalent to `--quiet`)

## Project layout

- src/ - Rust implementation
- reference/ - Original Go implementation
- tests/ - Rust tests (parity and behavior)
- development_documentation/ - specification and porting progress

## Contributing

This port prioritizes test-driven parity with the Go reference. If you add behavior, add tests and update development_documentation/porting_progress.md.
