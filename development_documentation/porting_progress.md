# Wiretap-RS Porting Progress

## Current State
- CLI scaffolded with clap; `configure` is implemented and mirrors the Go reference output/behavior.
- Core WireGuard config models implemented in Rust (`Config`, `PeerConfig`, and key handling).
- Server command/server file generation implemented.
- Added config parsing helpers for WireGuard-style configs and wiretap server config files.
- Added tests for key parsing, config serialization, and config parsing (nickname + endpoint).
- Added server config loading helper (env vs file) with tests.
- Added `serve` CLI wiring to load server config from file/env and start a WireGuard+smoltcp runtime loop.
- `configure` now writes relay server addresses and the E2EE API address into server configs.
- `serve` now starts the HTTP API server (tiny_http) bound to the E2EE API address, with simple-mode fallback to default API address.
- `serve` now drops to simple mode when the E2EE peer key is missing (matches Go behavior).
- `serve` now exposes a `--simple` flag to force relay-only mode.
- `serve` now supports `--api/--api-port` overrides for the placeholder HTTP API binding.
- API `expose` now starts TCP/UDP forwarders and a minimal SOCKS5 handler for `--dynamic`, tracking active listeners for add/remove.
- Added HTTP API test coverage for dynamic SOCKS5 expose round-trips.
- Added CLI parse coverage for `serve` API override flags.
- HTTP API now supports `GET /allocate?type=` and `POST /addpeer?interface=` to match Go routing.
- API addpeer now rejects missing public keys or empty allowed IP lists (matches spec).
- API allocation state now primes (increments) initial addresses on service startup to match Go behavior.
- Status CLI now supports `--network-info` and queries server interfaces via API.
- Status now queries server relay configs to build a basic topology tree and prints peers with API errors.
- Added serve options processing (disable IPv6 filtering) with tests.
- Added delete-config support for server configs (CLI and helper).
- Added minimal `status` summary parsing from local config files with tests.
- Added status helper to load config files directly with test coverage.
- Status CLI now supports custom relay/e2ee config paths.
- Added add-server planning helper with tests.
- Added add-client planning helper with tests.
- Add CLI wiring for add server/client (file-based).
- Add server planning now allocates relay + API addresses and updates client relay config; add client port defaults from endpoint.
- Add server planning now accepts outbound endpoint and derives relay port from endpoint/outbound.
- Add server planning now supports localhost IP relay setting.
- Add client planning now strips IPv6 allowed routes when disable-ipv6 is set.
- Expose/ping CLI argument parsing added with tests; runtime stubs now validate/print placeholder output.
- Added expose request validation and API address resolution helpers with tests.
- Added API/ping stubs plus initial transport module scaffolding with protocol parsing tests.
- Added add server --server-address CLI wiring with API allocation support.
- Userspace router can now ingest AllowedIPs for route table setup (tests included).
- Added IP header parsing utilities for userspace routing with tests.
- Added userspace loop skeleton that parses packets and selects routes (tests included).
- Implemented minimal protocol header validation for TCP/UDP/ICMP in userspace processing.
- Added UDP-backed WireGuard bind implementation plus src/dst-aware wireguard packet struct; NullBind now records sent packets.
- Userspace routing now maps peer AllowedIPs to per-peer endpoints; serve builds a UDP userspace stack and runs the processing loop.
- Tests updated for UDP bind + per-peer routing and passing.
- Added packet parsing/build helpers and naive TCP/UDP/ICMP proxy handlers that forward via OS sockets and craft reply packets.
- Userspace stack can now route outbound packets to peer endpoints via `send_packet` (tested).
- Added boringtun WireGuard tunnel wrapper + smoltcp TCP proxy; serve now runs a WireGuard+smoltcp loop for TCP stateful forwarding with UDP/ICMP fallback.
- Added HTTP client for ping/expose API calls with tests; ping CLI now prints responses/timing.
- Added in-memory API service and lightweight HTTP server (tiny_http) to handle ping/expose list/add/delete; end-to-end tests exercise client/server round-trips.
- Added serverinfo/serverinterfaces/allocate/addpeer/addallowedips API endpoints (client + server + HTTP) with round-trip tests.
- Added minimal serve runtime iteration that drives the userspace stack against a bind (tested with NullBind).
- Added add server API-assisted planning (allocation-based addresses + nickname resolution) with tests; CLI now uses API allocation for `add server --server-address`.
- API add-allowed-IPs now appends routes; `add server --server-address` pushes new relay routes to existing servers and skips rewriting client relay config.
- Added keepalive handling for outbound add-server flows plus CLI regression test ensuring relay config is untouched in API add-server mode.
- `add server` outbound endpoint semantics now match Go (server config omits endpoint; client relay config carries endpoint + keepalive).
- Added API allocation peer types with client address tracking, plus add-client `--server-address` flow that allocates clients and wires peers/keepalive.
- Aligned API allocation defaults with Go (client/server/e2ee + API defaults) and seed API state from relay/e2ee configs when available.
- Added IPv6 packet helpers, ICMPv4 port-unreachable builder, and stateful UDP proxy with connection tracking; serve loop now uses UDP proxy with polling.
- Added UDP proxy + ICMP unreachable integration tests.
- Added ICMPv6 echo + port-unreachable handling and wired userspace stack to reuse UDP proxy with per-flow peer mapping.
- Smoltcp proxy now handles UDP flows alongside TCP (OS UDP sockets bridged through smoltcp); serve uses smoltcp for UDP while ICMP remains packet-based.
- Smoltcp UDP now uses per-listener sockets (avoids multi-client conflicts), adds ICMP unreachable fallback, and includes UDP round-trip + multi-source tests.
- ICMP handler now supports pluggable ping checks (system ping in serve) with test coverage for ping failure suppression.
- Added multi-peer WireGuard tunnel manager with longest-prefix route selection; serve now builds relay tunnel from all peers instead of single-peer only.
- API server now reports host interface CIDR addresses via system interface discovery.
- API allocation now records client/server address states with indices and logs incoming API requests.
- API addpeer/addallowedips now update the live relay tunnel; serve shares the relay tunnel with the API service.
- Simple-mode serve now adds the API bind address to smoltcp local addresses (matches relay+API address behavior).
- Serverinfo now returns a placeholder E2EE config when running relay-only.
- smoltcp proxy now honors LocalhostIP by DNAT-ing TCP/UDP to 127.0.0.1.
- Serve now logs localhost forwarding warnings to match the Go runtime.
- Serve honors WIRETAP_DISABLEIPV6 from the environment.
- API client now disables proxy-from-env to match Go behavior.
- API bind address selection now forces IPv4 defaults when IPv6 is disabled.
- API client allocate now uses GET with type query for Go server compatibility.
- API client addpeer now uses interface query + PeerConfig body for Go server compatibility.
- Server config parsing now stores relay preshared keys on peers (matches WireGuard semantics).
- Server file generation now falls back to peer preshared keys when present.
- Server config loading now applies environment overrides on top of file config.
- Added nested E2EE-over-relay data path: relay tunnel now encapsulates E2EE WireGuard UDP datagrams; decrypted E2EE IP traffic is routed through the smoltcp proxy loop.
- API addpeer now updates the live E2EE tunnel when available.
- Added tests for UDP encapsulation and relay-wrapped E2EE packets reaching smoltcp.
- Added IPv6 UDP encapsulation test and MultiPeerSession handshake round-trip test.
- Added end-to-end E2EE-over-relay integration test and API localhost fallback mapping for tunnel access.
- API service is now shared with the smoltcp proxy to handle HTTP requests over the tunnel path.
- Add client file-based planning now auto-disables IPv6 when the base E2EE config is IPv4-only.
- CLI help now honors `--show-hidden`; hidden flags appear when requested.
- Add server route parsing ignores empty strings (matches Go behavior).
- Simple-mode configure now adds the API address to the relay interface; server file/command output handles multiple relay addresses safely.
- Serve now exposes TCP timeout/keepalive flags and smoltcp proxy enforces completion/connect/idle timeouts for closer network stack parity.
- Serve now accepts WireGuard keepalive, and E2EE peers inherit relay keepalive by default for userspace tunnel parity.
- Expose now routes TCP/dynamic requests through the smoltcp tunnel via a serve-loop bridge (host listeners enqueue tunnel connections).
- UDP expose now forwards through smoltcp sockets (host UDP listener bridged into the tunnel).
- smoltcp TCP proxy now propagates half-close events between tunnel sockets and host streams.
- Serve no longer starts the host tiny_http API server by default; API is served through the smoltcp tunnel path.
- Added API expose command channel test coverage.
- Added smoltcp expose bridge tests for TCP host bridge SYN emission and UDP expose forwarding.
- Server config parser now ignores trailing comment blocks (e.g., embedded command hints) with test coverage.
- Serve now fills default relay/E2EE AllowedIPs when missing in server config (matches Go defaults) with tests.
- WireGuard timer updates now ignore ConnectionExpired instead of aborting the runtime.
- WireGuard decapsulation now ignores InvalidMac (and other non-fatal) errors to avoid crashing on stray packets.
- Added tracing-based logging with configurable log file output (debug builds default to ./logs/).
- Troubleshooting notes (client cannot handshake to server; observed Jan 21, 2026):
  - Client `wg show` for `wiretap_relay` shows no `latest handshake` and no peer endpoint, only AllowedIPs (`172.17.0.0/24, fd:17::/48`). This indicates the relay tunnel never completed a handshake; the client has not received any packets from the relay peer.
  - Client `wg show` for `wiretap` (E2EE) shows endpoint `172.17.0.2:51821` and `transfer: 0 B received, 3.76 KiB sent`. This means the client is sending E2EE packets toward the relay address, but no replies come back because the relay tunnel is down. E2EE is layered over relay; if relay is down, E2EE cannot handshake.
  - Server config (`wiretap_server.conf`) shows `[Relay.Peer] Endpoint = 192.168.0.233:51820`. In inbound mode (`--endpoint`), the server dials the *client*; therefore this endpoint must be the client’s reachable UDP address. If this value is actually the *server’s* LAN IP, the server is effectively dialing itself and the relay handshake will never start. Fix: either (a) regenerate configs using `--outbound-endpoint <server-ip>:51820` so the client dials the server, or (b) change server relay peer endpoint to the client’s real IP/port and ensure UDP 51820 is reachable from the server.
  - Client-side `curl http://192.168.0.233:51820` is invalid for testing because 51820 is UDP WireGuard, not HTTP. Correct API test is `curl http://[::2]/ping` (or `192.0.2.2` when IPv6 is disabled) *after* relay/E2EE are up.
  - If both machines can ICMP ping each other but UDP 51820 is blocked by host firewall/NAT, relay handshake still fails. Verify client is listening on UDP 51820 (`ss -lun | rg 51820`) and server can send UDP to client; inbound mode requires server → client reachability.
- Serve loop now treats "peer endpoint missing" as non-fatal: logs a warning and continues waiting for handshake instead of exiting (covers inbound mode where endpoint is learned after first packet).
- Added `-q/--quiet` on `serve` to suppress stdout/stderr prints and disable all logging output (no stdout and no log files) even in debug builds.
- `serve` now injects default E2EE interface addresses (172.18.0.2/32 + fd:18::2/128) when missing from the server config, matching Go's viper defaults so IPv4 traffic (e.g. localhost mapping) is accepted by the smoltcp stack.
- smoltcp interface address list now includes `LocalhostIP` when configured so packets to the mapped IP are accepted by the stack (needed for localhost TCP forwarding).
- **Troubleshooting notes (Jan 23, 2026, localhost forwarding hang with E2EE):**
  - **Observed behavior:** Relay + E2EE handshakes succeed (client `wg show` reports `latest handshake` and non-zero transfers), server logs show `Received handshake_initiation`/`Sending handshake_response` on E2EE, yet `curl http://10.0.0.123:8080` from the client times out while a local server on the host is listening at `127.0.0.1:8080`. This indicates the TCP SYN never results in a SYN-ACK from the smoltcp stack.
  - **Path recap:** Client sends TCP SYN from `172.19.0.1` (E2EE addr) to `10.0.0.123:8080`. Kernel routes to E2EE WG; E2EE UDP datagrams target relay IP `172.17.0.2:51821`; relay tunnel decrypts to UDP packet and `extract_e2ee_datagram` forwards payload into `MultiPeerSession::decapsulate_from`, producing inner IP packets for `SmoltcpTcpProxy::handle_ip_packet`. Reply packets should be sourced from `10.0.0.123` so the client accepts them (AllowedIPs include `10.0.0.123/32`).
  - **Go vs Rust delta:** Go uses gVisor stack IPTables DNAT to map `LocalhostIP -> 127.0.0.1` within the netstack (`configureLocalhostForwarding`); Rust currently maps only at host-connect time (`map_localhost_addr`), leaving smoltcp to see the original `10.0.0.123` destination. This should still work if smoltcp sees the SYN, but there is no equivalent NAT filter in the smoltcp stack yet.
  - **New instrumentation:** Added `tracing::debug` logs in `SmoltcpTcpProxy` to emit:
    - `smoltcp tcp syn received` when a SYN is observed and a listener socket is created.
    - `smoltcp tcp established; connecting to host` and `smoltcp tcp host connection established/failed` when the proxy tries to connect to the host (after TCP handshake completes).
    - `smoltcp outbound tcp` / `smoltcp outbound ip` for every outbound packet produced by smoltcp (includes src/dst/flags) to verify SYN-ACK or data packets are actually emitted.
    - `e2ee datagram outbound` when E2EE-encapsulated UDP datagrams are sent over the relay (includes src/dst/size) to verify encapsulation occurs.
  - **Checksum handling (likely root cause):** smoltcp defaults to *verifying* inbound TCP/UDP checksums. WireGuard decapsulation can surface packets with offload/partial checksums, which smoltcp will drop silently. Updated `QueueDevice` capabilities to **skip RX verification but still compute TX checksums** (`Checksum::Tx` for IPv4/TCP/UDP/ICMP), and added a test to ensure SYNs with bad checksums still elicit a response.
  - **Routing (likely root cause for missing SYN-ACK):** smoltcp `Medium::Ip` requires a route to emit packets unless the destination is in `ip_addrs`. With /32 addresses, replies to `172.19.0.1` had **no route**, so SYN-ACK never left the stack. Added default IPv4/IPv6 routes (via the first local address of each family) in `SmoltcpTcpProxy::new` so the stack will dispatch outbound replies for any destination.
    These logs are critical to determine whether SYNs reach smoltcp or whether host connection attempts are failing.
  - **Interpretation of missing logs:** If no `smoltcp tcp syn received` appears during a client `curl`, the SYN is not reaching smoltcp (likely extraction/decapsulation path or routing issue). If `syn received` appears but no host connection log, smoltcp may never reach `State::Established` (no SYN-ACK round trip), suggesting outbound packets are not being sent back via E2EE/relay. If `host connection failed`, the local server binding or OS firewall is at fault.

## Handoff Notes
- **Current coverage:** key parsing, config serialization/parsing, server config loading (file/env), serve options, status summary (file-based), add server/client planners, expose request validation, boringtun WireGuard tunnel + smoltcp TCP proxy, userspace routing + basic TCP/UDP/ICMP forwarding, UDP bind integration.
- **CLI state:** `configure`, `serve` (config load + flags + WireGuard+smoltcp loop), `status` (basic summary with custom config paths), and `add` (server/client file-based) are wired; `expose`/`ping` parse and validate but still call runtime stubs.
- **Key modules:** `src/peer.rs` (config + key primitives), `src/serve.rs` (server config loader + options), `src/status.rs` (summary helpers), `src/add.rs` (add planners), `src/expose.rs` (expose planning + validation), `src/transport/userspace` (bind/router/packet parsing).
- **Missing runtime:** no E2EE nested tunnel; API still runs on a host socket rather than the tunnel.

### Detailed Handoff (New Developer Quick Start)
**High-level architecture (Rust port as of now):**
- `serve` uses a **single-peer WireGuard tunnel** implemented with **boringtun** (see `src/transport/wireguard.rs`).
- WireGuard packets are transported over a UDP socket bound locally (listen addr from config), with a **single remote peer endpoint**.
- Decrypted IP packets are handled as:
  - **TCP**: forwarded into a **smoltcp TCP proxy** (see `src/transport/smoltcp.rs`) which manages TCP state and bridges to OS `TcpStream`.
  - **UDP/ICMP**: handled by existing per-packet proxy functions in `src/transport/udp.rs` and `src/transport/icmp.rs`.
- Encrypted outbound packets are sent back through boringtun.
- There is **no E2EE nested tunnel** yet and **no multi-peer** support.

**Runtime data flow:**
1) `serve` loads server config (`load_server_config`) and applies IPv6 filtering (`apply_serve_options`).
2) `run_wireguard_smoltcp` builds a `WireguardTunnel` from relay private key + relay peer public key/endpoint.
3) Loop:
   - `tunnel.recv_packets()` decrypts network datagrams; returns IP packets.
   - TCP packets go through `SmoltcpTcpProxy::handle_ip_packet`.
   - UDP/ICMP packets go through `udp::handle_udp_packet` and `icmp::handle_icmp_packet`.
   - Any responses are re-encrypted via `tunnel.send_ip_packet`.
   - smoltcp proxy is polled each tick (`tcp_proxy.poll`) and outbound data from smoltcp is encrypted.

**Key files:**
- `src/transport/wireguard.rs`: boringtun wrapper (handshake, encrypt/decrypt, timers).
- `src/transport/smoltcp.rs`: smoltcp device + TCP socket lifecycle + OS stream bridging.
- `src/transport/packet.rs`: IP/TCP parsing + checksum helpers.
- `src/serve.rs`: runtime loop wiring (single-peer WireGuard + smoltcp).
- `src/transport/userspace/*`: earlier routing/bind skeleton (used in tests; no longer the primary runtime path).

**Dependencies and constraints:**
- `boringtun = "0.6"` requires `x25519-dalek = "=2.0.0-rc.3"`. Do not upgrade without resolving this.
- `smoltcp = "0.11"` with `medium-ip` + TCP/UDP/ICMP sockets. Device implementation uses queued packets.
- The current TCP proxy is stateful but minimal (no retries, no advanced timers, no connection pooling).

**Current tests and coverage:**
- WireGuard handshake/encryption round-trip: `tests/wireguard_tunnel_tests.rs`.
- smoltcp TCP SYN response: `tests/smoltcp_proxy_tests.rs`.
- UDP/TCP/ICMP per-packet proxy behaviors: `tests/transport_data_path_tests.rs`.
- Userspace routing + bind tests: `tests/transport_userspace_tests.rs`.
- Full suite: `cargo test`.

**Known behavior gaps vs Go reference:**
- Single-peer only. No relay mesh or dynamic peer additions at runtime.
- No nested E2EE tunnel (WireGuard over relay) or userspace bind equivalent to Go.
- UDP forwarding uses per-packet proxying; no UDP connection tracking or ICMP unreachable from target host.
- TCP proxy relies on OS `TcpStream` bridging rather than full in-stack TCP proxy (Go uses gVisor).
- API runtime still uses lightweight HTTP server (not on top of tunnel).

## Next Steps (Detailed Checklist)
### WireGuard / Tunnel
- [ ] Multi-peer WireGuard manager:
  - Map peer public key -> `WireguardTunnel` or per-peer boringtun session.
  - Select peer by AllowedIPs (route table).
  - Support peer endpoint updates (e.g., after handshake).
- [ ] E2EE nested tunnel:
  - Create a second boringtun tunnel that uses relay tunnel as transport (similar to Go userspace bind).
  - Decide: encapsulate E2EE WG packets inside relay WG IP packets or route them directly via tunnel.
- [ ] Persistent keepalive timers:
  - Ensure `update_timers` is called for each tunnel periodically.
  - Expose keepalive config per peer (currently uses peer keepalive from config).

### smoltcp Data Path
- [ ] Replace UDP/ICMP per-packet proxying with smoltcp sockets:
  - Use smoltcp UDP sockets for bidirectional NAT-like flows.
  - Use smoltcp ICMP sockets for echo handling.
- [ ] TCP improvements:
  - Connection timeouts + idle timeout handling.
  - Proper half-close handling and stream shutdown semantics.
  - Backpressure: avoid unbounded buffering between smoltcp socket and OS stream.

### Serve Runtime / CLI
- [ ] Enable runtime selection (single-peer vs multi-peer vs E2EE) via config/flags.
- [ ] Add `--simple` behavior to bypass E2EE once nested tunnel is implemented.
- [ ] Wire API service to run inside the tunnel rather than in-memory HTTP.

### API / Control Plane
- [ ] Replace tiny_http server with smoltcp or tunnel-aware transport.
- [ ] Implement control-plane authentication (not in Go, but consider minimal protection).
- [ ] Implement expose dynamic forwarding data path using smoltcp / socket proxy.

### Testing + Tools
- [ ] Add multi-peer routing tests (AllowedIPs selection).
- [ ] Add E2EE tunnel round-trip tests.
- [ ] Add TCP stream tests for long-lived connections + half-close.
- [ ] Add UDP flow tests with multiple senders and ICMP unreachable behavior.

## Additional Considerations
- **Performance:** current proxy uses per-packet allocations; consider buffer pools.
- **Security:** API currently unauthenticated; exposing over tunnel is risky.
- **Compatibility:** Go reference uses gVisor netstack; smoltcp differs in behavior and defaults.
- **Platform:** boringtun and smoltcp should be portable but test on Linux first.

## Implemented Modules
- `src/constants.rs`: Defaults and subnet helpers.
- `src/peer.rs`: Key parsing/generation, peer/config modeling, config serialization, server command/file generation.
- `src/cli.rs`: CLI definitions and `configure` command logic.
- `src/add.rs`: Add server/client planners and file helpers.
- `src/expose.rs`: Expose request validation and API address resolution.
- `src/api.rs`: API client for ping/expose/list/remove.
- `src/api.rs`: API client for serverinfo/serverinterfaces/allocate/addpeer/addallowedips.
- `src/ping.rs`: Ping runtime wrapper using API client.
- `src/transport/mod.rs`: Transport protocol enums and flow tuple.
- `src/transport/packet.rs`: IP packet parsing/build helpers and checksum utilities.
- `src/transport/wireguard.rs`: boringtun-based WireGuard tunnel wrapper (handshake + encrypt/decrypt).
- `src/transport/smoltcp.rs`: smoltcp TCP proxy/device integration.
- `src/transport/api.rs`: In-memory API service + HTTP front-end handling ping/expose list/add/delete/serverinfo/serverinterfaces/allocate/addpeer/addallowedips semantics.
- `src/transport/userspace`: Bind abstraction, packet parsing, router, stack skeleton.
- `src/serve.rs`: serve runtime loop driving WireGuard+smoltcp (single-peer).

## Notable Gaps
- WireGuard bind is UDP-backed and uses boringtun for encryption; still single-peer and no E2EE nested tunnel.
- Userspace TCP/UDP/ICMP forwarding is implemented but minimal (per-packet proxy, no TCP handshake/state or UDP reuse). TCP now has a smoltcp-backed stateful path.
- API networking still uses a lightweight HTTP server; not integrated with gVisor/WireGuard netstack and only supports control-plane calls (no data-path).
- Clipboard support is not implemented for `configure` or `add server`.
- `serve` runtime does not implement multi-peer/E2EE WireGuard management (single-peer only).
- API endpoints missing vs Go: dynamic forwarding data path, control-plane auth; serverinfo/serverinterfaces/allocate/addpeer/addallowedips now exist but use in-memory state only.

## Stubbed Functionality (Rust)
- `src/cli.rs`: clipboard support (`configure`, `add server`) prints “not implemented yet”.
- `src/serve.rs`: no multi-peer/E2EE WireGuard management yet; single-peer boringtun only.
- `src/transport/userspace/bind.rs`: `UdpBind` is wired into serve runtime; E2EE userspace bind not ported.
- `src/transport/tcp.rs`, `src/transport/udp.rs`, `src/transport/icmp.rs`: minimal proxy implementations; no connection tracking or full TCP state (smoltcp TCP path is separate).
- `src/transport/api.rs`: HTTP server placeholder; not hooked to WireGuard netstack; control-plane auth missing.

## Remaining Work Checklist
- Implement wireguard bind abstraction:
  - Extend boringtun wrapper for multi-peer and E2EE nested tunnels.
  - Define interfaces for relay/e2ee binds and attach to actual data path.
- Userspace routing/data path:
  - Parse transport headers (TCP/UDP ports, ICMP types).
  - Implement TCP/UDP relay + ICMP echo handling (minimal).
  - Build connection tracking, UDP reuse, and full TCP state handling.
  - Add localhost redirection logic for TCP in userspace stack.
- API + control plane:
  - Implement API client/server message formats in `src/transport/api.rs`.
  - Wire `expose`/`ping` to actual API networking.
  - Implement expose list/remove responses in CLI output.
- `serve` runtime:
  - Expand to multi-peer relay and E2EE nested tunnel handling.
  - Apply disable-ipv6 filtering to runtime stack.
- Add server/client advanced flows:
  - Harden API error handling and reconciliation of multi-hop route updates.
- UX polish:
  - Clipboard support for configure/add server.
  - Improve status output to match reference tree formatting.
