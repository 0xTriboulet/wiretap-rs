# Wiretap (Go reference) Specification - Detailed

This document specifies the behavior and implementation details of the Go reference implementation of `wiretap` (located under `/reference/wiretap/src`). It is intended to be a faithful, detailed blueprint for the Rust port. It is written from the code as implemented, including edge cases and quirks.

---

## 1. Purpose and Architecture

Wiretap is a user-space WireGuard-based relay/proxy system that lets clients route traffic into a target network through a chain of servers. It supports:

- A **Relay** WireGuard interface used for forwarding packets between peers.
- An optional nested **E2EE** WireGuard interface (also userspace) that provides end-to-end encrypted traffic across the relay network.
- A lightweight **HTTP API** embedded into each server for network management (peer allocation, topology inspection, exposing services, etc.).
- TCP, UDP, and ICMP proxying/forwarding implemented on top of a gVisor netstack.

In normal mode, the server runs two WireGuard devices:

1. **Relay device** bound to a gVisor netstack backed by a userspace TUN.
2. **E2EE device** bound to the relay device through a custom userspace WireGuard bind (`transport/userspace`).

In **simple mode**, the E2EE interface is omitted; the relay interface directly handles traffic, and the API address is added to the relay interface.

High-level data flow:

- Client traffic enters Relay, is forwarded across relay hops.
- At the target server, traffic is decrypted on E2EE, then proxied into the host network via gVisor handlers.
- Return traffic is re-encapsulated and sent back through the E2EE + Relay path.

---

## 2. Functional Components (Module-Level Responsibilities)

- `cmd/`: CLI entry points and workflows (`configure`, `serve`, `add`, `expose`, `status`, `ping`).
- `peer/`: WireGuard config representation, parsing/serialization, key generation, address allocation helpers.
- `api/`: Client-side HTTP API wrapper used by CLI workflows.
- `transport/api/`: Server-side HTTP API implementation and in-memory network allocation state.
- `transport/`: Shared network helpers (proxying, packet crafting, socks5, stack address tracking).
- `transport/tcp`, `transport/udp`, `transport/icmp`: Protocol forwarding on gVisor netstack.
- `transport/userspace`: Userspace WireGuard bind enabling E2EE-over-Relay.

---

## 3. Defaults and Global Constants

Defined in `cmd/root.go`:

- `Port` default: **51820**
- `E2EEPort` default: **51821**
- `ApiPort` default: **80**
- `Keepalive` default: **25 seconds**
- `MTU` default: **1420**

Subnets (default ranges):

- API: `::/8` (IPv6), `192.0.2.0/24` (IPv4)
- Client relay: `172.16.0.0/16`, `fd:16::/40`
- Relay (server relay subnets): `172.17.0.0/16`, `fd:17::/40`
- E2EE: `172.18.0.0/16`, `fd:18::/40`
- Client E2EE: `172.19.0.0/16`, `fd:19::/40`

Subnet prefix sizes:

- `SubnetV4Bits = 24`
- `SubnetV6Bits = 48`
- `APIBits = 16` (IPv6 default)
- `APIV4Bits = 24`

Other constants:

- `USE_ENDPOINT_PORT = -1` sentinel for "infer port from endpoint"
- `CUSTOM_PREFIX = "#@"` for Wiretap-only config extensions

---

## 4. CLI Surface

Entry point: `main.go` -> `cmd.Execute()` (Cobra). The CLI binary is named `wiretap`.

### 4.1 Global behavior

- `wiretap` with no arguments prints help and exits.
- Global flag `--show-hidden / -H` reveals hidden flags on help output.
- Version is exposed via Cobra `Version`.

### 4.2 `wiretap configure`

Purpose: Generate initial client configs (relay + E2EE) and a server config file. It also prints ready-to-run server commands (POSIX and PowerShell) and optionally copies to clipboard.

Key flag behavior:

- Exactly **one** of `--endpoint` or `--outbound-endpoint` must be set.
- `--routes` is required. Empty strings are ignored later during parsing.
- `--port` default:
  - If `--endpoint` set: use that endpoint port.
  - Otherwise: `51820`.
- `--sport` default:
  - If `--outbound-endpoint` set: use that endpoint port.
  - Otherwise: `51820`.
- `--disable-ipv6`: if set and `--api` is IPv6, the API address is replaced with the default IPv4 API address.
- `--localhost-ip`: if set, appends `<ip>/32` to `AllowedIPs` list.
- `--PSK`: generates a preshared key and embeds it in the relay peer config.

Hidden but supported flags (via `--show-hidden`):

- `--api`, `--ipv4-relay`, `--ipv6-relay`, `--ipv4-e2ee`, `--ipv6-e2ee`, `--ipv4-relay-server`, `--ipv6-relay-server`
- `--keepalive`, `--mtu`, `--disable-ipv6`, `--relay-output`, `--e2ee-output`, `--server-output`, `--simple`

Detailed generation logic:

1. Build server relay and server E2EE configs (fresh keypairs).
2. Compute relay subnets based on `--ipv4-relay-server` and `--ipv6-relay-server`:
   - Masked to `SubnetV4Bits` / `SubnetV6Bits`.
3. Construct client relay config:
   - ListenPort: `--port` (derived if `USE_ENDPOINT_PORT`).
   - Addresses: `--ipv4-relay`, `--ipv6-relay` (IPv6 omitted if `--disable-ipv6`).
   - Peer: server relay public key.
   - AllowedIPs:
     - **Simple mode**: user routes + API address (+ localhost IP if provided).
     - **Normal mode**: relay subnets only.
   - Endpoint: `--outbound-endpoint` if provided.
   - PersistentKeepalive: only when `--outbound-endpoint` set.
4. Construct client E2EE config (unless `--simple`):
   - ListenPort: `E2EEPort` (51821).
   - Addresses: `--ipv4-e2ee`, `--ipv6-e2ee` (IPv6 omitted if `--disable-ipv6`).
   - Peer: server E2EE public key.
   - AllowedIPs: user routes + API address (+ localhost IP if provided).
   - Endpoint: server relay IPv4 address + `E2EEPort`.
   - MTU: `mtu - 80`.
5. Convert client configs to peer configs and add to server configs:
   - Relay: if `--endpoint` specified (inbound case), set endpoint on the server's relay peer.
   - E2EE: endpoint always set to client relay address + `E2EEPort`.
6. Set server relay MTU when `--mtu` is not default.
7. Apply server `LocalhostIP` if provided.
8. Select output filenames:
   - If file exists, suffix with a number (see `FindAvailableFilename`).
   - In simple mode, relay config output filename is forced to the E2EE output filename.
9. Write configs and server config file.
10. Print output, show configs, and print server command. If `--clipboard`, copy the POSIX server command.

Outputs:

- Client relay config (default `wiretap_relay.conf`, or `wiretap.conf` in simple mode)
- Client E2EE config (default `wiretap.conf`, omitted in simple mode)
- Server config file (default `wiretap_server.conf`)

### 4.3 `wiretap serve`

Purpose: Run a Wiretap server. Initializes Relay (and optional E2EE), starts TCP/UDP/ICMP forwarding, and exposes the HTTP API.

Flags:

- Primary: `--config-file (-f)`, `--delete-config (-D)`, `--quiet (-q)`, `--debug (-d)`, `--simple`, `--disable-ipv6`, `--log (-l)`, `--log-file (-o)`.
- TCP handling: `--completion-timeout`, `--conn-timeout`, `--keepalive-idle`, `--keepalive-interval`, `--keepalive-count`.
- Localhost forwarding: `--localhost-ip`.
- Hidden/deprecated flags still supported: `--private-relay`, `--public-relay`, `--preshared-relay`, `--private-e2ee`, `--public-e2ee`, `--endpoint-relay`, `--endpoint-e2ee`, `--allowed`, `--ipv4-relay`, `--ipv6-relay`, `--ipv4-e2ee`, `--ipv6-e2ee`, `--api`, `--keepalive`, `--mtu`.

Behavior summary:

- Configuration is read from environment + optional INI config file via Viper.
- `--delete-config` deletes the config file after parsing.
- Errors out if:
  - No relay and no E2EE public keys are present.
  - E2EE public key present but relay public key missing.
- If E2EE peer key missing, prints warning and runs in simple mode.
- If `disableipv6` and API address is IPv6, API address is replaced with IPv4 default.
- E2EE peer keepalive interval (when E2EE is enabled) is taken from `Relay.Peer.keepalive`.

### 4.4 `wiretap add`

Parent command for `add client` and `add server`.

Global add flags:

- `--endpoint`: inbound endpoint (server connects to client)
- `--outbound-endpoint`: outbound endpoint (client connects to server)
- `--keepalive`: keepalive interval (seconds)

`--endpoint` and `--outbound-endpoint` are used by subcommands.

#### 4.4.1 `wiretap add client`

- Adds a new client to the existing network.
- Reads existing relay + E2EE configs to discover API endpoint (uses the last AllowedIPs entry of the first E2EE peer).
- Allocates addresses from API (`AllocateClientNode`).
- Generates new relay and E2EE configs for the new client.
- IPv6 is considered disabled if the base E2EE config has only one address (IPv4).
- Copies relay peers from base config:
  - If `--server-address` empty: copy all relay peers.
  - If `--server-address` set: find the leaf server by nickname or API address and copy only that relay peer (plus its routes).
- Copies all E2EE peers into new E2EE config.
- Pushes new client peers to all servers via API:
  - Always add E2EE peer to each server.
  - Add relay peer only to relay nodes (or leaf, depending on `--server-address`).
  - If the server is E2EE-only, update allowed IPs on the leaf-facing relay peer.
- Writes new relay + E2EE configs with numbered filenames if needed.

#### 4.4.2 `wiretap add server`

- Adds a new server node to the existing network.
- Reads client relay + E2EE configs to get current network state.
- If the first E2EE peer API address is IPv4, IPv6 is treated as disabled and `APIBits` is set to `APIV4Bits` globally.

Two modes:

1) **Direct to client** (`--server-address` empty):

- Compute next relay subnets using existing relay peers.
- Compute next API prefix using E2EE peers (lowest API addr within prefix).
- Add new relay peer to client relay config (allowed IPs = next relay subnets).
- Add new E2EE peer to client E2EE config (allowed IPs = `--routes` + new API address).
- Add client relay/E2EE peers to server configs.
- Assign server relay and E2EE addresses from newly allocated prefixes.

2) **Connect to existing server** (`--server-address` set):

- Resolve `--server-address` as nickname or IP (errors if duplicate nickname).
- Query leaf server via API for relay config.
- Determine relay node as lowest API address within API prefix.
- Allocate new server addresses via API (`AllocateServerNode`).
- Add relay peer to leaf server via `AddRelayPeer`.
- Add route updates to all other servers via `AddAllowedIPs`.
- Update local client E2EE config with new server peer.

Common steps:

- Sets listen port (default derived from outbound endpoint or 51820).
- Sets LocalhostIP if provided.
- Writes updated client configs (relay only in direct-to-client mode; E2EE always).
- Writes server config file with POSIX + PowerShell commands.

### 4.5 `wiretap expose`

Manages static and dynamic port forwarding via server APIs.

- Base command `expose` has subcommands `list` and `remove`.
- If `--server-address` is absent, it reads all API addresses from local E2EE config and applies to all servers.
- `--dynamic` and `--local` are mutually exclusive.

Expose (add):

- **Dynamic**: `--dynamic` and `--remote <port>` required.
- **Static**: `--local <port>`, optional `--remote` (defaults to local), `--protocol tcp|udp`.
- API call: `POST /expose`.

List:

- API call: `POST /expose` with action `list`.

Remove:

- API call: `POST /expose` with action `delete`.

### 4.6 `wiretap status`

Builds a tree view of the Wiretap topology by querying each server API.

- Parses local relay + E2EE configs.
- Queries all E2EE peers concurrently.
- Builds a tree based on Relay peers and their AllowedIPs.
- Optional `--network-info` includes host interface lists from each server.
- Servers that fail API queries are reported in a separate "Peers with Errors" section.

### 4.7 `wiretap ping`

- Pings a server API (`/ping`) and prints the response latency.

---

## 5. Configuration Formats

### 5.1 WireGuard Config (`peer.ParseConfig`)

Wiretap reads standard WireGuard config files with some extensions.

Supported sections:

- `[Interface]`
  - `PrivateKey`
  - `Address` (may appear multiple times)
  - `ListenPort`
  - `MTU`
  - `LocalhostIP` (Wiretap extension)

- `[Peer]`
  - `PublicKey`
  - `PresharedKey`
  - `AllowedIPs` (comma-separated)
  - `Endpoint` (IP:port or [IP]:port; DNS names also supported)
  - `PersistentKeepalive`
  - `Nickname` (Wiretap extension)

Wiretap-specific extension: any line prefixed with `#@` is treated as part of the config (not a comment). This is used to encode `Nickname` in configs without breaking standard WireGuard parsers.

Parsing behavior:

- File is split on double newlines (`\n\n`) into sections.
- Section header must be exactly `[Interface]` or `[Peer]` (case-insensitive).
- Only one `[Interface]` section is allowed.
- Empty lines are ignored; comment lines starting with `#` are ignored unless `#@` prefix is present.
- Unknown sections cause an error.
- A `[Peer]` block is only added if a public key was set.
- Lines are parsed as `key = value`; missing `=` is an error.

Serialization:

- `Config.AsFile()` renders canonical WireGuard file, including `LocalhostIP` and any peer `Nickname` as `#@ Nickname = ...`.
- `Config.AsShareableFile()` returns a minimal `[Peer]` stanza with the public key, optional PSK, and `AllowedIPs = 0.0.0.0/32`.
- `Config.AsIPC()` emits wireguard-go IPC format with hex-encoded keys.

### 5.2 Server Config File (`peer.CreateServerFile`)

`wiretap configure` and `wiretap add server` emit a server config file for `wiretap serve` (INI format):

- `[Relay.Interface]`
  - `PrivateKey`
  - `IPv4`, `IPv6`
  - `Port`
  - `MTU`
  - `LocalhostIP` (optional)

- `[Relay.Peer]`
  - `PublicKey`
  - `PresharedKey` (optional)
  - `Allowed` (comma-separated)
  - `Endpoint` (optional)

- `[E2EE.Interface]` (omitted in `simple` mode)
  - `PrivateKey`
  - `Api` (single address)

- `[E2EE.Peer]` (omitted in `simple` mode)
  - `PublicKey`
  - `Endpoint` (optional)

### 5.3 Environment Variables and Viper Mapping

`wiretap serve` can be configured via environment variables with prefix `WIRETAP_`. Viper maps dots to underscores and is case-insensitive.

`CreateServerCommand` emits these environment variables (typical set):

Relay interface:

- `WIRETAP_RELAY_INTERFACE_PRIVATEKEY`
- `WIRETAP_RELAY_INTERFACE_IPV4`
- `WIRETAP_RELAY_INTERFACE_IPV6`
- `WIRETAP_RELAY_INTERFACE_PORT`
- `WIRETAP_RELAY_INTERFACE_MTU`
- `WIRETAP_RELAY_INTERFACE_LOCALHOSTIP` (if set)

Relay peer:

- `WIRETAP_RELAY_PEER_PUBLICKEY`
- `WIRETAP_RELAY_PEER_PRESHAREDKEY` (if set)
- `WIRETAP_RELAY_PEER_ALLOWED`
- `WIRETAP_RELAY_PEER_ENDPOINT` (if set)

E2EE interface/peer (only when not `simple`):

- `WIRETAP_E2EE_INTERFACE_PRIVATEKEY`
- `WIRETAP_E2EE_INTERFACE_API`
- `WIRETAP_E2EE_PEER_PUBLICKEY`
- `WIRETAP_E2EE_PEER_ENDPOINT` (if set)

Mode flag:

- `WIRETAP_DISABLEIPV6=true` when IPv6 is disabled.

---

## 6. Peer and Config Data Structures

### 6.1 `peer.Config`

Wrapper around `wgtypes.Config` with extra state:

- `config` (wgtypes.Config)
- `mtu` (int)
- `peers` ([]PeerConfig)
- `addresses` ([]net.IPNet)
- `localhostIP` (string)
- `presharedKey` (*wgtypes.Key)

Key behaviors:

- `NewConfig()` always generates a new private key.
- `GetConfig(ConfigArgs)` generates a config with overrides (private key, port, MTU, peers, addresses, etc.).
- `GenPresharedKey()` stores a key on `Config` itself (used when emitting server config files/commands).
- `AsPeer()` returns a new `PeerConfig` using this config's private key.
- `FindAvailableFilename()` appends a numeric suffix if filename already exists.

### 6.2 `peer.PeerConfig`

Wrapper around `wgtypes.PeerConfig` plus:

- `privateKey` (stored when created locally)
- `endpointDNS` (string for DNS endpoints)
- `nickname` (string)

Key behaviors:

- `SetEndpoint()` accepts IP:port or DNS:port. DNS endpoints are stored in `endpointDNS` without resolution.
- `GetApiAddr()` returns the **last** AllowedIPs entry (Wiretap convention).
- `AsFile()` renders `[Peer]` section, serializing `nickname` as `#@ Nickname = ...`.
- `AsIPC()` renders WireGuard IPC peer config with hex-encoded keys.

### 6.3 Address Allocation Helpers

- `GetNextPrefix(prefix)` increments a subnet by one at the given prefix length.
- `GetNextPrefixesForPeers(peers)` uses each AllowedIPs index position across peers to compute the next available prefixes.

---

## 7. Server Runtime (`wiretap serve`)

### 7.1 Configuration Ingest

Order:

1. Environment variables (`WIRETAP_` prefix).
2. Optional INI config file (`--config-file`).
3. Built-in defaults in `wiretapDefault` and viper defaults.

Deprecated flags are still supported and bound into viper keys.

### 7.2 WireGuard Devices

**Relay device**:

- Netstack TUN created via `netstack.CreateNetTUNwithOptions`.
- Bound to `conn.NewDefaultBind()` (wireguard-go standard bind).
- Configured via `Config.AsIPC()` (printed to stdout).

**E2EE device** (non-simple mode):

- Netstack TUN created with MTU = relay MTU - 80.
- Bound to `userspace.NewBind(tnetRelay)` so all E2EE traffic traverses relay stack.
- Configured via `Config.AsIPC()` (printed to stdout).

### 7.3 Netstack and Forwarding

- Relay stack created with IPv4 + IPv6, TCP/UDP/ICMP protocols, and raw packet support.
- In non-simple mode, relay stack enables forwarding for IPv4 and IPv6.
- E2EE stack uses API address + E2EE addresses.
- Transport handler is E2EE stack (normal mode) or relay stack (simple mode).
- Stack is set to promiscuous mode on NIC 1.

Protocol handlers:

- TCP: `transport/tcp` forwarder.
- UDP: `transport/udp` handler.
- ICMP: `transport/icmp` echo handling.

### 7.4 Localhost Forwarding (Experimental)

If `Relay.Interface.LocalhostIP` is set:

- Must be IPv4, or server exits with fatal error.
- Adds a DNAT rule to gVisor NAT table to map packets destined to that IPv4 address to `127.0.0.1` (port preserved).
- Prints warnings for loopback, multicast, or public IPs.

### 7.5 API Server

- HTTP server bound to API address on port 80.
- Uses gVisor netstack `tnet.ListenTCP`.
- Logs each request with `(client <addr>) - API: <request>`.

---

## 8. API Server Details (`transport/api`)

### 8.1 Address Allocation State

`NetworkState`:

- `NextClientRelayAddr4`, `NextClientRelayAddr6`
- `NextServerRelayAddr4`, `NextServerRelayAddr6`
- `NextClientE2EEAddr4`, `NextClientE2EEAddr6`
- `NextServerE2EEAddr4`, `NextServerE2EEAddr6`
- `ApiAddr`
- (also includes `ServerRelaySubnet4` and `ServerRelaySubnet6`, but these are not populated by `serve`)

On API startup:

- `serverAddresses[serverIndex] = initial NetworkState`
- `Next*` addresses are incremented once
- `ApiAddr` is incremented once
- `serverIndex` increments

On `GET /allocate`:

- Returns current `NetworkState` JSON.
- Increments the `Next*` fields based on peer type:
  - Client: `NextClientRelay*`, `NextClientE2EE*`
  - Server: `NextServerRelay*`, `NextServerE2EE*`, `ApiAddr`
- Stores state in `clientAddresses` or `serverAddresses` and increments indices.
- Uses locks: `nsLock`, `indexLock`, `addressLock`.

### 8.2 `POST /addpeer`

- Request body: serialized `peer.PeerConfig` JSON.
- Query parameter: `interface` (`0` = Relay, `1` = E2EE).
- Requires non-empty `AllowedIPs`.
- Applies the peer to the appropriate device via `dev.IpcSet(p.AsIPC())`.
- Adds peer to in-memory config for `serverinfo`.

### 8.3 `POST /addallowedips`

- Request body: `AddAllowedIPsRequest` with `PublicKey` and `AllowedIPs`.
- Finds peer in relay config by public key.
- Appends AllowedIPs and applies updated peer to device with IPC.

### 8.4 `POST /expose`

Request body: `ExposeRequest`:

- `Action`: `ExposeActionExpose`, `ExposeActionList`, `ExposeActionDelete`
- `LocalPort`, `RemotePort`, `Protocol` (`tcp`/`udp`)
- `Dynamic` (bool)

Expose key: `(RemoteAddr, LocalPort, RemotePort, Protocol)` where `RemoteAddr` is the API client's IP (from `r.RemoteAddr`).

- **List**: returns all tuples in the map.
- **Expose**:
  - If `Dynamic` true: opens TCP listener on `RemotePort`, runs SOCKS5 using `transport.ForwardDynamic`.
  - If TCP: opens TCP listener on `RemotePort`, uses `transport.ForwardTcpPort` to forward to `(RemoteAddr:LocalPort)`.
  - If UDP: opens UDP listener on `RemotePort`, uses `transport.ForwardUdpPort` to forward to `(RemoteAddr:LocalPort)`.
- **Delete**: closes listeners/sockets and removes tuple from map; errors if not found.

### 8.5 `GET /serverinfo` and `GET /serverinterfaces`

- `/serverinfo`: returns JSON with `RelayConfig` and `E2EEConfig` (E2EE may be empty in simple mode).
- `/serverinterfaces`: returns host network interface list and addresses.

---

## 9. API Client Details (`api/`)

- All requests use a custom `http.Transport` with `Proxy = nil` to bypass proxies.
- Timeout: 3 seconds per request.
- Non-200 status returns error with the response body.
- Request helper builds URLs as `http://<apiAddr>:<port>/<route>?<query>`.
- Implements wrappers for `/ping`, `/serverinfo`, `/serverinterfaces`, `/allocate`, `/addpeer`, `/addallowedips`, `/expose`.

---

## 10. Transport Implementations

### 10.1 TCP Forwarding (`transport/tcp`)

Flow per connection:

1. Handler receives a `tcp.ForwarderRequest` from gVisor.
2. Adds destination address to the stack via `transport.ConnCounts` to allow outbound traffic from that IP.
3. `checkDst` attempts to connect to destination:
   - On `ECONNREFUSED`, signals to send RST.
   - On other errors, does not send RST.
   - If connection succeeds, starts a catch timer; if unused within `CatchTimeout`, destination conn is closed.
4. `accept` creates a TCP endpoint for the peer side and sets keepalive options:
   - `KeepaliveIdle`, `KeepaliveInterval`, `KeepaliveCount`.
5. Proxies data both directions via `transport.Proxy`.
6. Removes address from `ConnCounts` when done.

### 10.2 UDP Forwarding (`transport/udp`)

UDP forwarding is implemented manually to enable ICMP port-unreachable behavior.

Key structures:

- `sourceMap`: maps client source address to (Count, Port) to reuse ephemeral ports.
- `connMap`: maps `(source, dest)` tuple to a packet channel.

Flow:

1. On inbound UDP packet, clone packet and call `newPacket`.
2. `newPacket`:
   - If connection exists, enqueue packet to its channel.
   - Otherwise, allocate a new dialer and channel; reuse a previous ephemeral port if the source is known.
3. `handleConn`:
   - Creates outbound UDP socket using `go-reuseport` so ICMP errors are received.
   - Forwards packets to the real destination.
   - Reads responses and crafts reply packets manually (`sendResponse`) to preserve original source/dest.
   - On `ECONNREFUSED`, sends an ICMP Port Unreachable to the peer (`sendUnreachable`).

`sendResponse` and `sendUnreachable` craft IP headers and use `transport.SendPacket` to inject packets into the gVisor stack.

### 10.3 ICMP Handling (`transport/icmp`)

- Uses gVisor raw endpoints to read ICMPv4 and ICMPv6.
- Handles echo requests only.
- A `Ping` interface chooses one of:
  - `go-ping` socket-based ping (if unprivileged ping allowed)
  - `exec ping` via system binary
  - `noPing` fallback (no response)
- If ping succeeds, generates an echo reply with spoofed addresses and injects it using `transport.SendPacket`.
- ICMPv6 header is manually constructed to reconstruct destination address (control message provides it).

### 10.4 Shared Transport Helpers (`transport/transport.go`)

- `ConnCounts`: tracks address usage to add/remove IP addresses to the gVisor stack dynamically.
- `GetNetworkLayer`: decodes IPv4/IPv6 headers for packet crafting.
- `SendPacket`: uses a packet endpoint to send raw IP packets.
- `Proxy`: bi-directional TCP copy with error logging.
- `ForwardTcpPort`, `ForwardUdpPort`, `ForwardDynamic` are used by the API `expose` feature.

---

## 11. Userspace Bind (`transport/userspace`)

Purpose: allow the E2EE WireGuard device to bind to the relay netstack, so the E2EE traffic traverses relay transport.

`UserspaceSocketBind` implements `conn.Bind` from wireguard-go. Key details:

- `Open` attempts to create UDP connections via `gonet.DialUDP` on the relay netstack.
- It returns a slice of receive functions and the bound port.
- It uses `UserspaceEndpoint` implementing `conn.Endpoint`.

Important quirks (as implemented):

- `listenNet` uses `gonet.DialUDP` rather than a pure listener, and uses `udp6` for the IPv4 path (likely unintended, but current behavior).
- In `Open`, the IPv6 connection is never created; the second branch mistakenly checks `if ipv4 != nil` instead of `if ipv6 != nil` before appending the receive function and storing `bind.ipv6`.
- `Close` only closes the IPv4 socket.

These behaviors should be preserved or explicitly corrected in the Rust port, depending on desired compatibility.

---

## 12. Status Tree Construction

`wiretap status` uses relay peer relationships to build a topology tree:

- Starts with local client as root.
- Queries all E2EE peers concurrently using `/serverinfo`.
- For each server, uses its relay config to identify downstream peers.
- Skips relay peers that contain the client relay address in their AllowedIPs (client-facing peers).
- Tree nodes include:
  - nickname, relay public key (short), e2ee public key (short), API addr, routes, optional LocalhostIP
  - optional host interface list via `/serverinterfaces` when `--network-info` is set.

Servers that fail API queries are printed in a separate "Peers with Errors" section.

---

## 13. Error Handling and Logging

- `check()` helper exits with fatal log on error.
- API requests use 3-second timeout and disable HTTP proxy.
- TCP/UDP forwarding logs errors but continues.
- WireGuard log level:
  - `--debug` => verbose
  - `--quiet` => silent
  - default => error
- `--log` with `--log-file` writes logs to file; if `--quiet` also set, only log file output is used.

---

## 14. Compatibility Notes for Rust Port

- Preserve config parsing semantics (including `#@` prefix, ignored comments, and error behavior).
- Preserve API routing, including `expose` tuple key definition and how `RemoteAddr` is determined.
- Preserve gVisor stack behaviors (promiscuous mode, dynamic address add/remove).
- Preserve wireguard IPC formatting and hex key encoding.
- Preserve `FindAvailableFilename` numbering behavior.
- Ensure E2EE MTU is always `relay MTU - 80`.
- Consider mirroring userspace bind quirks unless explicitly fixed (see section 11).

---

## 15. Quick Reference Tables

### 15.1 API Endpoints

- `GET /ping` -> `pong`
- `GET /serverinfo` -> JSON: `{ RelayConfig, E2EEConfig }`
- `GET /serverinterfaces` -> JSON list of `{ Name, Addrs[] }`
- `GET /allocate?type=0|1` -> JSON `NetworkState`
- `POST /addpeer?interface=0|1` -> add peer
- `POST /addallowedips` -> add allowed IPs to relay peer
- `POST /expose` -> expose/list/delete ports

### 15.2 Ports

- WireGuard Relay listen port: `51820` (default)
- WireGuard E2EE listen port: `51821`
- API HTTP port: `80`
