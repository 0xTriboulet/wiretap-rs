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
- `--routes (-r)` is **required**. Empty strings are ignored later during parsing. This specifies CIDR IP ranges that will be routed through wiretap.
- `--endpoint (-e)`: IP:PORT (or [IP]:PORT for IPv6) of wireguard listener that server will connect to (inbound connection).
- `--outbound-endpoint (-o)`: IP:PORT (or [IP]:PORT for IPv6) of wireguard listener that client will connect to (outbound connection).
- `--port (-p)` default:
  - If `--endpoint` set: use that endpoint port.
  - Otherwise: `51820`.
- `--sport (-S)` default (server port):
  - If `--outbound-endpoint` set: use that endpoint port.
  - Otherwise: `51820`.
- `--nickname (-n)`: Server nickname to display in 'status' command (stored as Wiretap extension in peer config).
- `--disable-ipv6`: if set and `--api` is IPv6, the API address is replaced with the default IPv4 API address.
- `--localhost-ip (-i)`: **[EXPERIMENTAL]** if set, appends `<ip>/32` to `AllowedIPs` list and configures localhost redirection on server (see section 16.1).
- `--PSK (-K)`: generates a preshared key and embeds it in the relay peer config.
- `--clipboard (-c)`: copies the POSIX server command to the system clipboard using the `atotto/clipboard` library.
- `--simple`: disables multihop and multiclient features for a simpler setup (omits E2EE interface).
- `--server-output (-s)`: wiretap server config output filename (default: `wiretap_server.conf`).
- `--relay-output`: wireguard relay config output filename (default: `wiretap_relay.conf`).
- `--e2ee-output`: wireguard E2EE config output filename (default: `wiretap.conf`).

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

The API server runs on every wiretap server, bound to the API address on port 80 (HTTP).

### 8.1 API Server Startup

- Listener created with `tnet.ListenTCP` on the gVisor netstack.
- Bound to API address (IPv6 or IPv4 depending on `--disable-ipv6`).
- All requests are logged: `(client <addr>) - API: <request-uri>`.
- Non-200 responses include error message in response body.
- Uses Go's standard `net/http` package with custom handlers.

### 8.2 Address Allocation State

`NetworkState` structure:

- `NextClientRelayAddr4`, `NextClientRelayAddr6` - next IPv4/IPv6 relay addresses for clients
- `NextServerRelayAddr4`, `NextServerRelayAddr6` - next IPv4/IPv6 relay addresses for servers
- `NextClientE2EEAddr4`, `NextClientE2EEAddr6` - next IPv4/IPv6 E2EE addresses for clients
- `NextServerE2EEAddr4`, `NextServerE2EEAddr6` - next IPv4/IPv6 E2EE addresses for servers
- `ApiAddr` - next API address for new server
- `ServerRelaySubnet4`, `ServerRelaySubnet6` - server relay subnet (not populated by `serve`, used by `add server`)

On API startup:

1. Initial `NetworkState` is stored at `serverAddresses[serverIndex]`.
2. All `Next*` addresses are incremented by one (`.Next()`).
3. `ApiAddr` is incremented.
4. `serverIndex` is incremented.

On subsequent allocations:

- State is copied, returned, then incremented.
- Separate indices for clients (`clientIndex`) and servers (`serverIndex`).
- Thread-safe with four locks: `nsLock`, `indexLock`, `addressLock`, `devLock`.

### 8.3 API Endpoints

#### `GET /ping`

**Purpose**: Health check / connectivity test.

**Request**: No parameters.

**Response**:
- Status: `200 OK`
- Body: `pong` (plain text)

**Example**:
```bash
curl http://[::2]/ping
# Response: pong
```

---

#### `GET /serverinfo`

**Purpose**: Retrieve server's relay and E2EE configurations.

**Request**: No parameters.

**Response**:
- Status: `200 OK`
- Content-Type: `application/json`
- Body: JSON object with `ServerConfigs` structure:

```json
{
  "RelayConfig": {
    "config": { /* wgtypes.Config */ },
    "mtu": 1420,
    "peers": [ /* array of PeerConfig */ ],
    "addresses": [ /* array of IPNet */ ],
    "localhostIP": "192.168.137.137",  // if configured
    "presharedKey": null
  },
  "E2EEConfig": {
    // Same structure as RelayConfig, or null in simple mode
  }
}
```

**Error Response**:
- Status: `500 Internal Server Error`
- Body: Error message string

**Usage**: Used by `wiretap status` and `wiretap add client` to query existing server configurations.

---

#### `GET /serverinterfaces`

**Purpose**: Get host network interface information.

**Request**: No parameters.

**Response**:
- Status: `200 OK`
- Content-Type: `application/json`
- Body: Array of `HostInterface` objects:

```json
[
  {
    "Name": "eth0",
    "Addrs": [
      { "IP": "10.0.0.5", "Mask": "ffffff00" },
      { "IP": "fe80::1", "Mask": "ffff:ffff:ffff:ffff::" }
    ]
  },
  {
    "Name": "lo",
    "Addrs": [
      { "IP": "127.0.0.1", "Mask": "ff000000" },
      { "IP": "::1", "Mask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }
    ]
  }
]
```

**Implementation Details**:
- Uses Go's `net.Interfaces()` to enumerate all interfaces.
- For each interface, retrieves addresses with `ifx.Addrs()`.
- Parses each address as CIDR notation.
- Errors during enumeration are logged but not fatal.

**Error Response**:
- Status: `500 Internal Server Error`
- Body: Error message string

**Usage**: Used by `wiretap status --network-info` to display host network details.

---

#### `GET /allocate?type=<0|1>`

**Purpose**: Reserve address space for a new client or server.

**Request**:
- Method: `GET`
- Query parameter: `type` (required)
  - `0` = Client (`peer.Client`)
  - `1` = Server (`peer.Server`)

**Response**:
- Status: `200 OK`
- Content-Type: `application/json`
- Body: Current `NetworkState` JSON (before incrementing):

```json
{
  "NextClientRelayAddr4": "172.16.0.2",
  "NextClientRelayAddr6": "fd:16::2",
  "NextServerRelayAddr4": "172.17.0.3",
  "NextServerRelayAddr6": "fd:17::3",
  "NextClientE2EEAddr4": "172.19.0.2",
  "NextClientE2EEAddr6": "fd:19::2",
  "NextServerE2EEAddr4": "172.18.0.3",
  "NextServerE2EEAddr6": "fd:18::3",
  "ApiAddr": "::3",
  "ServerRelaySubnet4": "0.0.0.0",
  "ServerRelaySubnet6": "::"
}
```

**Behavior After Response**:

For `type=0` (Client):
- Increments: `NextClientRelayAddr4`, `NextClientRelayAddr6`, `NextClientE2EEAddr4`, `NextClientE2EEAddr6`
- Stores state in `clientAddresses[clientIndex]`
- Increments `clientIndex`

For `type=1` (Server):
- Increments: `NextServerRelayAddr4`, `NextServerRelayAddr6`, `NextServerE2EEAddr4`, `NextServerE2EEAddr6`, `ApiAddr`
- Stores state in `serverAddresses[serverIndex]`
- Increments `serverIndex`

**Error Responses**:
- Status: `400 Bad Request` - invalid or missing `type` parameter
- Status: `405 Method Not Allowed` - non-GET request
- Status: `500 Internal Server Error` - JSON marshaling error

**Thread Safety**: Uses `nsLock`, `indexLock`, and `addressLock` to prevent race conditions.

---

#### `POST /addpeer?interface=<0|1>`

**Purpose**: Add a new peer to the server's relay or E2EE device.

**Request**:
- Method: `POST`
- Query parameter: `interface` (required)
  - `0` = Relay (`InterfaceType.Relay`)
  - `1` = E2EE (`InterfaceType.E2EE`)
- Content-Type: `application/json`
- Body: `PeerConfig` JSON (serialized peer configuration):

```json
{
  "PublicKey": "base64-encoded-key",
  "PresharedKey": "base64-encoded-key",  // optional
  "Endpoint": "1.2.3.4:51820",           // optional
  "AllowedIPs": ["10.0.0.0/24", "::2/128"],
  "PersistentKeepalive": 25,             // optional, in seconds
  "nickname": "my-server"                // optional, Wiretap extension
}
```

**Validation**:
- `AllowedIPs` must be non-empty or request fails with `500 Internal Server Error` and body `no addresses`.
- `interface` must be `0` or `1` or request fails with `400 Bad Request`.

**Behavior**:
1. Parses JSON body into `peer.PeerConfig`.
2. Selects device (relay or E2EE) based on `interface` parameter.
3. Applies peer configuration via `dev.IpcSet(p.AsIPC())`.
4. Adds peer to in-memory config (`RelayConfig` or `E2EEConfig`) for future `/serverinfo` queries.
5. Prints IPC config to stdout (debugging).
6. Logs: `API: Peer Added: <public-key>`

**Response**:
- Status: `200 OK`
- Body: Empty

**Error Responses**:
- Status: `400 Bad Request` - invalid `interface` parameter
- Status: `405 Method Not Allowed` - non-POST request
- Status: `500 Internal Server Error` - JSON parsing error, empty AllowedIPs, or IPC set failure

**Thread Safety**: Uses `devLock` to serialize device updates.

---

#### `POST /addallowedips`

**Purpose**: Add new AllowedIPs to an existing relay peer.

**Request**:
- Method: `POST`
- Content-Type: `application/json`
- Body: `AddAllowedIPsRequest` JSON:

```json
{
  "PublicKey": "base64-encoded-key",
  "AllowedIPs": [
    { "IP": "10.0.1.0", "Mask": "ffffff00" },
    { "IP": "fd:17::100", "Mask": "ffff:ffff:ffff::" }
  ]
}
```

**Validation**:
- Peer with `PublicKey` must exist in relay config or request fails with `500 Internal Server Error` and body `peer not found`.

**Behavior**:
1. Parses request body.
2. Finds peer in `RelayConfig` by public key.
3. Appends each AllowedIP to peer's existing list via `p.AddAllowedIPs()`.
4. Applies updated peer to device via `devRelay.IpcSet(p.AsIPC())`.

**Response**:
- Status: `200 OK`
- Body: Empty

**Error Responses**:
- Status: `405 Method Not Allowed` - non-POST request
- Status: `500 Internal Server Error` - JSON parsing error, peer not found, or IPC set failure

**Thread Safety**: Uses `devLock`.

**Usage**: Called by `wiretap add server` when attaching a new server to propagate route updates to other servers in the network.

---

#### `POST /expose`

**Purpose**: Manage port forwarding (expose, list, delete).

**Request**:
- Method: `POST`
- Content-Type: `application/json`
- Body: `ExposeRequest` JSON:

```json
{
  "Action": 0,        // 0=Expose, 1=List, 2=Delete
  "LocalPort": 80,    // Port on client (for TCP/UDP forward)
  "RemotePort": 8080, // Port on server
  "Protocol": "tcp",  // "tcp" or "udp"
  "Dynamic": false    // true for SOCKS5, false for static forward
}
```

**ExposeTuple Key**: `(RemoteAddr, LocalPort, RemotePort, Protocol)`
- `RemoteAddr` is parsed from the HTTP request's `r.RemoteAddr` (client IP making the API call).

##### Action 1: List

**Request**: `Action: 1`

**Response**:
- Status: `200 OK`
- Content-Type: `application/json`
- Body: Array of `ExposeTuple` objects:

```json
[
  {
    "RemoteAddr": "fd:19::1",
    "LocalPort": 80,
    "RemotePort": 8080,
    "Protocol": "tcp"
  },
  {
    "RemoteAddr": "fd:19::1",
    "LocalPort": 0,
    "RemotePort": 1080,
    "Protocol": "tcp"
  }
]
```

##### Action 0: Expose

**Validation**:
- Tuple must not already exist or request fails with `500 Internal Server Error` and body `port already exposed`.

**Dynamic Forward** (`Dynamic: true`):
1. Opens TCP listener on `RemotePort` (host network).
2. Spawns `transport.ForwardDynamic` goroutine:
   - Starts SOCKS5 server using `armon/go-socks5`.
   - Custom dialer connects to client's E2EE address at requested port.
   - Proxies connections bidirectionally.
3. Stores listener in `exposeMap[tuple].TcpListener`.

**Static TCP Forward** (`Protocol: "tcp"`):
1. Opens TCP listener on `RemotePort`.
2. Spawns `transport.ForwardTcpPort` goroutine:
   - Accepts connections from listener.
   - Dials client at `RemoteAddr:LocalPort` through gVisor stack.
   - Proxies bidirectionally with `transport.Proxy`.
3. Stores listener in `exposeMap[tuple].TcpListener`.

**Static UDP Forward** (`Protocol: "udp"`):
1. Opens UDP socket on `RemotePort`.
2. Spawns `transport.ForwardUdpPortWithTracking` goroutine:
   - Tracks per-source-address connections with 60-second timeout.
   - Forwards datagrams to client at `RemoteAddr:LocalPort`.
   - Maintains return path mapping.
   - Includes watchdog to close idle connections.
3. Stores socket in `exposeMap[tuple].UdpConn`.

**Response**:
- Status: `200 OK`
- Body: Empty

##### Action 2: Delete

**Validation**:
- Tuple must exist or request fails with `500 Internal Server Error` and body `not found`.

**Behavior**:
1. Looks up tuple in `exposeMap`.
2. Closes listener (TCP) or socket (UDP).
3. Removes tuple from map.

**Response**:
- Status: `200 OK`
- Body: Empty

**Error Responses** (all actions):
- Status: `405 Method Not Allowed` - non-POST request
- Status: `500 Internal Server Error` - JSON parsing error, validation failure, bind error, or close error

**Thread Safety**: Uses `exposeLock` (RWMutex) to protect the expose map.

**Important Notes**:
- All expose mappings are lost if the server process exits.
- Dynamic forwards use SOCKS5 (TCP only).
- UDP forwards use connection tracking to handle multiple concurrent sources.
- The `RemoteAddr` is determined from the API request source, not a parameter.

---

## 9. API Client Details (`api/`)

All API client functions are defined in the `api/` package and used by CLI commands.

### 9.1 HTTP Transport Configuration

- Uses custom `http.Transport` with `Proxy: nil` to bypass system proxy settings.
- Timeout: **3 seconds** per request (hardcoded).
- Client is created fresh for each request (not reused).

### 9.2 Request Helper

All requests use a common helper that:
1. Builds URL as `http://<apiAddr>:<port>/<route>?<query>`.
2. Sets appropriate HTTP method (GET or POST).
3. Sends request with 3-second timeout.
4. Checks status code - anything non-200 is an error.
5. Returns error with response body as message on failure.

### 9.3 API Wrapper Functions

#### `Ping(apiAddr string, port uint16) error`
- Endpoint: `GET /ping`
- Returns nil on success, error on failure.
- Used by `wiretap ping` command.

#### `GetServerInfo(apiAddr string, port uint16) (*api.ServerConfigs, error)`
- Endpoint: `GET /serverinfo`
- Returns `ServerConfigs` struct with relay and E2EE configs.
- Used by `wiretap status` and `wiretap add client`.

#### `GetServerInterfaces(apiAddr string, port uint16) ([]api.HostInterface, error)`
- Endpoint: `GET /serverinterfaces`
- Returns array of host interface information.
- Used by `wiretap status --network-info`.

#### `AllocateClientNode(apiAddr string, port uint16) (*api.NetworkState, error)`
- Endpoint: `GET /allocate?type=0`
- Returns address allocation for a new client.
- Used by `wiretap add client`.

#### `AllocateServerNode(apiAddr string, port uint16) (*api.NetworkState, error)`
- Endpoint: `GET /allocate?type=1`
- Returns address allocation for a new server.
- Used by `wiretap add server`.

#### `AddRelayPeer(apiAddr string, port uint16, peerConfig peer.PeerConfig) error`
- Endpoint: `POST /addpeer?interface=0`
- Adds peer to server's relay device.
- Used by `wiretap add client` and `wiretap add server`.

#### `AddE2EEPeer(apiAddr string, port uint16, peerConfig peer.PeerConfig) error`
- Endpoint: `POST /addpeer?interface=1`
- Adds peer to server's E2EE device.
- Used by `wiretap add client` and `wiretap add server`.

#### `AddAllowedIPs(apiAddr string, port uint16, req api.AddAllowedIPsRequest) error`
- Endpoint: `POST /addallowedips`
- Adds routes to existing relay peer.
- Used by `wiretap add server`.

#### `Expose(apiAddr string, port uint16, req api.ExposeRequest) ([]api.ExposeTuple, error)`
- Endpoint: `POST /expose`
- Manages port forwarding.
- Returns array of tuples for list action, empty array otherwise.
- Used by `wiretap expose`, `wiretap expose list`, `wiretap expose remove`.

### 9.4 Error Handling

- Network errors (timeout, connection refused) return immediately with error.
- HTTP errors (non-200 status) return error with response body.
- JSON parsing errors return with parse error message.
- No retries are attempted on any failure.

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

UDP forwarding is implemented manually (not using gVisor's built-in forwarding) to enable proper ICMP port-unreachable behavior.

Key structures:

- `sourceMap`: maps client source address to `(Count, Port)` to reuse ephemeral ports across connections.
- `connMap`: maps `(source, dest)` tuple to a packet channel for demultiplexing.

Flow:

1. On inbound UDP packet, clone packet and call `newPacket`.
2. `newPacket`:
   - If connection exists in `connMap`, enqueue packet to its channel.
   - Otherwise, allocate a new UDP socket and channel.
   - Reuse a previous ephemeral port from `sourceMap` if the source address is known.
   - Spawn `handleConn` goroutine for the new connection.
3. `handleConn`:
   - Creates outbound UDP socket using `go-reuseport` library (`reuseport.NewReusablePortPacketConn`).
   - **Critical**: Socket must be created with `reuseport` so ICMP errors from the kernel are properly delivered.
   - Forwards packets from channel to real destination.
   - Reads responses from real destination.
   - Crafts reply packets manually using `sendResponse` to preserve original source/dest addresses.
   - On `ECONNREFUSED` error, sends ICMP Port Unreachable to peer via `sendUnreachable`.
   - Removes connection from `connMap` and ephemeral port tracking on exit.

#### ICMP Port Unreachable Handling

When the OS receives a UDP packet destined for a closed port, the kernel generates an ICMP "Destination Unreachable - Port Unreachable" message. This is received by the `reuseport` socket.

`sendUnreachable` behavior:
- Crafts ICMP packet (IPv4 or IPv6) with Type 3 Code 3 (Destination Unreachable - Port Unreachable).
- Includes original UDP packet (up to ICMP payload limit) in ICMP payload.
- Injects into gVisor stack using `transport.SendPacket`.
- Spoofs source address to be the real destination, so client sees realistic ICMP error.

#### `sendResponse` and `sendUnreachable` Manual Packet Crafting

Both functions manually construct IP + UDP or IP + ICMP packets:

1. Decode original packet headers using `transport.GetNetworkLayer`.
2. Build new headers with swapped source/destination.
3. For UDP response:
   - Swap source/dest IP and ports.
   - Calculate UDP checksum.
   - Combine IP + UDP + payload.
4. For ICMP unreachable:
   - Set ICMP type and code.
   - Include original packet in payload.
   - Calculate ICMP checksum.
5. Inject using `transport.SendPacket` with spoofed source address.

#### Edge Cases and Quirks

- **Port reuse**: Ephemeral ports are tracked per-source-address to maintain consistent port mapping for multi-packet "connections".
- **No connection state expiry**: Connections remain in `connMap` until the socket is closed or an error occurs. There's no idle timeout in the basic `ForwardUdpPort` implementation.
- **`ForwardUdpPortWithTracking`**: Enhanced version used by expose feature:
  - Tracks per-source connections with `trackedConn` structure.
  - Includes `lastActive` timestamp.
  - Watchdog goroutine runs every 30 seconds, closes connections idle for more than `UDP_TIMEOUT` (60 seconds).
  - Properly handles cleanup when main listener is closed.
  - More robust for long-running forwards.

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

### 13.1 Global Error Handler

`check()` helper function (in `cmd/` package):
- Takes an error and optional message.
- If error is non-nil: logs with `log.Fatal()` and exits immediately.
- Used throughout CLI commands for unrecoverable errors.
- Exit code is 1 on fatal errors.

### 13.2 WireGuard Device Log Levels

Set based on command-line flags in `wiretap serve`:

- `--debug (-d)`: Sets device log level to `device.LogLevelVerbose`
- `--quiet (-q)`: Sets device log level to `device.LogLevelSilent`
- Default (neither): Sets device log level to `device.LogLevelError`

Log output destination:
- If `--log (-l)` with `--log-file (-o)`: Logs to specified file.
- If `--quiet` and `--log-file`: Logs only to file (stdout suppressed).
- Otherwise: Logs to stdout.

### 13.3 API Error Responses

All API endpoints follow consistent error handling:

1. Method validation: `405 Method Not Allowed` for wrong HTTP method.
2. Parameter validation: `400 Bad Request` for invalid/missing parameters.
3. Processing errors: `500 Internal Server Error` with error message in body.
4. Success: `200 OK` with appropriate response body.

Error response helper (`writeErr`):
- Sets HTTP status to 500.
- Writes error message string to response body.
- Logs any write errors with `log.Printf("API Error: %v", err)`.

### 13.4 API Client Timeout

- All API requests have a hardcoded **3-second timeout**.
- Timeout errors are returned as-is (e.g., "context deadline exceeded").
- No automatic retries on timeout or any other error.

### 13.5 TCP Forwarding Errors

From `transport/tcp`:

- **Connection refused** (ECONNREFUSED):
  - Detected in `checkDst` when attempting to dial destination.
  - Causes RST to be sent to peer (via WireGuard device behavior).
  - Logged but connection attempt is abandoned.
- **Other dial errors**:
  - Do NOT send RST.
  - Error logged and connection abandoned.
- **Catch timeout**:
  - If connection established but no data exchanged within `CatchTimeout`, destination conn is closed.
  - Prevents resource leaks from port scanners.
- **Proxy errors** during data transfer:
  - Logged with `log.Printf("error copying between connections: %v\n", err)`.
  - Connection is closed but not considered fatal.

### 13.6 UDP Forwarding Errors

From `transport/udp`:

- **ECONNREFUSED**:
  - Detected when writing to closed port.
  - Triggers `sendUnreachable` to send ICMP Port Unreachable to client.
  - Connection is cleaned up.
- **Send/receive errors**:
  - Logged with `log.Println()`.
  - Connection continues (for send errors) or closes (for receive errors).
- **Packet crafting errors**:
  - Logged but packet is dropped.
  - Does not crash the handler.

### 13.7 ICMP Ping Errors

From `transport/icmp`:

- If ping fails (any reason), no echo reply is sent.
- Error is logged and packet is dropped.
- Three ping implementations with fallback:
  1. `go-ping` socket mode (if available).
  2. `go-ping` exec mode (fallback).
  3. `noPing` (no-op fallback if ping not available).

### 13.8 Configuration Parsing Errors

From `peer/` package:

- **File not found**: Fatal error via `check()`.
- **Invalid section header**: Error returned, parsing stops.
- **Missing `=` in key-value**: Error returned.
- **Unknown section**: Error returned.
- **Invalid key**: Ignored (not an error).
- **Duplicate `[Interface]` section**: Error returned.
- **Multiple `[Peer]` sections**: Allowed, each creates a new peer.
- **Peer with no public key**: Silently ignored (not added to config).

### 13.9 Server Startup Errors

From `cmd/serve.go`:

- **No relay AND no E2EE key**: Fatal error.
- **E2EE key present but relay key missing**: Fatal error.
- **E2EE peer key missing**: Warning printed, server runs in simple mode automatically.
- **Invalid localhost IP** (not IPv4): Fatal error.
- **Localhost IP is loopback/multicast/public**: Warning printed, continues.
- **Device creation failure**: Fatal error (panics via `log.Panic()`).

### 13.10 Logging Conventions

- **API requests**: `(client <addr>) - API: <request-uri>`
- **API errors**: `API Error: <error>`
- **Peer added**: `API: Peer Added: <public-key>`
- **API startup**: `API: API listener up`
- **Localhost IP warnings**: `API: WARNING: <message>`
- **Port forward logs**:
  - TCP: `(client [<ip>]:<port>) <- Expose: TCP <- <remote-addr>`
  - UDP: `(client <ip>) <- Expose: UDP <- <remote-addr>`
  - Close: `Closing idle UDP forward: ...`
  - Shutdown: `All routines for UDP forward <addr> successfully shut down`

---

## 14. Edge Cases and Behavioral Quirks

### 14.1 Userspace Bind Issues (`transport/userspace`)

**Known bugs in Go implementation** that should be preserved or explicitly documented:

1. **IPv6 connection never created**:
   - In `Open()`, after creating IPv4 connection, the code checks `if ipv4 != nil` instead of `if ipv6 != nil` before appending IPv6 receive function.
   - Result: `bind.ipv6` is never populated, IPv6 receive function is never added.
   - Impact: IPv6 E2EE traffic may not work correctly.

2. **listenNet uses DialUDP instead of Listen**:
   - Uses `gonet.DialUDP` for both IPv4 and IPv6 paths.
   - Should probably use a proper listener.
   - Current behavior: establishes a "connection" rather than listening.

3. **IPv4 uses udp6**:
   - IPv4 branch uses `udp6` network string in `DialUDP`.
   - Likely unintended, should be `udp4`.

4. **Close only closes IPv4**:
   - `Close()` method only calls `bind.ipv4.Close()`.
   - IPv6 socket (if it existed) would leak.

**Rust port consideration**: Decide whether to replicate these bugs for exact compatibility, or fix them with documentation of the differences.

### 14.2 Config File Numbering

`FindAvailableFilename(filename)` behavior:

- If file exists, appends `_1` before extension.
- If that exists, tries `_2`, `_3`, etc.
- Continues incrementing until an available filename is found.
- No upper limit on number.
- Example: `wiretap.conf` → `wiretap_1.conf` → `wiretap_2.conf`

### 14.3 Simple Mode Filename Override

In `configure` command when `--simple` is set:
- Relay config filename is **forced** to the E2EE config filename.
- Only one file is written (the relay config using the E2EE filename).
- Default result: `wiretap.conf` instead of `wiretap_relay.conf` + `wiretap.conf`.

### 14.4 AllowedIPs as API Address Indicator

Convention: The **last** AllowedIPs entry in an E2EE peer config is treated as the API address.

- Used by `GetApiAddr()` helper.
- Assumed to be a single IP (e.g., `::2/128` or `192.0.2.2/32`).
- Critical for client tools to find servers' API endpoints.
- If this convention is not followed, API calls will fail.

### 14.5 Endpoint Port Inference

`USE_ENDPOINT_PORT = -1` sentinel value:

- When `--port` or `--sport` is set to `-1` (default), port is inferred from endpoint string.
- If endpoint is empty, falls back to `51820`.
- Port extraction: parses endpoint as `host:port` or `[host]:port` (IPv6).

### 14.6 Empty Routes Handling

`--routes` accepts a slice of strings, including empty strings:
- Empty strings in the slice are ignored during processing.
- Allows for default values in flag definitions without causing errors.

### 14.7 DNS Endpoints

`peer.PeerConfig` supports DNS names in endpoints:
- Stored in `endpointDNS` field (separate from resolved endpoint).
- Not resolved at config generation time.
- WireGuard will resolve at runtime.
- Serialized as-is in config files.

### 14.8 Relay Forwarding Behavior

In normal (non-simple) mode:
- Relay stack has IPv4 and IPv6 **forwarding enabled** via `s.SetForwardingDefaultAndAllNICs()`.
- Allows packets to be routed between relay peers.
- E2EE stack does NOT have forwarding enabled.

In simple mode:
- Relay stack does not enable forwarding.
- Direct traffic handling only.

### 14.9 E2EE Handshake Trigger

From README:
- "By default the E2EE handshake will not occur until the Client sends data."
- First packet from client triggers WireGuard handshake.
- May need to ping an IP in routes to trigger initial handshake.
- After first handshake, keepalive maintains connection.

### 14.10 Server Restart Persistence

**Important limitation**: Servers do NOT persist any runtime state.

If a server process exits and is restarted:
- All added clients are forgotten (must be re-added).
- All port forwards are forgotten (must be re-exposed).
- Only the initial peer configuration is remembered (from config file or env vars).

This is a fundamental limitation of the current architecture.

### 14.11 API Address Assignment

API addresses are assigned sequentially from a subnet:
- Default IPv6: starts at `::2` (`.1` reserved for future use).
- Default IPv4: starts at `192.0.2.2`.
- Increment by one for each new server.
- No collision detection or reuse of freed addresses.
- No IPv4/IPv6 coordination (assigned independently).

### 14.12 MTU Calculation

E2EE MTU is always `relay MTU - 80`:
- Default: 1420 - 80 = 1340.
- Accounts for WireGuard overhead of nested tunnel.
- Not configurable independently.
- Hardcoded subtraction of 80 bytes.

### 14.13 Preshared Key Behavior

When `--PSK` flag is used:
- Generated once in `configure`.
- Stored in relay config's preshared key field.
- Applied to the server's relay peer.
- **Not** applied to E2EE peer (no PSK for E2EE).
- Uses WireGuard's `GenPresharedKey()` function (cryptographically random).

### 14.14 Keepalive Inheritance

From `serve` command:
- E2EE peer keepalive interval is taken from `Relay.Peer.keepalive` value.
- Not configured separately.
- Only applies when both relay and E2EE are configured.

### 14.15 Promiscuous Mode

NIC 1 on both relay and E2EE stacks is set to promiscuous mode:
- Allows receiving packets for any destination MAC address.
- Necessary for gVisor's userspace networking.
- Set via `s.SetPromiscuousMode(1, true)`.

### 14.16 Catch Timeout in TCP Forwarding

`CatchTimeout` constant (from flags: `--completion-timeout`):
- Default value (implementation-dependent, typically 5-10 seconds).
- If a TCP connection is established but no data is sent within this timeout, destination connection is closed.
- Prevents resource exhaustion from port scans.
- Source connection remains open (handled by WireGuard keepalive).

---

## 15. SOCKS5 Implementation Details (`ForwardDynamic`)

- Preserve config parsing semantics (including `#@` prefix, ignored comments, and error behavior).
- Preserve API routing, including `expose` tuple key definition and how `RemoteAddr` is determined.
- Preserve gVisor stack behaviors (promiscuous mode, dynamic address add/remove).
- Preserve wireguard IPC formatting and hex key encoding.
- Preserve `FindAvailableFilename` numbering behavior.
- Ensure E2EE MTU is always `relay MTU - 80`.
- Consider mirroring userspace bind quirks unless explicitly fixed (see section 11).

---

## 15. SOCKS5 Implementation Details (`ForwardDynamic`)

The dynamic port forwarding feature uses the `armon/go-socks5` library to provide a SOCKS5 proxy server.

### 15.1 SOCKS5 Server Setup

When `--dynamic` is specified in the `expose` command:

1. A TCP listener is created on the specified `--remote` port on the server.
2. A SOCKS5 server is instantiated with a custom dialer function.
3. The custom dialer:
   - Parses the destination address and port from the SOCKS5 request.
   - Uses `gonet.DialTCPWithBind` to create a connection through the gVisor netstack.
   - Sets the source address to the server's API address (localAddr).
   - Sets the destination to the client's address with the requested port.
   - Routes traffic through the E2EE/Relay network to the client.

### 15.2 SOCKS5 Usage

The destination IP in SOCKS5 requests is **rewritten** by the server. Any IP address can be specified in the SOCKS5 request; the server will always route it to the client's E2EE address. This means:

```bash
curl -x socks5://<server-ip>:8080 http://<any-ip>:80
```

The `<any-ip>` value is effectively ignored for routing purposes - it's the port that matters.

### 15.3 Connection Flow

1. External client connects to SOCKS5 server on remote port.
2. SOCKS5 handshake negotiates connection (no authentication by default).
3. Client sends CONNECT request with destination address and port.
4. Server creates connection to client's E2EE address at the requested port.
5. Data is proxied bidirectionally using `io.Copy`.

### 15.4 Limitations

- No authentication is configured on the SOCKS5 server (uses default `socks5.Config`).
- Only TCP connections are supported (not UDP or BIND).
- The feature does not remember state across server restarts.

---

## 16. Experimental Features

### 16.1 Localhost Server Access (`--localhost-ip`)

**Status**: Experimental, lightly tested. TCP-only, IPv4-only.

This feature allows accessing services on the server's `127.0.0.1` loopback interface without individual port forwards.

#### Configuration

Available in `configure` and `add server` commands via `--localhost-ip <IPv4 address>`:

```bash
wiretap configure --endpoint 7.3.3.1:1337 --routes 10.0.0.0/24 --localhost-ip 192.168.137.137
```

#### Behavior

1. The specified IPv4 address is appended to the client's AllowedIPs with a `/32` mask.
2. The server stores the address in `LocalhostIP` field of the relay config.
3. During server startup, a DNAT rule is added to the gVisor NAT table:
   - Uses `s.IPTables().ReplaceTable(stack.NATID, ...)` 
   - Rule: `-A PREROUTING -p tcp -d <localhost-ip> -j DNAT --to-destination 127.0.0.1`
   - Matches: protocol TCP, destination = localhost-ip
   - Action: DNAT to 127.0.0.1, preserving port
4. Return traffic is automatically NATed back to the original client.

#### Validation and Warnings

On server startup, the implementation checks the provided IP:
- **Fatal error** if the IP is not IPv4
- **Warning** if IP is in loopback range (127.0.0.0/8)
- **Warning** if IP is multicast (224.0.0.0/4)
- **Warning** if IP is not in private ranges (RFC 1918)

Logged as: `API: WARNING: <reason>`

#### Example Usage

```bash
# Server started with --localhost-ip 192.168.137.137
# Access service on 127.0.0.1:8080 from client:
curl http://192.168.137.137:8080
```

#### Limitations

1. **TCP only** - UDP traffic to the localhost IP is not redirected.
2. **IPv4 only** - IPv6 loopback `::1` cannot be targeted due to NAT limitations.
3. **Single address** - Only one localhost IP can be configured per server.
4. **127.0.0.0/8 restriction** - Only `127.0.0.1` is reachable, not other addresses in the loopback range.
5. **Added clients** - New clients added after deployment don't automatically get the localhost IP in their routes.
6. **No persistence** - Not preserved if the server process exits.

#### Implementation Location

- **Configuration**: `cmd/configure.go`, `cmd/add_server.go` - sets `LocalhostIP` field
- **Server setup**: `cmd/serve.go` - applies NAT rule via `s.IPTables().ReplaceTable()`
- **Storage**: `peer/config.go` - `Config.localhostIP` field

### 16.2 TCP Tunneling

**Status**: Experimental. Use as last resort only. Performance will suffer.

WireGuard uses UDP for transport. If UDP is completely blocked (inbound and outbound), WireGuard traffic can be tunneled over TCP using external tools. This is **strongly discouraged** due to TCP-over-TCP performance issues.

#### Using Chisel

Chisel (https://github.com/jpillora/chisel) provides cross-platform UDP-over-TCP tunneling.

**On Wiretap Client** (runs chisel server):
```bash
./chisel server --port 8080
```

**On Wiretap Server** (runs chisel client):
```bash
./chisel client <wiretap-client-addr>:8080 61820:0.0.0.0:51820/udp
```
- `8080`: chisel listening port on client
- `61820`: local UDP port on server (forwarded to client)
- `51820`: WireGuard listening port on client

**Start Wiretap Server** with forwarded port:
```bash
WIRETAP_RELAY_INTERFACE_PRIVATEKEY=<key> \
WIRETAP_RELAY_PEER_PUBLICKEY=<key> \
WIRETAP_E2EE_INTERFACE_PRIVATEKEY=<key> \
WIRETAP_E2EE_PEER_PUBLICKEY=<key> \
WIRETAP_E2EE_PEER_ENDPOINT=172.16.0.1:51821 \
./wiretap serve --endpoint localhost:61820
```

#### Using SOCAT

Alternative if SOCAT is available:

**On Wiretap Server**:
```bash
socat udp4-listen:61820,reuseaddr,fork tcp:<wiretap-client-addr>:61820
```

**On Wiretap Client**:
```bash
socat tcp4-listen:61820,reuseaddr,fork udp:localhost:51820
```

**Start Wiretap Server**:
```bash
./wiretap serve --endpoint localhost:61820 <other-args>
```

#### Performance Considerations

From WireGuard's Known Limitations:
> "WireGuard explicitly does not support tunneling over TCP, due to the classically terrible network performance of tunneling TCP-over-TCP."

When application TCP traffic is tunneled through WireGuard (which uses UDP), and that UDP is then tunneled through TCP, you get **TCP-over-TCP**, causing:
- Duplicate retransmission logic
- Exponential backoff conflicts
- Severe throughput degradation
- High latency under packet loss

### 16.3 Add Clients To Any Server

**Status**: Experimental. Limited functionality compared to first-hop client attachment.

Normally, new clients are added to first-hop servers (servers directly connected to the original client). This experimental feature allows attaching clients to any server in the network using the `--server-address` flag.

#### Command

```bash
./wiretap add client --server-address <api-address|nickname> --endpoint <ip:port> --port <port>
```

#### Behavior

1. New client is added to the specified server's relay and E2EE peer lists via API.
2. Client receives routes from that server's branch of the topology.
3. Client can access all servers in the attached branch.
4. **Limitation**: Client CANNOT access servers in other branches that only connect through the original client.

#### Topology Restrictions

Clients do not route traffic from other clients. Consider this topology:

```
         ┌──────┐
         │  C0  │  (original client)
         └┬────┬┘
          │    │
    ┌─────┴┐  ┌┴─────┐
    │  S0  │  │  S2  │
    └──┬───┘  └──┬───┘
       │         │
    ┌──┴───┐  ┌──┴───┐
    │  S1  │  │  S3  │◄─── C1 attached here
    └──────┘  └──────┘
```

- C1 (attached to S3) can access: S2, S3 (right branch)
- C1 **cannot** access: S0, S1 (left branch, only reachable through C0)

#### Manual Configuration

After adding a client to an arbitrary server, you may need to manually edit the generated `wiretap.conf`:

- **Remove routes** that conflict with the new client's local network.
- Example: If S3 has route `10.2.0.0/16` but C1 is on that subnet, remove that AllowedIPs entry.
- **Keep**: API address and other desired routes.

#### Limitations

1. Cannot access servers in branches not connected to the attachment point.
2. Server restarts forget about added clients (same as normal client addition).
3. All servers must be deployed before adding clients.
4. Route conflicts require manual config editing.

---

## 17. Clipboard Support

The `configure` and `add server` commands support copying server startup commands to the system clipboard.

### Implementation

Uses the `atotto/clipboard` library (cross-platform clipboard access).

### Usage

Add the `--clipboard` (or `-c`) flag:

```bash
./wiretap configure --endpoint 1.2.3.4:51820 --routes 10.0.0.0/24 --clipboard
```

### Behavior

1. After generating configs, the **POSIX shell** server command is copied to the clipboard.
2. Output shows clipboard status:
   - Success: `clipboard: successfully copied` (green)
   - Failure: `clipboard: error copying to clipboard: <error>` (red)

### Clipboard Contents

The exact POSIX shell command that would be printed to stdout, for example:

```bash
WIRETAP_RELAY_INTERFACE_PRIVATEKEY=<key> WIRETAP_RELAY_PEER_PUBLICKEY=<key> ... ./wiretap serve
```

### Platform Support

Depends on platform-specific clipboard mechanisms:
- **Linux**: xclip, xsel, wl-clipboard (Wayland), or termux-clipboard (Android)
- **macOS**: pbcopy
- **Windows**: clip.exe
- **WSL**: clip.exe via /mnt/c/Windows/System32/clip.exe

If no clipboard utility is available, the command returns an error which is shown in the output.

---

## 18. Quick Reference Tables

### 18.1 API Endpoints

- `GET /ping` -> `pong`
- `GET /serverinfo` -> JSON: `{ RelayConfig, E2EEConfig }`
- `GET /serverinterfaces` -> JSON list of `{ Name, Addrs[] }`
- `GET /allocate?type=0|1` -> JSON `NetworkState`
- `POST /addpeer?interface=0|1` -> add peer
- `POST /addallowedips` -> add allowed IPs to relay peer
- `POST /expose` -> expose/list/delete ports

### 18.2 Ports

- WireGuard Relay listen port: `51820` (default)
- WireGuard E2EE listen port: `51821`
- API HTTP port: `80`

---

## 19. Compatibility Notes for Rust Port

### 19.1 Must Preserve

These behaviors must be exactly replicated for compatibility:

1. **Config parsing semantics**:
   - `#@` prefix for Wiretap extensions
   - Ignored comment lines (except `#@`)
   - Section parsing (double newline separation)
   - Error behavior (unknown sections, missing `=`)
   - Peer without public key is silently dropped

2. **API routing and contracts**:
   - Exact endpoint paths and methods
   - JSON request/response formats
   - Status codes and error messages
   - Expose tuple key definition: `(RemoteAddr, LocalPort, RemotePort, Protocol)`
   - `RemoteAddr` determination from `r.RemoteAddr`

3. **Address allocation sequence**:
   - Sequential increment with `.Next()`
   - Separate indices for clients and servers
   - Initial address reservation on server startup
   - No gaps or reuse

4. **AllowedIPs convention**:
   - Last entry in E2EE peer is the API address
   - Used by `GetApiAddr()` helper throughout codebase

5. **MTU calculation**:
   - E2EE MTU = relay MTU - 80
   - Hardcoded subtraction

6. **File numbering**:
   - `FindAvailableFilename` appends `_N` before extension
   - Increments until available

7. **IPC format**:
   - WireGuard IPC protocol
   - Hex-encoded keys
   - Specific field ordering and formatting

8. **Simple mode behavior**:
   - Omits E2EE interface
   - Forces relay filename to E2EE filename
   - Single config file output

9. **Port inference**:
   - `USE_ENDPOINT_PORT = -1` sentinel
   - Extraction from endpoint string
   - Fallback to 51820

10. **Localhost redirection**:
    - DNAT rule format
    - IPv4-only restriction
    - Port preservation
    - Warnings for unsafe IPs

### 19.2 Known Bugs to Address

Consider **fixing** these bugs in Rust port (with documentation):

1. **Userspace bind IPv6 bug**:
   - IPv6 connection never created due to wrong conditional
   - Should check `if ipv6 != nil` not `if ipv4 != nil`
   - Fix and document difference from Go version

2. **Userspace bind DialUDP vs Listen**:
   - Should use proper listener instead of DialUDP
   - Fix for correctness

3. **IPv4 using udp6**:
   - Should use `udp4` for IPv4 branch
   - Fix for correctness

4. **Close only closes IPv4**:
   - Should close both IPv4 and IPv6 sockets
   - Fix to prevent resource leaks

### 19.3 Optional Enhancements

Consider implementing with feature flags or configuration:

1. **Server state persistence**:
   - Save added clients and port forwards to disk
   - Restore on restart
   - Backward-compatible extension

2. **API authentication**:
   - Add optional API key or certificate-based auth
   - SOCKS5 authentication support
   - Disabled by default for compatibility

3. **Address reuse**:
   - Track freed addresses when clients disconnect
   - Reuse instead of always incrementing
   - More efficient for long-running deployments

4. **Idle timeout for UDP**:
   - Make `UDP_TIMEOUT` configurable
   - Currently hardcoded to 60 seconds

5. **TCP catch timeout**:
   - Make configurable via flag
   - Currently uses flag but default is unclear

6. **IPv6-only mode**:
   - Fully disable IPv4 (not just in config generation)
   - Reduce memory footprint

### 19.4 Behavioral Preservation

Preserve these exact behaviors:

1. **gVisor stack setup**:
   - Promiscuous mode on NIC 1
   - Forwarding enabled in relay (normal mode only)
   - Dynamic address add/remove via `ConnCounts`

2. **TCP forwarding**:
   - Catch timeout after connection
   - RST on ECONNREFUSED only
   - No RST on other errors

3. **UDP forwarding**:
   - Port reuse per source address
   - ICMP unreachable on ECONNREFUSED
   - Manual packet crafting for responses

4. **ICMP handling**:
   - Echo request/reply only
   - Ping fallback chain (socket → exec → noop)
   - Manual reply construction

5. **SOCKS5**:
   - No authentication
   - TCP-only (no UDP or BIND support)
   - Destination IP rewrite to client address

6. **Logging format**:
   - API request logs: `(client <addr>) - API: <uri>`
   - Port forward logs: specific format per protocol
   - Error logs: `log.Printf` style

7. **Error handling**:
   - Fatal on unrecoverable errors (via `check()`)
   - Log and continue for forwarding errors
   - 3-second API timeout

### 19.5 Dependencies to Evaluate

Go implementation uses these key dependencies:

1. **wireguard-go** (`golang.zx2c4.com/wireguard`):
   - Core WireGuard implementation
   - Consider: `boringtun` (Rust WireGuard) or other Rust alternatives

2. **gVisor netstack** (`gvisor.dev/gvisor`):
   - Userspace TCP/IP stack
   - Consider: `smoltcp`, `lwip`, or custom implementation

3. **go-socks5** (`github.com/armon/go-socks5`):
   - SOCKS5 server
   - Rust alternatives available

4. **go-reuseport** (for UDP ICMP handling):
   - Socket reuse for ICMP error reception
   - Rust alternatives or raw socket APIs

5. **atotto/clipboard**:
   - Cross-platform clipboard access
   - Rust alternatives: `cli-clipboard`, `copypasta`

6. **cobra** (CLI):
   - Command framework
   - Rust alternatives: `clap`, `structopt`

7. **viper** (config):
   - Configuration management
   - Rust alternatives: `config`, `figment`

### 19.6 Testing Priorities

For Rust port, prioritize testing:

1. **Config parsing**:
   - All valid WireGuard configs
   - Wiretap extensions (`#@` prefix)
   - Edge cases (empty lines, comments, unknown sections)
   - Filename numbering

2. **API contracts**:
   - All endpoint request/response formats
   - Error status codes
   - Thread safety of state updates
   - Concurrent allocations

3. **Address allocation**:
   - Sequential assignment
   - IPv4 and IPv6 independence
   - Wraparound behavior (if applicable)

4. **Port forwarding**:
   - TCP static forward
   - UDP static forward with tracking
   - SOCKS5 dynamic forward
   - Concurrent connections
   - Timeout behavior

5. **ICMP handling**:
   - Echo request/reply
   - Port unreachable generation
   - Packet crafting correctness

6. **Localhost redirection**:
   - DNAT rule application
   - Port preservation
   - IPv4-only restriction

7. **Error paths**:
   - All API error conditions
   - Network errors (timeout, refused)
   - Invalid configurations
   - Resource exhaustion
