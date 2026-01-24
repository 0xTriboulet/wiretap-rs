//! WireGuard peer configuration and key management.
//!
//! This module provides types and functions for managing WireGuard peers, keys, and
//! configurations. It handles:
//!
//! - Key generation and parsing (private, public, and preshared keys)
//! - Peer configuration (endpoints, allowed IPs, keepalive)
//! - Interface configuration parsing and generation
//! - WireGuard configuration file I/O
//!
//! # Key Types
//!
//! WireGuard uses Curve25519 keys:
//! - **Private keys**: Secret keys used to decrypt incoming packets
//! - **Public keys**: Derived from private keys, used to identify peers
//! - **Preshared keys**: Optional symmetric keys for additional security
//!
//! # Examples
//!
//! ## Generating and Using Keys
//!
//! ```rust
//! use wiretap_rs::peer::Key;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Generate a new private key
//! let private_key = Key::generate_private()?;
//!
//! // Derive the corresponding public key
//! let public_key = private_key.public_key();
//!
//! // Convert to base64 for WireGuard configuration
//! println!("PublicKey = {}", public_key.to_base64());
//!
//! // Parse a key from base64 string
//! let parsed = Key::parse("abcd1234...base64...")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Creating a Peer Configuration
//!
//! ```rust,no_run
//! use wiretap_rs::peer::PeerConfig;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Create a new peer with generated keys
//! let mut peer = PeerConfig::new()?;
//!
//! // Configure the peer
//! peer.set_endpoint("192.168.1.1:51820")?;
//! peer.set_keepalive(25)?;
//! peer.add_allowed_ip("10.0.0.0/24")?;
//! peer.set_nickname("my-server");
//!
//! println!("Peer public key: {}", peer.public_key());
//! # Ok(())
//! # }
//! ```
//!
//! ## Parsing Configuration Files
//!
//! ```rust,no_run
//! use wiretap_rs::peer::parse_config_file;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Parse a WireGuard configuration file
//! let config = parse_config_file("wiretap.conf")?;
//!
//! println!("Interface address: {:?}", config.addresses());
//! println!("Number of peers: {}", config.peers().len());
//!
//! for peer in config.peers() {
//!     println!("Peer: {}", peer.public_key());
//! }
//! # Ok(())
//! # }
//! ```

use anyhow::{Result, anyhow};
use base64::Engine;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use owo_colors::OwoColorize;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::{fs, str::FromStr};
use x25519_dalek::{PublicKey, StaticSecret};

const CUSTOM_PREFIX: &str = "#@";

/// A WireGuard cryptographic key (private, public, or preshared).
///
/// Wraps a 32-byte Curve25519 key used for WireGuard encryption. Can represent:
/// - Private keys (secret, used to derive public keys)
/// - Public keys (derived from private keys, identifies peers)
/// - Preshared keys (optional symmetric key for additional security)
///
/// Keys are typically encoded as base64 strings in WireGuard configurations.
///
/// # Examples
///
/// ```rust
/// use wiretap_rs::peer::Key;
///
/// # fn example() -> anyhow::Result<()> {
/// // Generate a new private key
/// let private = Key::generate_private()?;
///
/// // Derive the public key
/// let public = private.public_key();
///
/// // Convert to base64 string
/// let encoded = public.to_base64();
/// println!("Public key: {}", encoded);
///
/// // Parse from base64
/// let parsed = Key::parse(&encoded)?;
/// assert_eq!(parsed, public);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Key([u8; 32]);

impl Key {
    /// Generates a new random private key using a cryptographically secure RNG.
    ///
    /// # Returns
    ///
    /// A new randomly generated private key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wiretap_rs::peer::Key;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let private_key = Key::generate_private()?;
    /// let public_key = private_key.public_key();
    /// println!("Generated public key: {}", public_key);
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_private() -> Result<Self> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Ok(Self(bytes))
    }

    /// Generates a new random preshared key using a cryptographically secure RNG.
    ///
    /// Preshared keys provide an additional layer of symmetric encryption on top of
    /// the standard WireGuard handshake.
    ///
    /// # Returns
    ///
    /// A new randomly generated preshared key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wiretap_rs::peer::Key;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let preshared = Key::generate_preshared()?;
    /// println!("Preshared key: {}", preshared.to_base64());
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_preshared() -> Result<Self> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Ok(Self(bytes))
    }

    /// Derives the public key from this private key.
    ///
    /// Uses Curve25519 scalar multiplication to compute the public key.
    ///
    /// # Returns
    ///
    /// The corresponding public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wiretap_rs::peer::Key;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let private = Key::generate_private()?;
    /// let public = private.public_key();
    /// assert_ne!(private.to_base64(), public.to_base64());
    /// # Ok(())
    /// # }
    /// ```
    pub fn public_key(&self) -> Self {
        let secret = StaticSecret::from(self.0);
        let public = PublicKey::from(&secret);
        Self(public.to_bytes())
    }

/// Parses a key from a base64 or hexadecimal string.
///
/// Accepts both standard base64 encoding (44 characters) and hexadecimal
/// encoding (64 characters).
///
/// # Arguments
///
/// * `value` - The encoded key string
///
/// # Returns
///
/// The parsed key.
///
/// # Errors
///
/// Returns an error if:
/// - The encoding is invalid
/// - The decoded length is not 32 bytes
///
/// # Example
///
/// ```rust
/// use wiretap_rs::peer::Key;
///
/// # fn example() -> anyhow::Result<()> {
/// // Parse from base64
/// let key = Key::generate_private()?;
/// let encoded = key.to_base64();
/// let parsed = Key::parse(&encoded)?;
/// assert_eq!(key, parsed);
/// # Ok(())
/// # }
/// ```
pub fn parse(value: &str) -> Result<Self> {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) {
            if decoded.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&decoded);
                return Ok(Self(bytes));
            }
        }

        let decoded_hex = hex::decode(value).map_err(|_| anyhow!("invalid key encoding"))?;
        if decoded_hex.len() != 32 {
            return Err(anyhow!("invalid key length"));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded_hex);
        Ok(Self(bytes))
    }

    /// Encodes this key as a base64 string.
    ///
    /// # Returns
    ///
    /// A 44-character base64 string suitable for WireGuard configuration files.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wiretap_rs::peer::Key;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let key = Key::generate_private()?;
    /// let encoded = key.to_base64();
    /// assert_eq!(encoded.len(), 44);
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_base64(self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Creates a zero-filled key (all bytes are 0).
    ///
    /// Used internally for placeholder values. Not suitable for cryptographic use.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wiretap_rs::peer::Key;
    ///
    /// let zero = Key::zero();
    /// assert_eq!(zero.to_bytes(), [0u8; 32]);
    /// ```
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Returns the raw 32-byte key material by value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wiretap_rs::peer::Key;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let key = Key::generate_private()?;
    /// let bytes = key.to_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the raw 32-byte key material by reference.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wiretap_rs::peer::Key;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let key = Key::generate_private()?;
    /// let bytes = key.as_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Key::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Configuration for a single WireGuard peer.
///
/// Contains all the information needed to configure a WireGuard peer connection,
/// including keys, endpoint, allowed IPs, and keepalive settings.
///
/// # Examples
///
/// ```rust,no_run
/// use wiretap_rs::peer::PeerConfig;
///
/// # fn example() -> anyhow::Result<()> {
/// // Create a new peer with generated keys
/// let mut peer = PeerConfig::new()?;
///
/// // Configure endpoint and allowed IPs
/// peer.set_endpoint("192.168.1.1:51820")?;
/// peer.add_allowed_ip("10.0.0.0/24")?;
/// peer.add_allowed_ip("fd00::/48")?;
/// peer.set_keepalive(25)?;
///
/// println!("Public key: {}", peer.public_key());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerConfig {
    public_key: Key,
    preshared_key: Option<Key>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    endpoint_dns: Option<String>,
    keepalive: Option<u16>,
    private_key: Option<Key>,
    nickname: Option<String>,
}

/// Arguments for constructing a PeerConfig.
///
/// Used when parsing command-line arguments or other external configurations
/// to build a PeerConfig instance.
#[derive(Clone, Default)]
pub struct PeerConfigArgs {
    /// Base64-encoded public key string.
    pub public_key: Option<String>,
    
    /// Base64-encoded preshared key string.
    pub preshared_key: Option<String>,
    
    /// Endpoint in the format "host:port".
    pub endpoint: Option<String>,
    
    /// Persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<u16>,
    
    /// Whether to replace existing allowed IPs.
    pub replace_allowed_ips: bool,
    
    /// List of CIDR-notation allowed IPs.
    pub allowed_ips: Vec<String>,
    
    /// Base64-encoded private key string.
    pub private_key: Option<String>,
    
    /// Optional nickname for the peer.
    pub nickname: Option<String>,
}

impl PeerConfig {
    pub fn new() -> Result<Self> {
        let private_key = Key::generate_private()?;
        Ok(Self {
            public_key: private_key.public_key(),
            preshared_key: None,
            allowed_ips: Vec::new(),
            endpoint: None,
            endpoint_dns: None,
            keepalive: None,
            private_key: Some(private_key),
            nickname: None,
        })
    }

    fn empty() -> Self {
        Self {
            public_key: Key::zero(),
            preshared_key: None,
            allowed_ips: Vec::new(),
            endpoint: None,
            endpoint_dns: None,
            keepalive: None,
            private_key: None,
            nickname: None,
        }
    }

    pub fn from_args(args: PeerConfigArgs) -> Result<Self> {
        let mut peer = Self::new()?;
        if let Some(key) = args.public_key {
            peer.set_public_key(&key)?;
        }
        if let Some(key) = args.preshared_key {
            peer.set_preshared_key(&key)?;
        }
        if let Some(endpoint) = args.endpoint {
            peer.set_endpoint(&endpoint)?;
        }
        if let Some(keepalive) = args.persistent_keepalive {
            peer.set_keepalive(keepalive)?;
        }
        if !args.allowed_ips.is_empty() {
            peer.set_allowed_ips(&args.allowed_ips)?;
        }
        if let Some(key) = args.private_key {
            peer.set_private_key(&key)?;
        }
        if let Some(nickname) = args.nickname {
            peer.set_nickname(&nickname);
        }
        if args.replace_allowed_ips {
            // no-op in this phase
        }
        Ok(peer)
    }

    pub fn set_public_key(&mut self, key: &str) -> Result<()> {
        let parsed = Key::parse(key)?;
        self.public_key = parsed;
        self.private_key = None;
        Ok(())
    }

    pub fn set_preshared_key(&mut self, key: &str) -> Result<()> {
        let parsed = Key::parse(key)?;
        self.preshared_key = Some(parsed);
        Ok(())
    }

    pub fn set_private_key(&mut self, key: &str) -> Result<()> {
        let parsed = Key::parse(key)?;
        self.private_key = Some(parsed);
        self.public_key = parsed.public_key();
        Ok(())
    }

    pub fn set_endpoint(&mut self, endpoint: &str) -> Result<()> {
        if let Ok(addr) = SocketAddr::from_str(endpoint) {
            self.endpoint = Some(addr);
            self.endpoint_dns = None;
            return Ok(());
        }

        let (host, port) = split_host_port(endpoint)?;
        let host_addr = IpAddr::from_str(host).ok();
        if let Some(host_addr) = host_addr {
            let socket = SocketAddr::new(host_addr, port);
            self.endpoint = Some(socket);
            self.endpoint_dns = None;
        } else {
            self.endpoint = None;
            self.endpoint_dns = Some(endpoint.to_string());
        }
        Ok(())
    }

    pub fn set_keepalive(&mut self, seconds: u16) -> Result<()> {
        if seconds == 0 {
            return Err(anyhow!("keepalive must be > 0"));
        }
        self.keepalive = Some(seconds);
        Ok(())
    }

    pub fn set_allowed_ips(&mut self, allowed_ips: &[String]) -> Result<()> {
        self.allowed_ips.clear();
        for ip in allowed_ips {
            self.add_allowed_ip(ip)?;
        }
        Ok(())
    }

    pub fn add_allowed_ip(&mut self, ip: &str) -> Result<()> {
        if ip.trim().is_empty() {
            return Ok(());
        }
        let parsed = IpNet::from_str(ip)?;
        self.allowed_ips.push(parsed);
        Ok(())
    }

    pub fn set_nickname(&mut self, nickname: &str) {
        if !nickname.is_empty() {
            self.nickname = Some(nickname.to_string());
        }
    }

    pub fn nickname(&self) -> Option<&str> {
        self.nickname.as_deref()
    }

    pub fn public_key(&self) -> Key {
        self.public_key
    }

    pub fn private_key(&self) -> Option<Key> {
        self.private_key
    }

    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    pub fn endpoint_dns(&self) -> Option<&str> {
        self.endpoint_dns.as_deref()
    }

    pub fn allowed_ips(&self) -> &[IpNet] {
        &self.allowed_ips
    }

    pub fn keepalive(&self) -> Option<u16> {
        self.keepalive
    }

    pub fn preshared_key(&self) -> Option<Key> {
        self.preshared_key
    }

    pub fn api_addr(&self) -> Option<IpAddr> {
        self.allowed_ips.last().map(|net| net.addr())
    }

    pub fn as_file(&self) -> String {
        let mut s = String::new();
        s.push_str("[Peer]\n");
        if let Some(nickname) = &self.nickname {
            s.push_str(&format!("{} Nickname = {}\n", CUSTOM_PREFIX, nickname));
        }
        s.push_str(&format!("PublicKey = {}\n", self.public_key));
        if let Some(key) = &self.preshared_key {
            s.push_str(&format!("PresharedKey = {}\n", key));
        }
        if !self.allowed_ips.is_empty() {
            let mut allowed = Vec::new();
            for ip in &self.allowed_ips {
                allowed.push(ip.to_string());
            }
            s.push_str(&format!("AllowedIPs = {}\n", allowed.join(",")));
        }
        if let Some(endpoint) = self.endpoint {
            s.push_str(&format!("Endpoint = {}\n", endpoint));
        } else if let Some(endpoint) = &self.endpoint_dns {
            s.push_str(&format!("Endpoint = {}\n", endpoint));
        }
        if let Some(keepalive) = self.keepalive {
            s.push_str(&format!("PersistentKeepalive = {}\n", keepalive));
        }
        s
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    private_key: Key,
    listen_port: Option<u16>,
    mtu: Option<u16>,
    peers: Vec<PeerConfig>,
    addresses: Vec<IpNet>,
    localhost_ip: Option<Ipv4Addr>,
    preshared_key: Option<Key>,
}

#[derive(Clone, Default)]
pub struct ConfigArgs {
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
    pub peers: Vec<PeerConfigArgs>,
    pub addresses: Vec<String>,
    pub localhost_ip: Option<String>,
}

impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            private_key: Key::generate_private()?,
            listen_port: None,
            mtu: None,
            peers: Vec::new(),
            addresses: Vec::new(),
            localhost_ip: None,
            preshared_key: None,
        })
    }

    pub fn empty() -> Self {
        Self {
            private_key: Key::zero(),
            listen_port: None,
            mtu: None,
            peers: Vec::new(),
            addresses: Vec::new(),
            localhost_ip: None,
            preshared_key: None,
        }
    }

    pub fn from_args(args: ConfigArgs) -> Result<Self> {
        let mut config = Self::new()?;
        if let Some(key) = args.private_key {
            config.set_private_key(&key)?;
        }
        if let Some(port) = args.listen_port {
            config.set_port(port)?;
        }
        if let Some(mtu) = args.mtu {
            config.set_mtu(mtu)?;
        }
        if !args.peers.is_empty() {
            for peer_args in args.peers {
                let peer = PeerConfig::from_args(peer_args)?;
                config.add_peer(peer);
            }
        }
        if !args.addresses.is_empty() {
            config.set_addresses(&args.addresses)?;
        }
        if let Some(ip) = args.localhost_ip {
            config.set_localhost_ip(&ip)?;
        }
        Ok(config)
    }

    pub fn set_private_key(&mut self, key: &str) -> Result<()> {
        self.private_key = Key::parse(key)?;
        Ok(())
    }

    pub fn private_key(&self) -> Key {
        self.private_key
    }

    pub fn public_key(&self) -> Key {
        self.private_key.public_key()
    }

    pub fn gen_preshared_key(&mut self) -> Result<()> {
        self.preshared_key = Some(Key::generate_preshared()?);
        Ok(())
    }

    pub fn set_preshared_key(&mut self, key: &str) -> Result<()> {
        self.preshared_key = Some(Key::parse(key)?);
        Ok(())
    }

    pub fn preshared_key(&self) -> Option<Key> {
        self.preshared_key
    }

    pub fn set_port(&mut self, port: u16) -> Result<()> {
        if port == 0 {
            return Err(anyhow!("invalid port"));
        }
        self.listen_port = Some(port);
        Ok(())
    }

    pub fn port(&self) -> Option<u16> {
        self.listen_port
    }

    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        if mtu == 0 {
            return Err(anyhow!("invalid mtu"));
        }
        self.mtu = Some(mtu);
        Ok(())
    }

    pub fn mtu(&self) -> Option<u16> {
        self.mtu
    }

    pub fn add_peer(&mut self, peer: PeerConfig) {
        self.peers.push(peer);
    }

    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    pub fn peers_mut(&mut self) -> &mut Vec<PeerConfig> {
        &mut self.peers
    }

    pub fn set_addresses(&mut self, addrs: &[String]) -> Result<()> {
        self.addresses.clear();
        for addr in addrs {
            self.add_address(addr)?;
        }
        Ok(())
    }

    pub fn add_address(&mut self, addr: &str) -> Result<()> {
        if addr.trim().is_empty() {
            return Ok(());
        }
        let parsed = IpNet::from_str(addr)?;
        self.addresses.push(parsed);
        Ok(())
    }

    pub fn addresses(&self) -> &[IpNet] {
        &self.addresses
    }

    pub fn set_localhost_ip(&mut self, value: &str) -> Result<()> {
        let parsed = Ipv4Addr::from_str(value)?;
        self.localhost_ip = Some(parsed);
        Ok(())
    }

    pub fn localhost_ip(&self) -> Option<Ipv4Addr> {
        self.localhost_ip
    }

    pub fn as_peer(&self) -> Result<PeerConfig> {
        let mut peer = PeerConfig::new()?;
        peer.set_private_key(&self.private_key.to_string())?;
        Ok(peer)
    }

    pub fn as_file(&self) -> String {
        let mut s = String::new();
        s.push_str("[Interface]\n");
        s.push_str(&format!("PrivateKey = {}\n", self.private_key));
        for address in &self.addresses {
            s.push_str(&format!("Address = {}\n", address));
        }
        if let Some(port) = self.listen_port {
            s.push_str(&format!("ListenPort = {}\n", port));
        }
        if let Some(mtu) = self.mtu {
            s.push_str(&format!("MTU = {}\n", mtu));
        }
        if let Some(localhost) = self.localhost_ip {
            s.push_str(&format!("LocalhostIP = {}\n", localhost));
        }
        for peer in &self.peers {
            s.push_str("\n");
            s.push_str(&peer.as_file());
        }
        s
    }

    pub fn as_shareable_file(&self) -> String {
        let mut s = String::new();
        s.push_str("[Peer]\n");
        s.push_str(&format!("PublicKey = {}\n", self.public_key()));
        if let Some(key) = self.preshared_key {
            s.push_str(&format!("PresharedKey = {}\n", key));
        }
        s.push_str("AllowedIPs = 0.0.0.0/32\n");
        s
    }
}

pub fn parse_config_file(path: &str) -> Result<Config> {
    let contents = fs::read_to_string(path)?;
    parse_config(&contents)
}

pub fn parse_config(contents: &str) -> Result<Config> {
    let mut config = Config::new()?;

    for section in contents.split("\n\n") {
        let mut lines = section.lines();
        let Some(header) = lines.next() else { continue };
        if header.trim().is_empty() {
            continue;
        }
        if header.trim_start().starts_with('#') {
            continue;
        }
        match header.trim().to_ascii_lowercase().as_str() {
            "[interface]" => {
                for line in lines {
                    if line.trim().is_empty() || line.trim_start().starts_with('#') {
                        continue;
                    }
                    let (key, value) = parse_config_line(line)?;
                    match key.as_str() {
                        "privatekey" => config.set_private_key(&value)?,
                        "address" => config.add_address(&value)?,
                        "listenport" => config.set_port(value.parse::<u16>()?)?,
                        "mtu" => config.set_mtu(value.parse::<u16>()?)?,
                        "localhostip" => config.set_localhost_ip(&value)?,
                        _ => {}
                    }
                }
            }
            "[peer]" => {
                let mut peer = PeerConfig::empty();
                for line in lines {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let mut line = line.trim().to_string();
                    if line.starts_with(CUSTOM_PREFIX) {
                        line = line[CUSTOM_PREFIX.len()..].trim().to_string();
                    } else if line.starts_with('#') {
                        continue;
                    }
                    let (key, value) = parse_config_line(&line)?;
                    match key.as_str() {
                        "endpoint" => peer.set_endpoint(&value)?,
                        "allowedips" => {
                            let parts = value
                                .split(',')
                                .map(|v| v.trim().to_string())
                                .collect::<Vec<_>>();
                            peer.set_allowed_ips(&parts)?;
                        }
                        "publickey" => peer.set_public_key(&value)?,
                        "presharedkey" => peer.set_preshared_key(&value)?,
                        "persistentkeepalive" => peer.set_keepalive(value.parse::<u16>()?)?,
                        "nickname" => peer.set_nickname(&value),
                        _ => {}
                    }
                }

                if peer.public_key() != Key::zero() {
                    config.add_peer(peer);
                }
            }
            _ => {
                return Err(anyhow!("unknown configuration section: {}", header.trim()));
            }
        }
    }

    Ok(config)
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub relay: Config,
    pub e2ee: Option<Config>,
}

pub fn parse_server_file(path: &str) -> Result<ServerConfig> {
    let contents = fs::read_to_string(path)?;
    parse_server_config(&contents)
}

pub fn parse_server_config(contents: &str) -> Result<ServerConfig> {
    let mut relay = Config::new()?;
    let mut e2ee = Config::new()?;

    let mut relay_peer = PeerConfig::empty();
    let mut e2ee_peer = PeerConfig::empty();
    let mut has_e2ee = false;

    for section in contents.split("\n\n") {
        let mut lines = section.lines();
        let Some(header) = lines.next() else { continue };
        if header.trim().is_empty() {
            continue;
        }
        if header.trim_start().starts_with('#') {
            continue;
        }
        match header.trim().to_ascii_lowercase().as_str() {
            "[relay.interface]" => {
                for line in lines {
                    if line.trim().is_empty() || line.trim_start().starts_with('#') {
                        continue;
                    }
                    let (key, value) = parse_config_line(line)?;
                    match key.as_str() {
                        "privatekey" => relay.set_private_key(&value)?,
                        "ipv4" => relay.add_address(&format!("{}/32", value))?,
                        "ipv6" => relay.add_address(&format!("{}/128", value))?,
                        "port" => relay.set_port(value.parse::<u16>()?)?,
                        "mtu" => relay.set_mtu(value.parse::<u16>()?)?,
                        "localhostip" => relay.set_localhost_ip(&value)?,
                        _ => {}
                    }
                }
            }
            "[relay.peer]" => {
                for line in lines {
                    if line.trim().is_empty() || line.trim_start().starts_with('#') {
                        continue;
                    }
                    let (key, value) = parse_config_line(line)?;
                    match key.as_str() {
                        "allowed" => {
                            let parts = value
                                .split(',')
                                .map(|v| v.trim().to_string())
                                .collect::<Vec<_>>();
                            relay_peer.set_allowed_ips(&parts)?;
                        }
                        "publickey" => relay_peer.set_public_key(&value)?,
                        "presharedkey" => relay_peer.set_preshared_key(&value)?,
                        "endpoint" => relay_peer.set_endpoint(&value)?,
                        _ => {}
                    }
                }
            }
            "[e2ee.interface]" => {
                has_e2ee = true;
                for line in lines {
                    if line.trim().is_empty() || line.trim_start().starts_with('#') {
                        continue;
                    }
                    let (key, value) = parse_config_line(line)?;
                    match key.as_str() {
                        "privatekey" => e2ee.set_private_key(&value)?,
                        "api" => e2ee.add_address(&format!("{}/128", value))?,
                        _ => {}
                    }
                }
            }
            "[e2ee.peer]" => {
                has_e2ee = true;
                for line in lines {
                    if line.trim().is_empty() || line.trim_start().starts_with('#') {
                        continue;
                    }
                    let (key, value) = parse_config_line(line)?;
                    match key.as_str() {
                        "publickey" => e2ee_peer.set_public_key(&value)?,
                        "endpoint" => e2ee_peer.set_endpoint(&value)?,
                        _ => {}
                    }
                }
            }
            _ => {
                return Err(anyhow!("unknown configuration section: {}", header.trim()));
            }
        }
    }

    if relay_peer.public_key() != Key::zero() {
        relay.add_peer(relay_peer);
    }
    if has_e2ee && e2ee_peer.public_key() != Key::zero() {
        e2ee.add_peer(e2ee_peer);
    }

    Ok(ServerConfig {
        relay,
        e2ee: if has_e2ee { Some(e2ee) } else { None },
    })
}

#[derive(Clone, Copy)]
pub enum Shell {
    Posix,
    PowerShell,
}

pub fn create_server_command(
    relay: &Config,
    e2ee: &Config,
    shell: Shell,
    simple: bool,
    disable_v6: bool,
) -> String {
    let mut keys = Vec::new();
    let mut vals = Vec::new();

    keys.push("WIRETAP_RELAY_INTERFACE_PRIVATEKEY");
    vals.push(relay.private_key().to_string());

    if let Some(net) = relay.addresses().iter().find(|net| net.addr().is_ipv4()) {
        keys.push("WIRETAP_RELAY_INTERFACE_IPV4");
        vals.push(net.addr().to_string());
    }
    if let Some(net) = relay.addresses().iter().find(|net| net.addr().is_ipv6()) {
        keys.push("WIRETAP_RELAY_INTERFACE_IPV6");
        vals.push(net.addr().to_string());
    }

    if let Some(port) = relay.port() {
        keys.push("WIRETAP_RELAY_INTERFACE_PORT");
        vals.push(port.to_string());
    }

    if let Some(mtu) = relay.mtu {
        keys.push("WIRETAP_RELAY_INTERFACE_MTU");
        vals.push(mtu.to_string());
    }

    keys.push("WIRETAP_RELAY_PEER_PUBLICKEY");
    vals.push(
        relay
            .peers()
            .get(0)
            .map(|p| p.public_key().to_string())
            .unwrap_or_default(),
    );

    if let Some(key) = relay.preshared_key {
        keys.push("WIRETAP_RELAY_PEER_PRESHAREDKEY");
        vals.push(key.to_string());
    }

    if let Some(peer) = relay.peers().get(0) {
        if !peer.allowed_ips().is_empty() {
            let allowed = peer
                .allowed_ips()
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(",");
            keys.push("WIRETAP_RELAY_PEER_ALLOWED");
            vals.push(allowed);
        }
        if let Some(endpoint) = peer.endpoint() {
            keys.push("WIRETAP_RELAY_PEER_ENDPOINT");
            vals.push(endpoint.to_string());
        } else if let Some(endpoint) = peer.endpoint_dns() {
            keys.push("WIRETAP_RELAY_PEER_ENDPOINT");
            vals.push(endpoint.to_string());
        }
    }

    if !simple {
        keys.push("WIRETAP_E2EE_INTERFACE_PRIVATEKEY");
        vals.push(e2ee.private_key().to_string());

        if e2ee.addresses.len() == 1 {
            keys.push("WIRETAP_E2EE_INTERFACE_API");
            vals.push(e2ee.addresses[0].addr().to_string());
        }

        keys.push("WIRETAP_E2EE_PEER_PUBLICKEY");
        vals.push(
            e2ee.peers()
                .get(0)
                .map(|p| p.public_key().to_string())
                .unwrap_or_default(),
        );

        if let Some(peer) = e2ee.peers().get(0) {
            if let Some(endpoint) = peer.endpoint() {
                keys.push("WIRETAP_E2EE_PEER_ENDPOINT");
                vals.push(endpoint.to_string());
            } else if let Some(endpoint) = peer.endpoint_dns() {
                keys.push("WIRETAP_E2EE_PEER_ENDPOINT");
                vals.push(endpoint.to_string());
            }
        }
    }

    if disable_v6 {
        keys.push("WIRETAP_DISABLEIPV6");
        vals.push("true".to_string());
    }

    if let Some(localhost) = relay.localhost_ip() {
        keys.push("WIRETAP_RELAY_INTERFACE_LOCALHOSTIP");
        vals.push(localhost.to_string());
    }

    let mut out = String::new();
    match shell {
        Shell::Posix => {
            for (k, v) in keys.iter().zip(vals.iter()) {
                out.push_str(&format!("{}={} ", k, v));
            }
            out.push_str("./wiretap serve");
        }
        Shell::PowerShell => {
            for (k, v) in keys.iter().zip(vals.iter()) {
                out.push_str(&format!("$env:{}=\"{}\"; ", k, v));
            }
            out.push_str(".\\wiretap.exe serve");
        }
    }

    out
}

pub fn create_server_file(relay: &Config, e2ee: &Config, simple: bool) -> String {
    let mut s = String::new();

    s.push_str("[Relay.Interface]\n");
    s.push_str(&format!("PrivateKey = {}\n", relay.private_key()));
    for net in relay.addresses() {
        if net.addr().is_ipv4() {
            s.push_str(&format!("IPv4 = {}\n", net.addr()));
        } else {
            s.push_str(&format!("IPv6 = {}\n", net.addr()));
        }
    }
    if let Some(port) = relay.port() {
        s.push_str(&format!("Port = {}\n", port));
    }
    if let Some(mtu) = relay.mtu {
        s.push_str(&format!("MTU = {}\n", mtu));
    }
    if let Some(localhost) = relay.localhost_ip() {
        s.push_str(&format!("LocalhostIP = {}\n", localhost));
    }

    s.push_str("\n[Relay.Peer]\n");
    if let Some(peer) = relay.peers().get(0) {
        if !peer.allowed_ips().is_empty() {
            let allowed = peer
                .allowed_ips()
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(",");
            s.push_str(&format!("Allowed = {}\n", allowed));
        }
        s.push_str(&format!("PublicKey = {}\n", peer.public_key()));
        if let Some(key) = relay.preshared_key.or_else(|| peer.preshared_key()) {
            s.push_str(&format!("PresharedKey = {}\n", key));
        }
        if let Some(endpoint) = peer.endpoint() {
            s.push_str(&format!("Endpoint = {}\n", endpoint));
        } else if let Some(endpoint) = peer.endpoint_dns() {
            s.push_str(&format!("Endpoint = {}\n", endpoint));
        }
    }

    if !simple {
        s.push_str("\n[E2EE.Interface]\n");
        s.push_str(&format!("PrivateKey = {}\n", e2ee.private_key()));
        if e2ee.addresses.len() == 1 {
            s.push_str(&format!("Api = {}\n", e2ee.addresses[0].addr()));
        }

        s.push_str("\n[E2EE.Peer]\n");
        if let Some(peer) = e2ee.peers().get(0) {
            s.push_str(&format!("PublicKey = {}\n", peer.public_key()));
            if let Some(endpoint) = peer.endpoint() {
                s.push_str(&format!("Endpoint = {}\n", endpoint));
            } else if let Some(endpoint) = peer.endpoint_dns() {
                s.push_str(&format!("Endpoint = {}\n", endpoint));
            }
        }
    }

    s
}

pub fn find_available_filename(path: &str) -> String {
    let mut candidate = path.to_string();
    let mut count = 1;
    let input = Path::new(path);
    let ext = input.extension().and_then(|v| v.to_str()).unwrap_or("");
    let base = input.file_stem().and_then(|v| v.to_str()).unwrap_or(path);

    loop {
        if fs::metadata(&candidate).is_err() {
            break;
        }
        candidate = if ext.is_empty() {
            format!("{}{}", base, count)
        } else {
            format!("{}{}.{}", base, count, ext)
        };
        count += 1;
    }

    candidate
}

pub fn next_prefix_for_peers(peers: &[PeerConfig]) -> Vec<IpNet> {
    if peers.is_empty() {
        return Vec::new();
    }

    let mut prefixes = Vec::new();
    let slots = peers[0].allowed_ips().len();
    for slot in 0..slots {
        let mut base = peers[0].allowed_ips()[slot];
        for peer in peers {
            if peer.allowed_ips()[slot].addr() > base.addr() {
                base = peer.allowed_ips()[slot];
            }
        }
        prefixes.push(increment_prefix(base));
    }

    prefixes
}

fn increment_prefix(prefix: IpNet) -> IpNet {
    match prefix {
        IpNet::V4(net) => {
            let step = if net.prefix_len() == 0 {
                0
            } else {
                1u32 << (32 - net.prefix_len() as u32)
            };
            let next =
                Ipv4Net::new(increment_v4(net.network(), step), net.prefix_len()).unwrap_or(net);
            IpNet::V4(next)
        }
        IpNet::V6(net) => {
            if net.prefix_len() == 0 {
                return IpNet::V6(net);
            }
            let step = 1u128 << (128 - net.prefix_len() as u32);
            let next =
                Ipv6Net::new(increment_v6(net.network(), step), net.prefix_len()).unwrap_or(net);
            IpNet::V6(next)
        }
    }
}

fn increment_v4(base: Ipv4Addr, delta: u32) -> Ipv4Addr {
    let value = u32::from(base).saturating_add(delta);
    Ipv4Addr::from(value)
}

fn increment_v6(base: Ipv6Addr, delta: u128) -> Ipv6Addr {
    let value = u128::from(base).saturating_add(delta);
    Ipv6Addr::from(value)
}

fn split_host_port(endpoint: &str) -> Result<(&str, u16)> {
    if endpoint.starts_with('[') {
        if let Some(end) = endpoint.find(']') {
            let host = &endpoint[1..end];
            let rest = &endpoint[end + 1..];
            let port = rest.trim_start_matches(':').parse::<u16>()?;
            return Ok((host, port));
        }
    }

    let parts: Vec<&str> = endpoint.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("invalid endpoint"));
    }
    let port = parts[0].parse::<u16>()?;
    let host = parts[1];
    Ok((host, port))
}

fn parse_config_line(line: &str) -> Result<(String, String)> {
    let (key, value) = line
        .split_once('=')
        .ok_or_else(|| anyhow!("failed to parse line: no '=' found"))?;
    Ok((key.trim().to_ascii_lowercase(), value.trim().to_string()))
}

pub fn format_status_prefix(label: &str, value: &str) -> String {
    format!("{} {}", label.bold(), value.green())
}
