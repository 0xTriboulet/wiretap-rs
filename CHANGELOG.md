# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-04-06

### Added
- CMake/cmkr build system integration for C/C++ consumers via `FetchContent` or `add_subdirectory`
- C FFI layer (`src/ffi.rs`, `include/wiretap_rs.h`) exposing core wiretap-rs APIs to C/C++ callers
- SOCKS5 dynamic expose support (`src/transport/socks5.rs`)
- New test suites: `ffi_tests.rs`, `smoltcp_config_tests.rs`
- Expanded `api_http_server_tests.rs` and `quiet_mode_tests.rs` coverage
- Additional `cli_parse_tests.rs` cases for new CLI flags

### Changed
- Refactored `serve.rs`, `transport/api.rs`, `peer.rs`, `logging.rs`, and `cli.rs` for clarity and reduced duplication
- `add.rs` reworked for improved allocation logic
- `constants.rs` extended with new shared constants
- Updated README with CMake/cmkr build instructions and FFI usage examples

## [0.2.0] - 2026-01-24

### Changed
- Allocation state persistence is now opt-in via `WIRETAP_ALLOCATION_STATE` environment variable
- Improved server configuration with clearer defaults for state management

### Added
- Documentation for allocation state persistence configuration
- Enhanced test coverage for allocation state functionality

## [0.1.1] - 2026-01-24

### Fixed
- Configure aarch64 linker for cross-compilation to resolve build failures for ARM64 Linux targets

### Changed
- Removed redundant WireGuard routing explanation from README Overview section
- Deleted RELEASE_SUMMARY.md file

## [0.1.0] - 2026-01-24

### Added
- Initial release of wiretap-rs, a Rust port of the original Go implementation
- Core WireGuard proxy server functionality with userspace network stack
- Support for both library and standalone CLI application usage
- `configure` command for generating WireGuard configurations
- `serve` command for running the proxy server
- `ping` command for testing API connectivity
- `status` command for viewing network topology
- `add` command for adding peers dynamically
- `expose` command for port forwarding functionality
- Relay and E2EE (End-to-End Encrypted) WireGuard interfaces
- TCP/UDP/ICMP echo protocol support via smoltcp userspace stack
- HTTP API for managing peer allocation and topology
- Localhost mapping support for accessing server localhost resources
- Simple mode for traditional one-client-one-server VPN setup
- Structured logging via tracing crate
- Comprehensive README with usage examples and manual test walkthrough

### Known Limitations
- Userspace only implementation (no kernel WireGuard interface)
- Limited protocol coverage (TCP/UDP/ICMP echo only)
- Unauthenticated API (matches Go reference implementation)
- No systemd units or automatic firewall/NAT setup
- Potential edge-case differences in TCP/UDP handling compared to gVisor

[0.3.0]: https://github.com/0xTriboulet/wiretap-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/0xTriboulet/wiretap-rs/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/0xTriboulet/wiretap-rs/releases/tag/v0.1.1
[0.1.0]: https://github.com/0xTriboulet/wiretap-rs/releases/tag/v0.1.0
