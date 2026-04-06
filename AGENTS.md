# Project: wiretap-rs (Rust Port)

Welcome to the Rust version of wiretap! This project was originally written in Go and has been incrementally ported to Rust for improved performance/stability. The target implementation should work as both a `lib` that can be added to other Rust projects with `cargo add wiretap-rs`, and as a stand-alone command-line application. Complete functional parity through a test-driven development approach is the priority.

## Project Overview

*   **Original Language:** Go
*   **Current Language:** Rust
*   **Goal:** Replicate the functionality of the original Go service using idiomatic Rust.
*   **Key Dependencies/Crates:** None at this time.
*   **Project Structure:**
    *   `/reference`: Contains the original Go implementation
    *   `/reference/wiretap/tests`: Contains original test cases implemented in `.sh` script with manual testing instructions in `wt-tests.md`.
    *   `/development_documentation/specification.md`: Wiretap specification based on Go implementation.
    *   `/development_documentation/porting_progress.md`: Development notes tracking the porting progress.
    *   `/src`: Contains all source code.
    *   `/tests`: Integration tests.
    *   `/docs`: Project documentation.
    *   `Cargo.toml`: Rust's manifest file for dependencies and project metadata.

## Key Workflows & Commands

Agents should use the following commands to build, test, and manage the project.

*   **Build:**
    ```bash
    cargo build
    # or for release:
    cargo build --release
    ```

*   **Testing:**
    ```bash
    cargo test
    # Run tests for a specific crate (if a workspace):
    cargo test -p <crate-name>
    ```

*   **Code Style & Linting:**
    ```bash
    cargo fmt          # Auto-formats the code
    cargo clippy       # Runs linting checks
    ```

*   **Running the application (example):**
    ```bash
    cargo run -- [arguments]
    ```

## Development & Porting Guidelines

Adhere to these rules when making changes, especially during the porting process:

*   **Idiomatic Rust:** Translate Go patterns to idiomatic Rust (e.g., Go `goroutine` -> Rust `tokio::spawn`; Go `interface` -> Rust `trait`/generics). Do not simply write Go code in Rust syntax.
*   **Testing First:** Ensure comprehensive tests exist for the original Go functionality and use a test-driven approach when porting components. You *MUST* implement a test first, then watch the test fail, and then implement code that passes the test. New Rust code must maintain or improve test coverage. Tests should be run frequently.
*   **Incremental Porting:** The project uses a "Go sandwich" or similar approach to port code incrementally. New features should be implemented in Rust where possible.
*   **Error Handling:** Use Rust's robust error handling mechanisms (`Result` and `Option`) instead of Go's multi-value return style.
*   **Concurrency:** Use `tokio` for asynchronous I/O-bound tasks.
*   **Documentation:** After updating code, update the `/development_documentation/porting_progress.md` document that describes the changes made and the progress of the port.

## Boundaries & Constraints

*   **Never** modify generated files in `/generated` (if applicable).
*   **Never** commit secrets, API keys, or credentials to the repository; use environment variables.
*   **Do not** bypass CI/CD checks; all `cargo build` and `cargo test` checks must pass before a pull request.

## Resources

*   [The Rust Book](https://doc.rust-lang.org)
*   [Rust by Example](https://doc.rust-lang.org)
*   [Go to Rust Transition Guide (example link)](http://example.com/go-rust-guide)

