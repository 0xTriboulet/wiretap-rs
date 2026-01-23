use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = env::temp_dir().join(format!("wiretap_rs_{name}_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn resolve_binary() -> PathBuf {
    if let Ok(path) = env::var("CARGO_BIN_EXE_wiretap-rs") {
        return PathBuf::from(path);
    }
    if let Ok(path) = env::var("CARGO_BIN_EXE_wiretap_rs") {
        return PathBuf::from(path);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin_name = if cfg!(windows) { "wiretap-rs.exe" } else { "wiretap-rs" };
    manifest_dir.join("target").join("debug").join(bin_name)
}

#[test]
fn serve_quiet_suppresses_output() {
    let dir = temp_dir("quiet");
    let config_path = dir.join("server.conf");
    fs::write(&config_path, "[Relay.Interface]\n").expect("write config");

    let bin = resolve_binary();
    assert!(bin.exists(), "wiretap-rs binary not found: {}", bin.display());
    let output = Command::new(bin)
        .arg("serve")
        .arg("--quiet")
        .arg("--config-file")
        .arg(&config_path)
        .env("WIRETAP_LOG_DIR", dir.join("logs").to_string_lossy().to_string())
        .output()
        .expect("run wiretap-rs");

    assert!(!output.status.success(), "expected non-zero status");
    assert!(
        output.stdout.is_empty(),
        "stdout not empty: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "stderr not empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let logs_dir = dir.join("logs");
    if logs_dir.exists() {
        let entries = fs::read_dir(&logs_dir).expect("read logs dir");
        assert_eq!(
            entries.count(),
            0,
            "log files should not be created in quiet mode"
        );
    }
}
