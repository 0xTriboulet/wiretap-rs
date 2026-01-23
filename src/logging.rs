use once_cell::sync::OnceCell;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

static LOG_GUARD: OnceCell<WorkerGuard> = OnceCell::new();
static QUIET: OnceCell<bool> = OnceCell::new();

pub fn init_logging() {
    let quiet = detect_quiet();
    let _ = QUIET.set(quiet);
    let default_level = if cfg!(debug_assertions) { "debug" } else { "info" };
    let filter = env::var("WIRETAP_LOG_LEVEL")
        .or_else(|_| env::var("RUST_LOG"))
        .unwrap_or_else(|_| default_level.to_string());
    let filter = EnvFilter::new(filter);

    let stdout_layer = if quiet {
        None
    } else {
        Some(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
    };

    let file_layer = if quiet {
        None
    } else {
        resolve_log_file_path().and_then(|path| {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let file = fs::OpenOptions::new().create(true).append(true).open(&path).ok()?;
            let (writer, guard) = tracing_appender::non_blocking(file);
            let _ = LOG_GUARD.set(guard);
            Some(tracing_subscriber::fmt::layer().with_ansi(false).with_writer(writer))
        })
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
}

pub fn quiet_enabled() -> bool {
    QUIET.get().copied().unwrap_or(false)
}

fn detect_quiet() -> bool {
    if let Ok(value) = env::var("WIRETAP_QUIET") {
        let value = value.trim().to_ascii_lowercase();
        if matches!(value.as_str(), "1" | "true" | "yes" | "on") {
            return true;
        }
    }
    env::args().any(|arg| arg == "-q" || arg == "--quiet")
}

#[cfg(test)]
mod tests {
    use super::{init_logging, quiet_enabled};

    #[test]
    fn quiet_env_enables_quiet_mode() {
        unsafe {
            std::env::set_var("WIRETAP_QUIET", "1");
        }
        init_logging();
        assert!(quiet_enabled());
    }
}

fn resolve_log_file_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("WIRETAP_LOG_FILE") {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(PathBuf::from(trimmed));
    }

    let log_dir = if let Ok(dir) = env::var("WIRETAP_LOG_DIR") {
        let trimmed = dir.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(PathBuf::from(trimmed))
    } else if cfg!(debug_assertions) {
        Some(PathBuf::from("./logs"))
    } else {
        None
    };

    log_dir.map(|dir| dir.join(default_log_filename()))
}

fn default_log_filename() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("wiretap-{stamp}.log")
}
