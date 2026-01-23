fn main() {
    wiretap_rs::logging::init_logging();
    tracing::debug!("wiretap-rs starting");
    if let Err(err) = wiretap_rs::cli::run() {
        tracing::error!(error = %err, "wiretap-rs exited with error");
        if !wiretap_rs::logging::quiet_enabled() {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
}
