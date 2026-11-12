//! A timing trace for the [DEV] test-key app only (P5-3b): with the feature `test-key`, every
//! line goes to standard error with the milliseconds since the process started, so
//! `scripts\dev-app-check.ps1` can redirect it and report where the time goes. Without the
//! feature (the shipped app) nothing is compiled in: no log, no file, no environment variable.

#[cfg(feature = "test-key")]
mod on {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();

    /// Marks the process start; the first call counts.
    pub fn start() {
        let _ = START.get_or_init(Instant::now);
    }

    /// One line, `[   123.4 ms] text`.
    pub fn line(text: &str) {
        let ms = START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1000.0;
        eprintln!("[{ms:9.1} ms] {text}");
    }
}

/// Marks the process start (the test-key app only).
pub fn start() {
    #[cfg(feature = "test-key")]
    on::start();
}

/// Logs one line (the test-key app only); the text is built only when it is logged.
pub fn log(text: impl FnOnce() -> String) {
    #[cfg(feature = "test-key")]
    on::line(&text());
    #[cfg(not(feature = "test-key"))]
    let _ = text;
}
