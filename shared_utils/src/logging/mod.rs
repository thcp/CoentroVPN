//! Logging module for CoentroVPN.
//!
//! This module provides structured logging functionality using the `tracing` crate.
//! It includes utilities for initializing loggers with different configurations
//! and context-aware logging macros.

use std::path::Path;
use tracing::Level;
use tracing_appender::{
    non_blocking::{NonBlocking, WorkerGuard},
    rolling::{RollingFileAppender, Rotation},
};
use tracing_log::LogTracer;
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    prelude::*,
};

/// Log initialization options.
#[derive(Debug, Clone)]
pub struct LogOptions {
    /// Log level (default: INFO)
    pub level: Level,

    /// Whether to log to stdout (default: true)
    pub log_to_stdout: bool,

    /// Whether to log to a file (default: false)
    pub log_to_file: bool,

    /// Directory to store log files (default: "./logs")
    pub log_dir: String,

    /// Base filename for log files (default: "coentrovpn")
    pub log_file_name: String,

    /// Whether to use JSON format for logs (default: false)
    pub json_format: bool,

    /// Whether to include file and line information (default: true)
    pub include_file_line: bool,

    /// Whether to include span events (default: false)
    pub include_span_events: bool,
}

impl Default for LogOptions {
    fn default() -> Self {
        LogOptions {
            level: Level::INFO,
            log_to_stdout: true,
            log_to_file: false,
            log_dir: "./logs".to_string(),
            log_file_name: "coentrovpn".to_string(),
            json_format: false,
            include_file_line: true,
            include_span_events: false,
        }
    }
}

/// Initialize logging with the given options.
///
/// Returns a guard that must be kept alive for the duration of the program
/// to ensure logs are flushed properly.
///
/// # Examples
///
/// ```
/// use shared_utils::logging::{init_logging, LogOptions};
/// use tracing::Level;
///
/// let options = LogOptions {
///     level: Level::DEBUG,
///     log_to_file: true,
///     ..Default::default()
/// };
///
/// let _guard = init_logging(options);
/// ```
pub fn init_logging(options: LogOptions) -> Option<WorkerGuard> {
    // Bridge `log` crate records into `tracing` so legacy logs are captured
    let _ = LogTracer::init();

    let filter = EnvFilter::from_default_env().add_directive(options.level.into());

    let mut layers = Vec::new();
    let mut guard = None;

    // Configure stdout logging if enabled
    if options.log_to_stdout {
        let stdout_layer = fmt::layer()
            .with_file(options.include_file_line)
            .with_line_number(options.include_file_line)
            .with_target(true);

        let stdout_layer = if options.json_format {
            stdout_layer.json().boxed()
        } else {
            stdout_layer.boxed()
        };

        layers.push(stdout_layer);
    }

    // Configure file logging if enabled
    if options.log_to_file {
        let file_appender =
            RollingFileAppender::new(Rotation::DAILY, &options.log_dir, &options.log_file_name);

        let (non_blocking, worker_guard) = NonBlocking::new(file_appender);
        guard = Some(worker_guard);

        let file_layer = fmt::layer()
            .with_file(options.include_file_line)
            .with_line_number(options.include_file_line)
            .with_target(true)
            .with_writer(non_blocking);

        let file_layer = if options.json_format {
            file_layer.json().boxed()
        } else {
            file_layer.boxed()
        };

        layers.push(file_layer);
    }

    // Add span events if enabled
    let _span_events = if options.include_span_events {
        FmtSpan::FULL
    } else {
        FmtSpan::NONE
    };

    // Set the global subscriber (ignore if already set in this process)
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layers)
        .try_init();

    guard
}

/// Initialize logging with default options.
///
/// This is a convenience function that initializes logging with default options.
///
/// # Examples
///
/// ```
/// use shared_utils::logging::init_default_logging;
///
/// let _guard = init_default_logging();
/// ```
pub fn init_default_logging() -> Option<WorkerGuard> {
    init_logging(LogOptions::default())
}

/// Initialize logging from a configuration.
///
/// This function initializes logging based on the configuration settings.
///
/// # Examples
///
/// ```
/// use shared_utils::logging::init_logging_from_config;
/// use shared_utils::config::Config;
///
/// let config = Config::default();
/// let _guard = init_logging_from_config(&config);
/// ```
pub fn init_logging_from_config(config: &crate::config::Config) -> Option<WorkerGuard> {
    let level = match config.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let options = LogOptions {
        level,
        ..Default::default()
    };

    init_logging(options)
}

/// Create a file logger that logs to the specified file.
///
/// This function creates a file logger that logs to the specified file.
/// It returns a guard that must be kept alive for the duration of the program
/// to ensure logs are flushed properly.
///
/// # Examples
///
/// ```
/// use shared_utils::logging::file_logger;
///
/// let _guard = file_logger("app.log");
/// ```
pub fn file_logger(path: impl AsRef<Path>) -> WorkerGuard {
    let file_appender = tracing_appender::rolling::never(
        path.as_ref().parent().unwrap_or_else(|| Path::new(".")),
        path.as_ref().file_name().unwrap().to_str().unwrap(),
    );

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter(EnvFilter::from_default_env())
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tracing::{debug, error, info, trace, warn};

    #[test]
    fn test_init_logging() {
        let dir = tempdir().unwrap();
        let log_dir = dir.path().to_str().unwrap().to_string();

        let options = LogOptions {
            level: Level::TRACE,
            log_to_stdout: false,
            log_to_file: true,
            log_dir,
            log_file_name: "test.log".to_string(),
            ..Default::default()
        };

        let _guard = init_logging(options);

        trace!("This is a trace message");
        debug!("This is a debug message");
        info!("This is an info message");
        warn!("This is a warning message");
        error!("This is an error message");

        // We can't easily verify the log contents in a test,
        // but we can at least check that the file was created
        let entries = fs::read_dir(dir.path()).unwrap();
        assert!(entries.count() > 0);
    }
}
