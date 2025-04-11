use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logging(level: &str, format: &str) {
    if EnvFilter::try_new(level).is_err() {
        eprintln!("Invalid log level '{}', falling back to 'info'", level);
    }

    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    let builder = fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT)
        .with_timer(UtcTime::rfc_3339());

    if format == "json" {
        builder.json().init();
    } else {
        builder.pretty().with_ansi(true).init();
    }
}
