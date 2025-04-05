use tracing_subscriber::{fmt, EnvFilter};
use tracing_subscriber::fmt::format::FmtSpan;

pub fn init_logging(level: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let builder = fmt()
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .with_target(true);

    #[cfg(feature = "pretty-logs")]
    builder.pretty().init();

    #[cfg(not(feature = "pretty-logs"))]
    builder.json().init();
}
