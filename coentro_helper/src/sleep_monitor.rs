//! Monitors for system sleep and wake events.
use log::{error, info};
use std::pin::Pin;
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::Stream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepEvent {
    #[allow(dead_code)]
    Sleep, // Kept for future implementation of sleep detection
    Wake,
}

pub fn sleep_monitor() -> Pin<Box<dyn Stream<Item = SleepEvent> + Send>> {
    let stream = async_stream::stream! {
        let mut sigwake = match signal(SignalKind::window_change()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register signal handler for SIGWINCH: {}", e);
                return;
            }
        };

        info!("Monitoring for system sleep/wake events.");

        loop {
            sigwake.recv().await;
            info!("Received SIGWINCH, treating as a wake event.");
            yield SleepEvent::Wake;
        }
    };

    Box::pin(stream)
}
