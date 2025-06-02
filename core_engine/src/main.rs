mod session;
mod tunnel;

use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("core_engine=debug".parse().unwrap()),
        )
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .init();

    info!("Starting CoentroVPN core engine");
    debug!("Initializing with default configuration");

    // In the future, we would load configuration here
    // let config_manager = match ConfigManager::load_default() {
    //     Ok(manager) => manager,
    //     Err(err) => {
    //         error!("Failed to load configuration: {}", err);
    //         return;
    //     }
    // };

    // TODO: Implement core engine functionality

    info!("CoentroVPN core engine started");
}
