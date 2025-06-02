use shared_utils::logging;
use tracing::{debug, info};

fn main() {
    // Initialize logging with default settings
    let _guard = logging::init_default_logging();

    info!("Starting CoentroVPN GUI client");
    debug!("Initializing with default configuration");

    // In the future, we would load configuration here
    // let config_manager = match ConfigManager::load_default() {
    //     Ok(manager) => manager,
    //     Err(err) => {
    //         error!("Failed to load configuration: {}", err);
    //         return;
    //     }
    // };

    // TODO: Implement GUI client functionality

    info!("CoentroVPN GUI client started");
}
