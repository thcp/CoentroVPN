use shared_utils::logging;
use tracing::{debug, info};

fn main() {
    // Initialize logging with default settings
    let _guard = logging::init_default_logging();

    info!("Starting CoentroVPN Management API");
    debug!("Initializing with default configuration");

    // In the future, we would load configuration here
    // let config_manager = match ConfigManager::load_default() {
    //     Ok(manager) => manager,
    //     Err(err) => {
    //         error!("Failed to load configuration: {}", err);
    //         return;
    //     }
    // };

    // TODO: Implement Management API functionality

    info!("CoentroVPN Management API started");
}
