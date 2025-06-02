mod cli;

use shared_utils::logging;
use tracing::{info, debug, error};

fn main() {
    // Initialize logging with default settings
    let _guard = logging::init_default_logging();
    
    info!("Starting CoentroVPN CLI");
    debug!("Initializing CLI");
    
    // Run the CLI application
    if let Err(err) = cli::run() {
        error!("CLI error: {}", err);
        std::process::exit(1);
    }
}
