use axum::{routing::get, Router};
use lazy_static::lazy_static;
use prometheus::{Counter, Encoder, Registry, TextEncoder};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct HealthState {
    pub is_ready: Arc<Mutex<bool>>,
}

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref PACKETS_TOTAL: Counter =
        Counter::new("coentrovpn_packets_total", "Total packets handled").unwrap();
    pub static ref RETRIES_TOTAL: Counter = Counter::new(
        "coentrovpn_retries_total",
        "Total retry attempts for unacked messages"
    )
    .unwrap();
    pub static ref DUPLICATES_TOTAL: Counter = Counter::new(
        "coentrovpn_duplicates_total",
        "Total duplicate chunks discarded"
    )
    .unwrap();
    pub static ref REASSEMBLIES_TOTAL: Counter = Counter::new(
        "coentrovpn_reassemblies_total",
        "Total successful message reassemblies"
    )
    .unwrap();
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            is_ready: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn set_ready(&self) {
        let mut ready = self.is_ready.lock().await;
        *ready = true;
    }

    pub async fn is_ready(&self) -> bool {
        *self.is_ready.lock().await
    }
}

pub fn init_metrics() {
    REGISTRY
        .register(Box::new(PACKETS_TOTAL.clone()))
        .expect("Failed to register metric");
    REGISTRY
        .register(Box::new(RETRIES_TOTAL.clone()))
        .expect("Failed to register RETRIES_TOTAL");
    REGISTRY
        .register(Box::new(DUPLICATES_TOTAL.clone()))
        .expect("Failed to register DUPLICATES_TOTAL");
    REGISTRY
        .register(Box::new(REASSEMBLIES_TOTAL.clone()))
        .expect("Failed to register REASSEMBLIES_TOTAL");
}

pub async fn healthz() -> &'static str {
    "OK"
}

pub async fn metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

pub async fn ready(state: Arc<HealthState>) -> &'static str {
    if state.is_ready().await {
        "READY"
    } else {
        "NOT READY"
    }
}

pub async fn start_health_server(addr: SocketAddr, state: Arc<HealthState>) {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(move || ready(state.clone())))
        .route("/metrics", get(metrics));
    axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind TCP listener"),
        app.into_make_service(),
    )
    .await
    .expect("Health server failed to start");
}
