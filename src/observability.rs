use axum::{routing::get, Router};
use lazy_static::lazy_static;
use prometheus::{Counter, Encoder, Registry, TextEncoder, IntCounter, IntGauge, Histogram, register_int_counter, register_int_gauge, register_histogram};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct HealthState {
    pub is_ready: Arc<Mutex<bool>>,
}

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref PACKETS_TOTAL: IntCounter = register_int_counter!(
        "packets_total",
        "Total number of packets processed"
    )
    .unwrap();

    pub static ref DUPLICATES_TOTAL: IntCounter = register_int_counter!(
        "duplicates_total",
        "Total number of duplicate packets detected"
    )
    .unwrap();

    pub static ref REASSEMBLIES_TOTAL: IntCounter = register_int_counter!(
        "reassemblies_total",
        "Total number of packet reassemblies completed"
    )
    .unwrap();

    pub static ref RETRIES_TOTAL: IntCounter = register_int_counter!(
        "retries_total",
        "Total number of packet retries"
    )
    .unwrap();

    pub static ref LATENCY_HISTOGRAM: Histogram = register_histogram!(
        "packet_latency_seconds",
        "Histogram of packet processing latency in seconds"
    )
    .unwrap();

    pub static ref PACKET_LOSS_GAUGE: IntGauge = register_int_gauge!(
        "packet_loss",
        "Current packet loss percentage"
    )
    .unwrap();

    pub static ref THROUGHPUT_GAUGE: IntGauge = register_int_gauge!(
        "throughput_bytes_per_second",
        "Current throughput in bytes per second"
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
    REGISTRY
        .register(Box::new(LATENCY_HISTOGRAM.clone()))
        .expect("Failed to register LATENCY_HISTOGRAM");
    REGISTRY
        .register(Box::new(PACKET_LOSS_GAUGE.clone()))
        .expect("Failed to register PACKET_LOSS_GAUGE");
    REGISTRY
        .register(Box::new(THROUGHPUT_GAUGE.clone()))
        .expect("Failed to register THROUGHPUT_GAUGE");
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
