use axum::{routing::get, Router};
use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Counter, Encoder, Histogram,
    IntCounter, IntGauge, Registry, TextEncoder,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::Filter;

#[derive(Clone)]
pub struct HealthState {
    pub is_ready: Arc<Mutex<bool>>,
}

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref PACKETS_TOTAL: IntCounter =
        register_int_counter!("packets_total", "Total number of packets processed").unwrap();
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
    pub static ref RETRIES_TOTAL: IntCounter =
        register_int_counter!("retries_total", "Total number of packet retries").unwrap();
    pub static ref LATENCY_HISTOGRAM: Histogram = register_histogram!(
        "packet_latency_seconds",
        "Histogram of packet processing latency in seconds"
    )
    .unwrap();
    pub static ref PACKET_LOSS_GAUGE: IntGauge =
        register_int_gauge!("packet_loss", "Current packet loss percentage").unwrap();
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
    // Ensure metrics are always initialized
    REGISTRY
        .register(Box::new(PACKETS_TOTAL.clone()))
        .expect("Failed to register PACKETS_TOTAL");
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

pub async fn start_health_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let health_route =
        warp::path!("health").map(|| warp::reply::with_status("OK", warp::http::StatusCode::OK));
    warp::serve(health_route).run(addr.parse()?).await;
    Ok(())
}

pub async fn start_metrics_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metrics_route = warp::path!("metrics").map(|| {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        warp::http::Response::builder()
            .header("Content-Type", encoder.format_type())
            .body(buffer)
    });

    warp::serve(metrics_route).run(addr.parse()?).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{IntCounter, Registry};

    #[test]
    fn test_metrics_initialization() {
        let retries_total = IntCounter::new("retries_total", "Total retries").unwrap();
        let registry = Registry::new();
        registry.register(Box::new(retries_total.clone())).unwrap();

        retries_total.inc();
        assert_eq!(
            retries_total.get(),
            1,
            "Retries total should increment correctly"
        );
    }

    #[tokio::test]
    async fn test_metrics_server() {
        let addr = "127.0.0.1:9101";
        tokio::spawn(async move {
            start_metrics_server(addr).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let response = reqwest::get(format!("http://{}/metrics", addr))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        assert!(
            response.contains("# HELP"),
            "Metrics endpoint should return Prometheus metrics"
        );
    }
}
