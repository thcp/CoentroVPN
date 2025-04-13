use axum::{routing::get, Router};
use coentro_vpn::observability::{init_metrics, start_metrics_server};
use prometheus::IntCounter;
use reqwest::Client;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[test]
fn test_metrics_initialization() {
    let retries_total = IntCounter::new("retries_total", "Total retries").unwrap();
    retries_total.inc();
    assert_eq!(
        retries_total.get(),
        1,
        "Retries total should increment correctly"
    );
}

#[tokio::test]
async fn test_metrics_endpoint_responds_ok() {
    init_metrics();

    let app = Router::new().route("/metrics", get(metrics));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("http://{}/metrics", addr);
    let response = Client::new()
        .get(&url)
        .send()
        .await
        .expect("Failed to send request");

    assert!(response.status().is_success());

    let body = response.text().await.unwrap();
    assert!(body.contains("coentrovpn_packets_total"));
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
