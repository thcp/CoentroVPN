use axum::{routing::get, Router};
use coentrovpn::observability::{init_metrics, metrics};
use reqwest::Client;
use std::net::SocketAddr;
use tokio::net::TcpListener;

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
