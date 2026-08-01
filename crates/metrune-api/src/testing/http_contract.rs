//! Cross-cutting HTTP behavior that sits outside individual handlers.

use super::harness::harness;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use flate2::{write::GzEncoder, Compression};
use serde_json::json;
use std::io::Write;

#[tokio::test]
async fn request_ids_are_propagated_and_routing_statuses_are_distinct() {
    let harness = harness!();
    let request_id = "verification-request-42";
    let response = harness
        .raw_response(
            Request::builder()
                .method("GET")
                .uri("/v1/healthz")
                .header("x-request-id", request_id)
                .body(Body::empty())
                .expect("health request"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(request_id)
    );

    let server_info = harness
        .raw_response(
            Request::builder()
                .method("GET")
                .uri("/v1/server/info")
                .body(Body::empty())
                .expect("server info request"),
        )
        .await;
    assert_eq!(server_info.status(), StatusCode::OK);
    assert_eq!(
        server_info
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let (status, _) = harness.get("/v1/route-that-does-not-exist", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = harness.send("PUT", "/v1/healthz", None, json!(null)).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn gzip_json_requests_are_decompressed_before_authentication() {
    let harness = harness!();
    let workspace = harness.workspace("gzip-login").await;
    let body = json!({
        "email": workspace.admin.email,
        "password": workspace.admin.password,
    })
    .to_string();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(body.as_bytes())
        .expect("compress login request");
    let compressed = encoder.finish().expect("finish gzip stream");

    let (status, response) = harness
        .request(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_ENCODING, "gzip")
                .body(Body::from(compressed))
                .expect("compressed login request"),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(response["sessionToken"]
        .as_str()
        .is_some_and(|token| token.starts_with("mts_")));
}

#[tokio::test]
async fn oversized_and_malformed_json_are_rejected_at_the_http_boundary() {
    let harness = harness!();
    let response = harness
        .raw_response(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'a'; 10 * 1024 * 1024 + 1]))
                .expect("oversized request"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let (status, _) = harness
        .request(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{this-is-not-json"))
                .expect("malformed JSON request"),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
