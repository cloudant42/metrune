//! Every protected route must reject an absent, malformed, revoked or expired
//! credential, and admin-only routes must reject a non-admin member.

use super::harness::harness;
use axum::http::StatusCode;
use serde_json::json;

/// Routes that must never answer an unauthenticated caller.
///
/// Bodies are well-formed on purpose: axum runs the `Json` extractor before the
/// handler, so a malformed body would return 422 and the assertion would pass
/// without ever reaching the authentication check it is meant to cover.
fn protected_routes() -> Vec<(&'static str, &'static str, serde_json::Value)> {
    vec![
        ("GET", "/v1/auth/me", json!(null)),
        ("GET", "/v1/org/members", json!(null)),
        (
            "POST",
            "/v1/org/members",
            json!({"email": "someone@example.test", "role": "viewer"}),
        ),
        ("GET", "/v1/org/teams", json!(null)),
        ("POST", "/v1/org/teams", json!({"name": "a-team"})),
        ("GET", "/v1/org/installations", json!(null)),
        ("GET", "/v1/org/settings", json!(null)),
        ("PATCH", "/v1/org/settings", json!({"retentionDays": 30})),
        ("GET", "/v1/org/classifier", json!(null)),
        (
            "PATCH",
            "/v1/org/classifier",
            json!({
                "enabled": false,
                "executionMode": "local",
                "providerId": "custom",
                "endpoint": "https://provider.example/v1/chat/completions",
                "model": "a-model",
                "credentialId": "",
            }),
        ),
        ("GET", "/v1/org/credentials", json!(null)),
        (
            "POST",
            "/v1/org/credentials",
            json!({"credentialId": "c", "providerId": "p", "secret": "s", "grace_hours": 0}),
        ),
        (
            "POST",
            "/v1/org/vault/recovery",
            json!({"password": "irrelevant"}),
        ),
        ("GET", "/v1/org/prices", json!(null)),
        (
            "POST",
            "/v1/org/prices",
            json!({
                "providerId": "custom",
                "modelId": "m",
                "inputPerMillion": 1.0,
                "outputPerMillion": 1.0,
            }),
        ),
        ("GET", "/v1/org/invitations", json!(null)),
        (
            "POST",
            "/v1/org/invitations",
            json!({"email": "x@example.test", "role": "viewer"}),
        ),
        ("GET", "/v1/me/installations", json!(null)),
        (
            "POST",
            "/v1/me/enrollment-codes",
            json!({"installationName": "laptop", "platform": "linux"}),
        ),
    ]
}

#[tokio::test]
async fn protected_routes_reject_callers_without_a_credential() {
    let harness = harness!();
    for (method, path, body) in protected_routes() {
        let (status, _) = harness.send(method, path, None, body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} answered an unauthenticated caller with {status}"
        );
    }
}

#[tokio::test]
async fn protected_routes_reject_a_token_that_was_never_issued() {
    let harness = harness!();
    let forged = format!("mts_{}", uuid::Uuid::new_v4().simple());
    for (method, path, body) in protected_routes() {
        let (status, _) = harness.send(method, path, Some(&forged), body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} accepted a forged bearer token"
        );
    }
}

#[tokio::test]
async fn admin_routes_reject_a_viewer() {
    let harness = harness!();
    let workspace = harness.workspace("admin-gate").await;
    let admin_only: &[(&str, &str, serde_json::Value)] = &[
        ("GET", "/v1/org/members", json!(null)),
        (
            "POST",
            "/v1/org/members",
            json!({"email": "x@example.test", "role": "viewer"}),
        ),
        ("GET", "/v1/org/installations", json!(null)),
        ("PATCH", "/v1/org/settings", json!({"retentionDays": 30})),
        ("GET", "/v1/org/credentials", json!(null)),
        (
            "POST",
            "/v1/org/vault/recovery",
            json!({"password": "irrelevant"}),
        ),
        ("GET", "/v1/org/invitations", json!(null)),
    ];
    for (method, path, body) in admin_only {
        let (status, _) = harness
            .send(method, path, Some(&workspace.viewer.token), body.clone())
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {path} let a viewer through with {status}"
        );
    }
}

#[tokio::test]
async fn a_revoked_session_stops_working_immediately() {
    let harness = harness!();
    let workspace = harness.workspace("revoked").await;
    let (status, _) = harness
        .get("/v1/org/members", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);

    sqlx::query("UPDATE web_sessions SET revoked_at = NOW() WHERE user_id = $1")
        .bind(workspace.admin.user_id)
        .execute(&harness.postgres)
        .await
        .expect("revoke the session");

    let (status, _) = harness
        .get("/v1/org/members", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_expired_session_is_refused_even_though_it_was_never_revoked() {
    let harness = harness!();
    let workspace = harness.workspace("expired").await;
    sqlx::query(
        "UPDATE web_sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE user_id = $1",
    )
    .bind(workspace.admin.user_id)
    .execute(&harness.postgres)
    .await
    .expect("expire the session");

    let (status, _) = harness
        .get("/v1/org/members", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabling_an_account_locks_out_its_live_sessions() {
    let harness = harness!();
    let workspace = harness.workspace("disabled").await;
    sqlx::query("UPDATE users SET disabled_at = NOW() WHERE id = $1")
        .bind(workspace.admin.user_id)
        .execute(&harness.postgres)
        .await
        .expect("disable the account");

    let (status, _) = harness
        .get("/v1/org/members", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_session_without_an_active_organization_cannot_reach_organization_data() {
    let harness = harness!();
    let workspace = harness.workspace("no-active-org").await;
    // A user who belongs to several workspaces has not chosen one yet.
    let token = harness.issue_session(workspace.admin.user_id, None).await;
    let (status, _) = harness.get("/v1/org/members", Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The identity route still works, so the UI can offer the picker.
    let (status, _) = harness.get("/v1/auth/me", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_malformed_authorization_header_is_not_mistaken_for_a_token() {
    let harness = harness!();
    let workspace = harness.workspace("malformed").await;
    for header in [
        workspace.admin.token.clone(),
        format!("bearer {}", workspace.admin.token),
        format!("Bearer  {}", workspace.admin.token),
        format!("Basic {}", workspace.admin.token),
        "Bearer ".to_string(),
    ] {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/org/members")
            .header(axum::http::header::AUTHORIZATION, header.clone())
            .body(axum::body::Body::empty())
            .expect("build the request");
        let (status, _) = harness.request(request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the header {header:?} was accepted as a valid credential"
        );
    }
}

#[tokio::test]
async fn health_and_readiness_stay_open() {
    let harness = harness!();
    let (status, _) = harness.get("/v1/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
}
