use super::harness::{harness, Harness};
use crate::error::token_hash;
use axum::http::{header::CACHE_CONTROL, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn authorization_form(name: &str, platform: &str) -> String {
    format!("client_id=metrune-cli&installation_name={name}&platform={platform}")
}

fn token_form(device_code: &str) -> String {
    format!("grant_type={DEVICE_GRANT}&device_code={device_code}&client_id=metrune-cli")
}

async fn authorize(harness: &Harness, name: &str, platform: &str) -> Value {
    let (status, body) = harness
        .send_form(
            "/v1/oauth/device/authorization",
            authorization_form(name, platform),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn browser_approval_mints_exactly_one_owner_bound_installation() {
    let harness = harness!();
    let workspace = harness.workspace("device-success").await;
    let team_id = harness
        .create_team(workspace.organization_id, "device-team")
        .await;
    let authorization = authorize(&harness, "oauth-laptop", "linux").await;
    let device_code = authorization["device_code"].as_str().expect("device code");
    let user_code = authorization["user_code"].as_str().expect("user code");

    assert_eq!(
        authorization["verification_uri"],
        "https://metrune.example/device"
    );
    assert_eq!(authorization["interval"], 5);
    assert_eq!(authorization["expires_in"], 600);
    let persisted: (String, String) = sqlx::query_as(
        "SELECT device_code_hash, user_code_hash
         FROM device_enrollment_authorizations
         WHERE device_code_hash = $1",
    )
    .bind(token_hash(device_code))
    .fetch_one(&harness.postgres)
    .await
    .expect("persisted device authorization");
    assert_eq!(persisted.0, token_hash(device_code));
    assert_ne!(persisted.0, device_code);
    assert_ne!(persisted.1, user_code.replace('-', ""));

    let (status, pending) = harness
        .send_form("/v1/oauth/token", token_form(device_code))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(pending["error"], "authorization_pending");

    let (status, inspection) = harness
        .send(
            "POST",
            "/v1/oauth/device/verification",
            Some(&workspace.admin.token),
            json!({"userCode": user_code.to_ascii_lowercase()}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{inspection}");
    assert_eq!(inspection["installationName"], "oauth-laptop");
    assert_eq!(inspection["platform"], "linux");

    let other_workspace = harness.workspace("device-other").await;
    let foreign_team = harness
        .create_team(other_workspace.organization_id, "foreign")
        .await;
    let (status, _) = harness
        .send(
            "POST",
            "/v1/oauth/device/approval",
            Some(&workspace.admin.token),
            json!({
                "userCode": user_code,
                "decision": "approve",
                "teamId": foreign_team,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, approval) = harness
        .send(
            "POST",
            "/v1/oauth/device/approval",
            Some(&workspace.admin.token),
            json!({
                "userCode": user_code,
                "decision": "approve",
                "teamId": team_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{approval}");
    assert_eq!(approval["status"], "approved");

    let (first, second) = tokio::join!(
        harness.send_form("/v1/oauth/token", token_form(device_code)),
        harness.send_form("/v1/oauth/token", token_form(device_code)),
    );
    let responses = [first, second];
    let successes: Vec<&Value> = responses
        .iter()
        .filter_map(|(status, body)| (*status == StatusCode::OK).then_some(body))
        .collect();
    assert_eq!(successes.len(), 1, "{responses:?}");
    let rejected: Vec<&Value> = responses
        .iter()
        .filter_map(|(status, body)| (*status == StatusCode::BAD_REQUEST).then_some(body))
        .collect();
    assert_eq!(rejected.len(), 1, "{responses:?}");
    assert_eq!(rejected[0]["error"], "invalid_grant");

    let token = successes[0]["access_token"]
        .as_str()
        .expect("installation bearer");
    assert_eq!(successes[0]["token_type"], "Bearer");
    let installation_id = Uuid::parse_str(
        successes[0]["installation_id"]
            .as_str()
            .expect("installation id"),
    )
    .expect("UUID");
    let installation: (Uuid, Option<Uuid>, Option<Uuid>, Option<String>, String) = sqlx::query_as(
        "SELECT organization_id, owner_user_id, team_id, team_key, platform
             FROM installations WHERE id = $1",
    )
    .bind(installation_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("minted installation");
    assert_eq!(installation.0, workspace.organization_id);
    assert_eq!(installation.1, Some(workspace.admin.user_id));
    assert_eq!(installation.2, Some(team_id));
    assert_eq!(installation.3.as_deref(), Some("device-team"));
    assert_eq!(installation.4, "linux");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM installations
         WHERE organization_id = $1 AND name = 'oauth-laptop'",
    )
    .bind(workspace.organization_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("installation count");
    assert_eq!(count, 1);

    let (status, provision) = harness
        .send(
            "POST",
            "/v1/installation/classifier/provision",
            Some(token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{provision}");
}

#[tokio::test]
async fn pending_polling_slows_down_and_denial_is_terminal() {
    let harness = harness!();
    let workspace = harness.workspace("device-denial").await;
    let authorization = authorize(&harness, "denied-laptop", "wsl").await;
    let device_code = authorization["device_code"].as_str().expect("device code");
    let user_code = authorization["user_code"].as_str().expect("user code");

    let (first_status, first) = harness
        .send_form("/v1/oauth/token", token_form(device_code))
        .await;
    let (second_status, second) = harness
        .send_form("/v1/oauth/token", token_form(device_code))
        .await;
    assert_eq!(first_status, StatusCode::BAD_REQUEST);
    assert_eq!(first["error"], "authorization_pending");
    assert_eq!(second_status, StatusCode::BAD_REQUEST);
    assert_eq!(second["error"], "slow_down");
    let interval: i32 = sqlx::query_scalar(
        "SELECT poll_interval_seconds
         FROM device_enrollment_authorizations WHERE device_code_hash = $1",
    )
    .bind(token_hash(device_code))
    .fetch_one(&harness.postgres)
    .await
    .expect("poll interval");
    assert_eq!(interval, 10);

    let (status, denial) = harness
        .send(
            "POST",
            "/v1/oauth/device/approval",
            Some(&workspace.viewer.token),
            json!({"userCode": user_code, "decision": "deny"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{denial}");
    assert_eq!(denial["status"], "denied");

    let (status, body) = harness
        .send_form("/v1/oauth/token", token_form(device_code))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "access_denied");
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM installations WHERE name = 'denied-laptop'")
            .fetch_one(&harness.postgres)
            .await
            .expect("installation count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn expired_and_invalid_device_requests_fail_without_minting_credentials() {
    let harness = harness!();
    let workspace = harness.workspace("device-expired").await;
    let authorization = authorize(&harness, "expired-laptop", "macos").await;
    let device_code = authorization["device_code"].as_str().expect("device code");
    let user_code = authorization["user_code"].as_str().expect("user code");
    sqlx::query(
        "UPDATE device_enrollment_authorizations
         SET expires_at = NOW() - INTERVAL '1 second'
         WHERE device_code_hash = $1",
    )
    .bind(token_hash(device_code))
    .execute(&harness.postgres)
    .await
    .expect("expire device authorization");

    let (status, expired) = harness
        .send_form("/v1/oauth/token", token_form(device_code))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(expired["error"], "expired_token");
    let (status, _) = harness
        .send(
            "POST",
            "/v1/oauth/device/verification",
            Some(&workspace.admin.token),
            json!({"userCode": user_code}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let cases = vec![
        (
            "/v1/oauth/device/authorization",
            "client_id=unknown&installation_name=laptop&platform=linux".to_owned(),
            "invalid_client",
        ),
        (
            "/v1/oauth/device/authorization",
            "client_id=metrune-cli&installation_name=&platform=linux".to_owned(),
            "invalid_request",
        ),
        (
            "/v1/oauth/device/authorization",
            "client_id=metrune-cli&installation_name=laptop&platform=solaris".to_owned(),
            "invalid_request",
        ),
        (
            "/v1/oauth/token",
            "grant_type=password&device_code=unknown&client_id=metrune-cli".to_owned(),
            "unsupported_grant_type",
        ),
        (
            "/v1/oauth/token",
            format!("grant_type={DEVICE_GRANT}&device_code=unknown&client_id=metrune-cli"),
            "invalid_grant",
        ),
    ];
    for (path, form, expected) in cases {
        let (status, body) = harness.send_form(path, form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        assert_eq!(body["error"], expected, "{path}: {body}");
    }
}

#[tokio::test]
async fn approval_requires_an_active_workspace_and_oauth_responses_are_not_cached() {
    let harness = harness!();
    let workspace = harness.workspace("device-active-workspace").await;
    let no_workspace_session = harness.issue_session(workspace.admin.user_id, None).await;
    let authorization = authorize(&harness, "workspace-laptop", "other").await;
    let user_code = authorization["user_code"].as_str().expect("user code");

    let (status, body) = harness
        .send(
            "POST",
            "/v1/oauth/device/verification",
            Some(&no_workspace_session),
            json!({"userCode": user_code}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"]
        .as_str()
        .is_some_and(|message| message.contains("select a workspace")));

    let response = harness
        .raw_form_response(
            "/v1/oauth/device/authorization",
            authorization_form("cache-check", "linux"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}
