//! Successful control-plane lifecycles, validation edges, and concurrent writes.

use super::harness::{analytics_harness, batch, harness};
use axum::http::StatusCode;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use uuid::Uuid;

type CapturedManagedRequest = Arc<Mutex<Option<(String, Value)>>>;
type MockManagedProvider = (String, CapturedManagedRequest, thread::JoinHandle<()>);

fn mock_managed_provider() -> MockManagedProvider {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind managed provider");
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("provider address")
    );
    let captured = Arc::new(Mutex::new(None));
    let request_capture = Arc::clone(&captured);
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept managed request");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set managed provider timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let (body_start, content_length) = loop {
            let read = stream.read(&mut buffer).expect("read managed request");
            assert!(read > 0, "managed request ended before its body");
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .expect("managed request content length");
            break (header_end + 4, content_length);
        };
        while request.len() < body_start + content_length {
            let read = stream.read(&mut buffer).expect("read managed request body");
            assert!(read > 0, "managed request body was truncated");
            request.extend_from_slice(&buffer[..read]);
        }
        let headers = String::from_utf8_lossy(&request[..body_start]).into_owned();
        let body = serde_json::from_slice(&request[body_start..body_start + content_length])
            .expect("managed request JSON");
        *request_capture.lock().expect("managed request capture") = Some((headers, body));

        let body = r#"{"choices":[{"message":{"content":"{\"results\":[{\"index\":0,\"category\":\"testing\",\"confidence\":0.91},{\"index\":1,\"category\":\"documentation\",\"confidence\":0.82}]}"}}],"usage":{"prompt_tokens":20,"completion_tokens":5}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write managed response");
    });
    (endpoint, captured, handle)
}

#[tokio::test]
async fn client_version_telemetry_reaches_admin_and_personal_installation_views() {
    let harness = harness!();
    let workspace = harness.workspace("client-version").await;
    let (installation_id, installation_token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;
    let batch_id = format!("telemetry-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO ingest_batches(installation_id, batch_id, snapshot_count, completed_at)
         VALUES ($1,$2,0,NOW())",
    )
    .bind(installation_id)
    .bind(&batch_id)
    .execute(&harness.postgres)
    .await
    .expect("seed an idempotent batch");

    let (status, _) = harness
        .send_client(
            "/v1/ingest/sessions",
            &installation_token,
            Some("0.1.0"),
            batch(&batch_id, vec![]),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let stored = sqlx::query_scalar::<_, Option<String>>(
        "SELECT last_client_version FROM installations WHERE id = $1",
    )
    .bind(installation_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read client version telemetry");
    assert_eq!(stored.as_deref(), Some("0.1.0"));

    for (path, token) in [
        ("/v1/org/installations", &workspace.admin.token),
        ("/v1/me/installations", &workspace.admin.token),
    ] {
        let (status, installations) = harness.get(path, Some(token)).await;
        assert_eq!(status, StatusCode::OK);
        let installation = installations
            .as_array()
            .expect("installation array")
            .iter()
            .find(|item| item["id"] == installation_id.to_string())
            .expect("versioned installation");
        assert_eq!(installation["lastClientVersion"], "0.1.0");
    }
}

#[tokio::test]
async fn teams_and_installation_assignments_complete_their_full_lifecycle() {
    let harness = harness!();
    let workspace = harness.workspace("team-lifecycle").await;
    let (installation_id, _) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    let (status, created) = harness
        .send(
            "POST",
            "/v1/org/teams",
            Some(&workspace.admin.token),
            json!({"name": "  Platform  "}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["name"].as_str(), Some("Platform"));
    let team_id = Uuid::parse_str(created["id"].as_str().expect("team id")).expect("valid team id");

    let (status, _) = harness
        .send(
            "POST",
            "/v1/org/teams",
            Some(&workspace.admin.token),
            json!({"name": "Platform"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    for invalid in [String::new(), " ".into(), "x".repeat(81)] {
        let (status, _) = harness
            .send(
                "POST",
                "/v1/org/teams",
                Some(&workspace.admin.token),
                json!({"name": invalid}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let (status, _) = harness
        .send(
            "PATCH",
            &format!("/v1/org/installations/{installation_id}"),
            Some(&workspace.admin.token),
            json!({"teamId": team_id}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, teams) = harness
        .get("/v1/org/teams", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    let platform = teams
        .as_array()
        .expect("teams")
        .iter()
        .find(|team| team["id"] == team_id.to_string())
        .expect("created team");
    assert_eq!(platform["installations"].as_i64(), Some(1));

    let (status, _) = harness
        .send(
            "PATCH",
            &format!("/v1/org/teams/{team_id}"),
            Some(&workspace.admin.token),
            json!({"name": "Core Platform"}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let stored_assignment = sqlx::query_as::<_, (Option<Uuid>, Option<String>)>(
        "SELECT team_id, team_key FROM installations WHERE id = $1",
    )
    .bind(installation_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read installation assignment");
    assert_eq!(
        stored_assignment,
        (Some(team_id), Some("Core Platform".into()))
    );

    let (status, _) = harness
        .send(
            "DELETE",
            &format!("/v1/org/teams/{team_id}"),
            Some(&workspace.admin.token),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let stored_assignment = sqlx::query_as::<_, (Option<Uuid>, Option<String>)>(
        "SELECT team_id, team_key FROM installations WHERE id = $1",
    )
    .bind(installation_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read deleted team assignment");
    assert_eq!(stored_assignment, (None, None));

    let audit_actions = sqlx::query_scalar::<_, String>(
        "SELECT action FROM audit_events WHERE organization_id = $1 ORDER BY created_at",
    )
    .bind(workspace.organization_id)
    .fetch_all(&harness.postgres)
    .await
    .expect("read audit events");
    for action in [
        "team.create",
        "installation.assign_team",
        "team.rename",
        "team.delete",
    ] {
        assert!(audit_actions.iter().any(|entry| entry == action));
    }
}

#[tokio::test]
async fn managed_classification_routes_bounded_text_with_a_server_held_credential() {
    let harness = harness!();
    let workspace = harness.workspace("managed-route").await;
    let (_, installation_token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;
    let (endpoint, captured, provider) = mock_managed_provider();

    let (status, _) = harness
        .send(
            "POST",
            "/v1/org/credentials",
            Some(&workspace.admin.token),
            json!({
                "credentialId": "managed-provider",
                "providerId": "custom",
                "secret": "server-only-secret",
                "graceHours": 0,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = harness
        .send(
            "PATCH",
            "/v1/org/classifier",
            Some(&workspace.admin.token),
            json!({
                "enabled": true,
                "executionMode": "managed",
                "providerId": "custom",
                "endpoint": endpoint,
                "model": "managed-test-model",
                "credentialId": "managed-provider",
                "responseMode": "prompt_json",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, provisioned) = harness
        .send(
            "POST",
            "/v1/installation/classifier/provision",
            Some(&installation_token),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(provisioned["executionMode"].as_str(), Some("managed"));
    assert_eq!(provisioned["endpoint"].as_str(), Some(""));
    assert!(provisioned["credential"].is_null());

    let (status, _) = harness
        .send(
            "POST",
            "/v1/installation/classifier/classify-batch",
            Some("mti_not-issued"),
            json!({"texts": ["do not route this"]}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, classified) = harness
        .send(
            "POST",
            "/v1/installation/classifier/classify-batch",
            Some(&installation_token),
            json!({"texts": ["write upload tests", "document the client"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        classified["assignments"][0]["categoryId"].as_str(),
        Some("testing")
    );
    assert_eq!(
        classified["assignments"][1]["categoryId"].as_str(),
        Some("documentation")
    );

    provider.join().expect("managed provider");
    let (headers, body) = captured
        .lock()
        .expect("managed request capture")
        .take()
        .expect("provider request");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer server-only-secret"),
        "the server did not authenticate to the managed provider"
    );
    let serialized = body.to_string();
    assert!(serialized.contains("write upload tests"));
    assert!(serialized.contains("document the client"));
    assert!(
        !serialized.contains(&installation_token),
        "the installation credential was forwarded to the model provider"
    );
}

#[tokio::test]
async fn credentials_are_encrypted_redacted_rotated_provisioned_and_revoked() {
    let harness = harness!();
    let workspace = harness.workspace("credential-lifecycle").await;
    let (_, installation_token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;
    let credential_path = "/v1/org/credentials/provider-main";

    let (status, first) = harness
        .send(
            "POST",
            "/v1/org/credentials",
            Some(&workspace.admin.token),
            json!({
                "credentialId": "provider-main",
                "providerId": "custom",
                "secret": "first-super-secret",
                "graceHours": 0,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["version"].as_i64(), Some(1));
    assert!(!first.to_string().contains("first-super-secret"));

    let ciphertext = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT ciphertext FROM provider_credentials
         WHERE organization_id = $1 AND credential_id = 'provider-main' AND version = 1",
    )
    .bind(workspace.organization_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("stored ciphertext");
    assert!(
        !ciphertext
            .windows(b"first-super-secret".len())
            .any(|window| window == b"first-super-secret"),
        "the provider secret was persisted in plaintext"
    );

    let (status, settings) = harness
        .send(
            "PATCH",
            "/v1/org/classifier",
            Some(&workspace.admin.token),
            json!({
                "enabled": true,
                "executionMode": "local",
                "providerId": "custom",
                "endpoint": "https://classifier.example.test/v1/chat/completions",
                "model": "test-model",
                "credentialId": "provider-main",
                "responseMode": "prompt_json",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["credentialAvailable"].as_bool(), Some(true));

    let (status, provisioned) = harness
        .send(
            "POST",
            "/v1/installation/classifier/provision",
            Some(&installation_token),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(provisioned["executionMode"].as_str(), Some("local"));
    assert_eq!(
        provisioned["credential"].as_str(),
        Some("first-super-secret")
    );
    assert_eq!(provisioned["credentialVersion"].as_i64(), Some(1));

    let (status, second) = harness
        .send(
            "POST",
            "/v1/org/credentials",
            Some(&workspace.admin.token),
            json!({
                "credentialId": "provider-main",
                "providerId": "custom",
                "secret": "second-super-secret",
                "graceHours": 24,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["version"].as_i64(), Some(2));
    let (status, listed) = harness
        .get("/v1/org/credentials", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().expect("credentials").len(), 1);
    assert_eq!(listed[0]["version"].as_i64(), Some(2));
    assert!(!listed.to_string().contains("second-super-secret"));

    let (status, provisioned) = harness
        .send(
            "POST",
            "/v1/installation/classifier/provision",
            Some(&installation_token),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        provisioned["credential"].as_str(),
        Some("second-super-secret")
    );
    assert_eq!(provisioned["credentialVersion"].as_i64(), Some(2));

    let (status, managed) = harness
        .send(
            "PATCH",
            "/v1/org/classifier",
            Some(&workspace.admin.token),
            json!({
                "enabled": true,
                "executionMode": "managed",
                "providerId": "custom",
                "endpoint": "https://classifier.example.test/v1/chat/completions",
                "model": "test-model",
                "credentialId": "provider-main",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(managed["executionMode"].as_str(), Some("managed"));
    let (status, provisioned) = harness
        .send(
            "POST",
            "/v1/installation/classifier/provision",
            Some(&installation_token),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(provisioned["executionMode"].as_str(), Some("managed"));
    assert_eq!(provisioned["endpoint"].as_str(), Some(""));
    assert_eq!(provisioned["credentialId"].as_str(), Some(""));
    assert!(provisioned["credential"].is_null());

    let (status, _) = harness
        .send(
            "DELETE",
            credential_path,
            Some(&workspace.admin.token),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, listed) = harness
        .get("/v1/org/credentials", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed.as_array().expect("credentials").is_empty());
}

fn price(provider: &str, model: &str, input: f64) -> Value {
    json!({
        "providerId": provider,
        "modelId": model,
        "currency": "USD",
        "inputPerMillion": input,
        "outputPerMillion": 2.5,
        "cacheReadPerMillion": 0.25,
        "cacheWritePerMillion": 0.5,
        "reasoningPerMillion": 3.0,
        "requestPerRequest": 0.01,
        "imagePerImage": 0.02,
        "authority": "manual",
    })
}

#[tokio::test]
async fn organization_prices_validate_version_and_retire_cleanly() {
    let harness = harness!();
    let workspace = harness.workspace("price-lifecycle").await;
    let provider = format!("provider-{}", Uuid::new_v4().simple());
    let model = "model-a";

    for invalid in [
        json!({"providerId": "", "modelId": model}),
        price(&provider, model, -0.01),
        json!({"providerId": provider, "modelId": model, "currency": "US"}),
        json!({"providerId": provider, "modelId": model, "authority": "invented"}),
    ] {
        let (status, _) = harness
            .send(
                "POST",
                "/v1/org/prices",
                Some(&workspace.admin.token),
                invalid,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let (status, created) = harness
        .send(
            "POST",
            "/v1/org/prices",
            Some(&workspace.admin.token),
            price(&provider, model, 1.25),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["scope"].as_str(), Some("organization"));
    assert_eq!(created["price"]["inputPerMillion"].as_f64(), Some(1.25));
    let first_id = Uuid::parse_str(created["id"].as_str().expect("price id")).expect("UUID");

    let (status, updated) = harness
        .send(
            "PATCH",
            &format!("/v1/org/prices/{first_id}"),
            Some(&workspace.admin.token),
            price(&provider, model, 9.75),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let second_id = Uuid::parse_str(updated["id"].as_str().expect("new price id")).expect("UUID");
    assert_ne!(first_id, second_id);
    assert_eq!(updated["price"]["inputPerMillion"].as_f64(), Some(9.75));

    let (status, prices) = harness
        .get("/v1/org/prices", Some(&workspace.viewer.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    let matches = prices
        .as_array()
        .expect("prices")
        .iter()
        .filter(|entry| entry["providerId"] == provider && entry["modelId"] == model)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0]["id"].as_str(),
        Some(second_id.to_string().as_str())
    );

    let (status, _) = harness
        .send(
            "DELETE",
            &format!("/v1/org/prices/{second_id}"),
            Some(&workspace.admin.token),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, prices) = harness
        .get("/v1/org/prices", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!prices.as_array().expect("prices").iter().any(|entry| {
        entry["providerId"] == provider
            && entry["modelId"] == model
            && entry["scope"] == "organization"
    }));

    let service_token = harness
        .create_dashboard_token(workspace.organization_id, "admin")
        .await;
    let (status, _) = harness
        .send(
            "POST",
            "/v1/org/prices",
            Some(&service_token),
            price(&provider, "service-token-model", 1.0),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn retention_settings_persist_and_reject_values_outside_the_contract() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("retention-settings").await;

    for retention_days in [0, 3651] {
        let (status, _) = harness
            .send(
                "PATCH",
                "/v1/org/settings",
                Some(&workspace.admin.token),
                json!({"retentionDays": retention_days}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = harness
        .send(
            "PATCH",
            "/v1/org/settings",
            Some(&workspace.viewer.token),
            json!({"retentionDays": 30}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = harness
        .send(
            "PATCH",
            "/v1/org/settings",
            Some(&workspace.admin.token),
            json!({"retentionDays": 30}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, settings) = harness
        .get("/v1/org/settings", Some(&workspace.viewer.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["retentionDays"].as_i64(), Some(30));
}

#[tokio::test]
async fn a_personal_enrollment_code_has_one_winner_under_concurrency() {
    let harness = harness!();
    let workspace = harness.workspace("enrollment-race").await;
    let (_, created) = harness
        .send(
            "POST",
            "/v1/me/enrollment-codes",
            Some(&workspace.admin.token),
            json!({"installationName": "laptop", "platform": "linux"}),
        )
        .await;
    let code = created["code"]
        .as_str()
        .expect("enrollment code")
        .to_owned();

    let (first, second) = tokio::join!(
        harness.send(
            "POST",
            "/v1/enroll",
            None,
            json!({"enrollmentToken": code, "installationName": "racer-a"})
        ),
        harness.send(
            "POST",
            "/v1/enroll",
            None,
            json!({"enrollmentToken": code, "installationName": "racer-b"})
        ),
    );
    let successes = [first.0, second.0]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    let refusals = [first.0, second.0]
        .into_iter()
        .filter(|status| *status == StatusCode::UNAUTHORIZED)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(refusals, 1);

    let installed = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM installations
         WHERE organization_id = $1 AND owner_user_id = $2
           AND name IN ('racer-a', 'racer-b')",
    )
    .bind(workspace.organization_id)
    .bind(workspace.admin.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("count race-created installations");
    assert_eq!(installed, 1);
}
