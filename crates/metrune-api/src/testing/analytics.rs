//! Ingest and analytics against a live ClickHouse.
//!
//! The isolation these cover is enforced by the `WHERE` clauses built in
//! `filtered_query` and `personal_usage_suffix`. Unit tests can only assert the
//! SQL text; only a real query proves a co-tenant's rows stay invisible.

use super::harness::{analytics_harness, batch, snapshot};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn an_ingested_session_appears_only_in_its_own_organizations_analytics() {
    let harness = analytics_harness!();
    let alpha = harness.workspace("an-alpha").await;
    let beta = harness.workspace("an-beta").await;
    let (_, token) = harness
        .create_installation(alpha.organization_id, Some(alpha.admin.user_id))
        .await;

    let (status, ack) = harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch("batch-1", vec![snapshot("alpha-session", "alpha-user")]),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ack["accepted"].as_u64(), Some(1), "ingest rejected: {ack}");

    let (status, overview) = harness
        .get("/v1/analytics/overview", Some(&alpha.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(overview["sessions"].as_u64(), Some(1));
    assert_eq!(overview["totalTokens"].as_u64(), Some(1_500));

    // The co-tenant queries the same table and must see nothing.
    let (status, overview) = harness
        .get("/v1/analytics/overview", Some(&beta.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        overview["sessions"].as_u64(),
        Some(0),
        "a co-tenant's analytics counted another organization's sessions"
    );
    assert_eq!(overview["totalTokens"].as_u64(), Some(0));
}

#[tokio::test]
async fn session_listings_and_facets_stay_organization_scoped() {
    let harness = analytics_harness!();
    let alpha = harness.workspace("sl-alpha").await;
    let beta = harness.workspace("sl-beta").await;
    let (_, token) = harness
        .create_installation(alpha.organization_id, Some(alpha.admin.user_id))
        .await;
    harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch("batch-1", vec![snapshot("sl-session", "sl-user")]),
        )
        .await;

    // Session drilldown is reserved for service dashboard tokens; a signed-in
    // user is refused regardless of role.
    let (status, _) = harness
        .get("/v1/analytics/sessions", Some(&alpha.admin.token))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let alpha_service = harness
        .create_dashboard_token(alpha.organization_id, "analyst")
        .await;
    let beta_service = harness
        .create_dashboard_token(beta.organization_id, "analyst")
        .await;

    let (status, sessions) = harness
        .get("/v1/analytics/sessions", Some(&alpha_service))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sessions.as_array().expect("session array").len(), 1);

    let (status, sessions) = harness
        .get("/v1/analytics/sessions", Some(&beta_service))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        sessions.as_array().expect("session array").is_empty(),
        "a co-tenant's service token listed another organization's sessions"
    );

    let (status, facets) = harness
        .get("/v1/analytics/facets", Some(&beta.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        facets["projects"].as_array().expect("projects").is_empty(),
        "facets leaked another organization's project names"
    );
    let (_, facets) = harness
        .get("/v1/analytics/facets", Some(&alpha.admin.token))
        .await;
    assert!(facets["projects"]
        .as_array()
        .expect("projects")
        .iter()
        .any(|project| project.as_str() == Some("atlas")));
}

#[tokio::test]
async fn a_viewer_service_token_cannot_open_the_session_drilldown() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("drilldown-role").await;
    let viewer = harness
        .create_dashboard_token(workspace.organization_id, "viewer")
        .await;
    let (status, _) = harness.get("/v1/analytics/sessions", Some(&viewer)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let revoked = harness
        .create_dashboard_token(workspace.organization_id, "analyst")
        .await;
    sqlx::query("UPDATE dashboard_tokens SET revoked_at = NOW() WHERE organization_id = $1 AND role = 'analyst'")
        .bind(workspace.organization_id)
        .execute(&harness.postgres)
        .await
        .expect("revoke the service token");
    let (status, _) = harness.get("/v1/analytics/sessions", Some(&revoked)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn personal_usage_only_covers_the_callers_own_installations() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("pu").await;
    let (_, admin_token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;
    harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&admin_token),
            batch("batch-1", vec![snapshot("pu-session", "pu-user")]),
        )
        .await;

    let (status, usage) = harness
        .get("/v1/me/usage", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(usage["overview"]["sessions"].as_u64(), Some(1));

    // A colleague in the same organization owns no installation, so their
    // personal view must be empty even though the org-wide view is not.
    let (status, usage) = harness
        .get("/v1/me/usage", Some(&workspace.viewer.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        usage["overview"]["sessions"].as_u64(),
        Some(0),
        "personal usage showed a colleague's sessions"
    );

    let (status, sessions) = harness
        .get("/v1/me/sessions", Some(&workspace.viewer.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(sessions.as_array().expect("session array").is_empty());
}

#[tokio::test]
async fn personal_queries_refuse_an_installation_the_caller_does_not_own() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("pu-owned").await;
    let (installation, _) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    for path in [
        format!("/v1/me/usage?installationId={installation}"),
        format!("/v1/me/sessions?installationId={installation}"),
    ] {
        let (status, _) = harness.get(&path, Some(&workspace.viewer.token)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} answered for an installation the caller does not own"
        );
    }
}

#[tokio::test]
async fn a_replayed_batch_is_acknowledged_without_double_counting() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("replay").await;
    let (_, token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;
    let payload = batch(
        "batch-replay",
        vec![snapshot("replay-session", "replay-user")],
    );

    let (status, first) = harness
        .send("POST", "/v1/ingest/sessions", Some(&token), payload.clone())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["accepted"].as_u64(), Some(1));

    let (status, second) = harness
        .send("POST", "/v1/ingest/sessions", Some(&token), payload)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["accepted"].as_u64(), Some(0));
    assert_eq!(second["duplicates"].as_u64(), Some(1));

    let (_, overview) = harness
        .get("/v1/analytics/overview", Some(&workspace.admin.token))
        .await;
    assert_eq!(
        overview["sessions"].as_u64(),
        Some(1),
        "a retried batch was counted twice"
    );
}

#[tokio::test]
async fn a_newer_revision_replaces_the_stored_session() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("revision").await;
    let (_, token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    let first = snapshot("revision-session", "revision-user");
    harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch("batch-1", vec![first.clone()]),
        )
        .await;

    // The same session, resumed: higher revision, more tokens.
    let mut second = first.clone();
    second.revision = 2;
    second.usage_by_model[0].tokens.output = 2_500;
    harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch("batch-2", vec![second]),
        )
        .await;

    let (_, overview) = harness
        .get("/v1/analytics/overview", Some(&workspace.admin.token))
        .await;
    assert_eq!(
        overview["sessions"].as_u64(),
        Some(1),
        "a resumed session was stored twice instead of replaced"
    );
    assert_eq!(overview["totalTokens"].as_u64(), Some(3_500));
}

#[tokio::test]
async fn a_snapshot_with_raw_identifiers_is_rejected_without_failing_the_batch() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("validation").await;
    let (_, token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    let mut raw = snapshot("raw-session", "raw-user");
    raw.session_key = "too-short".into();
    raw.user_key = "also-short".into();

    let (status, ack) = harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch(
                "batch-mixed",
                vec![raw, snapshot("good-session", "good-user")],
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ack["accepted"].as_u64(), Some(1));
    assert_eq!(ack["rejected"].as_u64(), Some(1));
    assert!(!ack["errors"].as_array().expect("errors").is_empty());
}

#[tokio::test]
async fn an_unsupported_batch_schema_is_refused_outright() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("schema").await;
    let (_, token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    let (status, _) = harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            json!({
                "schemaVersion": "999",
                "batchId": "batch-future",
                "sentAt": chrono::Utc::now(),
                "snapshots": [],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn analytics_filters_narrow_the_result_without_escaping_the_organization() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("filters").await;
    let (_, token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;
    harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch("batch-1", vec![snapshot("filter-session", "filter-user")]),
        )
        .await;

    let (status, matching) = harness
        .get(
            "/v1/analytics/overview?project=atlas&client=codex",
            Some(&workspace.admin.token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(matching["sessions"].as_u64(), Some(1));

    let (status, other) = harness
        .get(
            "/v1/analytics/overview?project=not-a-project",
            Some(&workspace.admin.token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(other["sessions"].as_u64(), Some(0));

    // A filter value carrying SQL syntax is a bound parameter, not a fragment.
    let (status, injected) = harness
        .get(
            "/v1/analytics/overview?project=atlas%27%20OR%20%271%27%3D%271",
            Some(&workspace.admin.token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        injected["sessions"].as_u64(),
        Some(0),
        "a quoted filter value was interpolated into the query"
    );
}

#[tokio::test]
async fn a_revoked_installation_token_cannot_ingest() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("revoked-ingest").await;
    let (installation, token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    sqlx::query("UPDATE installations SET revoked_at = NOW() WHERE id = $1")
        .bind(installation)
        .execute(&harness.postgres)
        .await
        .expect("revoke the installation");

    let (status, _) = harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch("batch-1", vec![snapshot("revoked-session", "revoked-user")]),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ingested_rows_carry_the_organizations_retention_not_the_clients_claim() {
    let harness = analytics_harness!();
    let workspace = harness.workspace("retention").await;
    sqlx::query("UPDATE organizations SET retention_days = 17 WHERE id = $1")
        .bind(workspace.organization_id)
        .execute(&harness.postgres)
        .await
        .expect("set retention");
    let (_, token) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&token),
            batch(
                "batch-1",
                vec![snapshot("retention-session", "retention-user")],
            ),
        )
        .await;

    let stored = harness
        .state
        .clickhouse_for_tests()
        .query(
            "SELECT retention_days FROM session_snapshots_dedup FINAL
             WHERE organization_id = ? LIMIT 1",
        )
        .bind(workspace.organization_id.to_string())
        .fetch_one::<u32>()
        .await
        .expect("read the stored retention");
    assert_eq!(stored, 17);
}
