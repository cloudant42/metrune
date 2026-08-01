//! Postgres-backed fixture for the HTTP tests.
//!
//! The tests need a real database because every authorization decision in this
//! crate is a SQL predicate — a mocked store would only prove the mock agrees
//! with itself. `make test-integration` starts the container and points
//! `METRUNE_TEST_DATABASE_URL` at it; without that variable the tests report
//! that they were skipped rather than failing, so a plain `cargo test` stays
//! green on a machine with no Docker.

use crate::app::{router, AppState};
use crate::error::token_hash;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{header::AUTHORIZATION, Request, Response, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) const DATABASE_URL_VAR: &str = "METRUNE_TEST_DATABASE_URL";
pub(crate) const CLICKHOUSE_URL_VAR: &str = "METRUNE_TEST_CLICKHOUSE_URL";

/// Analytics tests share one ClickHouse table and isolate themselves by
/// organization id, which is the leading column of the sort key.
async fn test_clickhouse() -> Option<clickhouse::Client> {
    let url = std::env::var(CLICKHOUSE_URL_VAR)
        .ok()
        .filter(|url| !url.trim().is_empty())?;
    clickhouse::Client::default()
        .with_url(&url)
        .query("CREATE DATABASE IF NOT EXISTS metrune")
        .execute()
        .await
        .expect("create the test ClickHouse database");
    let client = clickhouse::Client::default()
        .with_url(&url)
        .with_database("metrune");
    crate::app::ensure_deduplicated_session_table(&client)
        .await
        .expect("create the deduplicated session table");
    Some(client)
}

/// A prepared organization with tokens for each role.
pub(crate) struct Workspace {
    pub(crate) organization_id: Uuid,
    pub(crate) admin: Session,
    pub(crate) viewer: Session,
}

pub(crate) struct Session {
    pub(crate) user_id: Uuid,
    pub(crate) token: String,
    pub(crate) email: String,
    pub(crate) password: String,
}

pub(crate) struct Harness {
    pub(crate) state: AppState,
    pub(crate) postgres: PgPool,
}

/// Each test owns its pool. `#[tokio::test]` builds a runtime per test and
/// drops it when the test ends, so a pool shared between tests would lose the
/// background tasks it needs the moment the first test finished.
///
/// The pool is deliberately small because every test holds one: the migrator
/// takes a Postgres advisory lock, so concurrent runs serialize and all but the
/// first are a no-op.
async fn test_pool() -> Option<PgPool> {
    let url = std::env::var(DATABASE_URL_VAR)
        .ok()
        .filter(|url| !url.trim().is_empty())?;
    let postgres = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&url)
        .await
        .expect("connect to the test database");
    sqlx::migrate!("../../migrations/postgres")
        .run(&postgres)
        .await
        .expect("run migrations against the test database");
    Some(postgres)
}

impl Harness {
    /// Returns `None` when no test database is configured, so the caller can
    /// skip instead of failing.
    pub(crate) async fn start() -> Option<Self> {
        let postgres = test_pool().await?;
        Some(Self {
            state: AppState::for_tests(postgres.clone(), None),
            postgres,
        })
    }

    /// Like [`Harness::start`], but also requires a live ClickHouse. Analytics
    /// and ingest routes are unusable without it.
    pub(crate) async fn start_with_analytics() -> Option<Self> {
        let postgres = test_pool().await?;
        let clickhouse = test_clickhouse().await?;
        Some(Self {
            state: AppState::for_tests(postgres.clone(), Some(clickhouse)),
            postgres,
        })
    }

    pub(crate) async fn request(&self, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = self.raw_response(request).await;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("read the response body")
            .to_bytes();
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, body)
    }

    pub(crate) async fn raw_response(&self, request: Request<Body>) -> Response<Body> {
        // Routes that rate-limit by client address extract `ConnectInfo`, which
        // is only populated by `into_make_service_with_connect_info`. Without
        // this the extractor fails and every such route answers 500.
        let peer = SocketAddr::from(([127, 0, 0, 1], 54321));
        router(self.state.clone())
            .layer(MockConnectInfo(peer))
            .oneshot(request)
            .await
            .expect("route the request")
    }

    pub(crate) async fn get(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        self.request(self.build("GET", path, token, None)).await
    }

    pub(crate) async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.request(self.build(method, path, token, Some(body)))
            .await
    }

    pub(crate) async fn send_client(
        &self,
        path: &str,
        token: &str,
        client_version: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = self.build("POST", path, Some(token), Some(body));
        if let Some(version) = client_version {
            request.headers_mut().insert(
                metrune_core::release::CLIENT_VERSION_HEADER,
                version.parse().expect("valid client-version header"),
            );
        }
        self.request(request).await
    }

    pub(crate) async fn send_form(
        &self,
        path: &str,
        body: impl Into<String>,
    ) -> (StatusCode, serde_json::Value) {
        self.request(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.into()))
                .expect("build a form request"),
        )
        .await
    }

    pub(crate) async fn raw_form_response(
        &self,
        path: &str,
        body: impl Into<String>,
    ) -> Response<Body> {
        self.raw_response(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.into()))
                .expect("build a form request"),
        )
        .await
    }

    fn build(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("build a request"),
            None => builder.body(Body::empty()).expect("build a request"),
        }
    }

    /// Creates an organization with an admin and a viewer, each holding a live
    /// web session. Every identifier is unique so tests sharing a database do
    /// not collide.
    pub(crate) async fn workspace(&self, label: &str) -> Workspace {
        let organization_id = self.create_organization(label).await;
        let admin = self.create_member(organization_id, label, "admin").await;
        let viewer = self.create_member(organization_id, label, "viewer").await;
        Workspace {
            organization_id,
            admin,
            viewer,
        }
    }

    pub(crate) async fn create_organization(&self, label: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO organizations(name) VALUES ($1) RETURNING id")
            .bind(format!("{label}-{}", Uuid::new_v4()))
            .fetch_one(&self.postgres)
            .await
            .expect("insert organization")
    }

    pub(crate) async fn create_member(
        &self,
        organization_id: Uuid,
        label: &str,
        role: &str,
    ) -> Session {
        let email = format!("{label}-{role}-{}@example.test", Uuid::new_v4().simple());
        let password = format!("pw-{}", Uuid::new_v4().simple());
        let hash = hash_password(&password);
        let user_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO users(organization_id, email, display_name, password_hash, role)
             VALUES ($1,$2,$3,$4,$5) RETURNING id",
        )
        .bind(organization_id)
        .bind(&email)
        .bind(format!("{label} {role}"))
        .bind(hash)
        .bind(role)
        .fetch_one(&self.postgres)
        .await
        .expect("insert user");
        sqlx::query(
            "INSERT INTO organization_memberships(organization_id, user_id, role)
             VALUES ($1,$2,$3)",
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(role)
        .execute(&self.postgres)
        .await
        .expect("insert membership");
        let token = self.issue_session(user_id, Some(organization_id)).await;
        Session {
            user_id,
            token,
            email,
            password,
        }
    }

    pub(crate) async fn issue_session(
        &self,
        user_id: Uuid,
        organization_id: Option<Uuid>,
    ) -> String {
        let token = format!("mts_{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO web_sessions(user_id, token_hash, active_organization_id, created_at, expires_at)
             VALUES ($1,$2,$3,NOW(),$4)",
        )
        .bind(user_id)
        .bind(token_hash(&token))
        .bind(organization_id)
        .bind(Utc::now() + Duration::days(1))
        .execute(&self.postgres)
        .await
        .expect("insert web session");
        token
    }

    /// Enrolls an installation directly, returning its id and bearer token.
    pub(crate) async fn create_installation(
        &self,
        organization_id: Uuid,
        owner_user_id: Option<Uuid>,
    ) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let token = format!("mti_{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO installations(id, organization_id, name, token_hash, owner_user_id, platform, created_at)
             VALUES ($1,$2,$3,$4,$5,'linux',NOW())",
        )
        .bind(id)
        .bind(organization_id)
        .bind("test-installation")
        .bind(token_hash(&token))
        .bind(owner_user_id)
        .execute(&self.postgres)
        .await
        .expect("insert installation");
        (id, token)
    }

    pub(crate) async fn create_team(&self, organization_id: Uuid, name: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO teams(organization_id, name) VALUES ($1,$2) RETURNING id",
        )
        .bind(organization_id)
        .bind(name)
        .fetch_one(&self.postgres)
        .await
        .expect("insert team")
    }

    /// Issues a service dashboard token — the non-user branch of
    /// `dashboard_auth`, which some routes accept exclusively.
    pub(crate) async fn create_dashboard_token(&self, organization_id: Uuid, role: &str) -> String {
        let token = format!("met_{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO dashboard_tokens(organization_id, token_hash, name, role)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(organization_id)
        .bind(token_hash(&token))
        .bind(format!("service-{role}"))
        .bind(role)
        .execute(&self.postgres)
        .await
        .expect("insert dashboard token");
        token
    }

    pub(crate) async fn installation_is_revoked(&self, installation_id: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at IS NOT NULL FROM installations WHERE id = $1",
        )
        .bind(installation_id)
        .fetch_one(&self.postgres)
        .await
        .expect("read installation")
    }
}

fn hash_password(password: &str) -> String {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .expect("hash the test password")
        .to_string()
}

/// Skips the body of a test when no test database is configured.
macro_rules! harness {
    () => {
        match crate::testing::harness::Harness::start().await {
            Some(harness) => harness,
            None => {
                eprintln!(
                    "skipping: set {} to run the HTTP integration tests (see `make test-integration`)",
                    crate::testing::harness::DATABASE_URL_VAR
                );
                return;
            }
        }
    };
}

/// Skips the body of a test unless both Postgres and ClickHouse are configured.
macro_rules! analytics_harness {
    () => {
        match crate::testing::harness::Harness::start_with_analytics().await {
            Some(harness) => harness,
            None => {
                eprintln!(
                    "skipping: set {} and {} to run the analytics tests (see `make test-integration`)",
                    crate::testing::harness::DATABASE_URL_VAR,
                    crate::testing::harness::CLICKHOUSE_URL_VAR
                );
                return;
            }
        }
    };
}

pub(crate) use {analytics_harness, harness};

/// Builds a snapshot the ingest contract accepts: pseudonymous keys of the
/// required length and a single priced usage slice.
pub(crate) fn snapshot(session_key: &str, user_key: &str) -> metrune_core::SessionSnapshot {
    use metrune_core::{
        CategoryAssignment, Cost, CostKind, SessionSnapshot, TokenBreakdown, UsageSlice,
        SCHEMA_VERSION,
    };
    let pad = |value: &str| format!("{value:0<40}");
    SessionSnapshot {
        schema_version: SCHEMA_VERSION.into(),
        session_key: pad(session_key),
        revision: 1,
        user_key: pad(user_key),
        project_key: Some("project-key".into()),
        project_alias: Some("atlas".into()),
        team_key: None,
        client_id: "codex".into(),
        client_version: Some("1.0.0".into()),
        started_at: Utc::now() - Duration::minutes(10),
        ended_at: Utc::now() - Duration::minutes(1),
        usage_by_model: vec![UsageSlice {
            provider_id: "openai".into(),
            model_id: "gpt-5".into(),
            tokens: TokenBreakdown {
                input: 1_000,
                output: 500,
                ..TokenBreakdown::default()
            },
            cost: Cost {
                amount: 1.25,
                currency: "USD".into(),
                kind: CostKind::Reported,
                pricebook_version: None,
                price_source: None,
            },
        }],
        category: CategoryAssignment::default(),
        turns: vec![],
        classifier_usage: Default::default(),
        signal_capabilities: vec![],
        classified_token_coverage: 0.0,
        classification_method_counts: vec![],
        turn_detail_truncated: false,
        source_schema_version: None,
    }
}

/// The envelope shape `/v1/ingest/sessions` expects.
pub(crate) fn batch(
    batch_id: &str,
    snapshots: Vec<metrune_core::SessionSnapshot>,
) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": metrune_core::SCHEMA_VERSION,
        "batchId": batch_id,
        "sentAt": Utc::now(),
        "snapshots": snapshots,
    })
}
