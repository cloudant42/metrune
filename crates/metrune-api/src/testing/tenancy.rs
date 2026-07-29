//! One organization's admin must not be able to read or mutate another
//! organization's records, even when they know the exact target id.

use super::harness::harness;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn listings_only_ever_contain_the_callers_organization() {
    let harness = harness!();
    let alpha = harness.workspace("alpha").await;
    let beta = harness.workspace("beta").await;
    harness
        .create_installation(beta.organization_id, Some(beta.admin.user_id))
        .await;
    harness.create_team(beta.organization_id, "beta-team").await;

    let (status, members) = harness
        .get("/v1/org/members", Some(&alpha.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    let emails: Vec<&str> = members
        .as_array()
        .expect("member array")
        .iter()
        .filter_map(|member| member["email"].as_str())
        .collect();
    assert!(
        !emails.contains(&beta.admin.email.as_str()),
        "a co-tenant's member appeared in this organization's listing"
    );
    assert!(emails.contains(&alpha.admin.email.as_str()));

    let (status, teams) = harness.get("/v1/org/teams", Some(&alpha.admin.token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(teams.as_array().expect("team array").is_empty());

    let (status, installations) = harness
        .get("/v1/org/installations", Some(&alpha.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(installations
        .as_array()
        .expect("installation array")
        .is_empty());
}

#[tokio::test]
async fn an_admin_cannot_mutate_a_team_belonging_to_another_organization() {
    let harness = harness!();
    let alpha = harness.workspace("alpha-team").await;
    let beta = harness.workspace("beta-team").await;
    let beta_team = harness.create_team(beta.organization_id, "beta-only").await;

    let (status, _) = harness
        .send(
            "PATCH",
            &format!("/v1/org/teams/{beta_team}"),
            Some(&alpha.admin.token),
            json!({"name": "hijacked"}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = harness
        .send(
            "DELETE",
            &format!("/v1/org/teams/{beta_team}"),
            Some(&alpha.admin.token),
            json!(null),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let name = sqlx::query_scalar::<_, String>("SELECT name FROM teams WHERE id = $1")
        .bind(beta_team)
        .fetch_one(&harness.postgres)
        .await
        .expect("the team must still exist");
    assert_eq!(name, "beta-only");
}

#[tokio::test]
async fn an_admin_cannot_reassign_another_organizations_installation() {
    let harness = harness!();
    let alpha = harness.workspace("alpha-install").await;
    let beta = harness.workspace("beta-install").await;
    let (beta_installation, _) = harness
        .create_installation(beta.organization_id, Some(beta.admin.user_id))
        .await;
    let alpha_team = harness
        .create_team(alpha.organization_id, "alpha-team")
        .await;

    let (status, _) = harness
        .send(
            "PATCH",
            &format!("/v1/org/installations/{beta_installation}"),
            Some(&alpha.admin.token),
            json!({"teamId": alpha_team}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_admin_cannot_change_a_membership_in_another_organization() {
    let harness = harness!();
    let alpha = harness.workspace("alpha-member").await;
    let beta = harness.workspace("beta-member").await;

    let (status, _) = harness
        .send(
            "PATCH",
            &format!("/v1/org/members/{}", beta.viewer.user_id),
            Some(&alpha.admin.token),
            json!({"role": "admin"}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(beta.organization_id)
    .bind(beta.viewer.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read the membership");
    assert_eq!(role, "viewer", "a co-tenant escalated a foreign membership");
}

#[tokio::test]
async fn a_personal_installation_cannot_be_revoked_by_someone_else() {
    let harness = harness!();
    let workspace = harness.workspace("owned").await;
    let (installation, _) = harness
        .create_installation(workspace.organization_id, Some(workspace.admin.user_id))
        .await;

    // The viewer is a legitimate member of the same organization, but does not
    // own this installation.
    let (status, _) = harness
        .send(
            "DELETE",
            &format!("/v1/me/installations/{installation}"),
            Some(&workspace.viewer.token),
            json!(null),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!harness.installation_is_revoked(installation).await);

    let (status, _) = harness
        .send(
            "DELETE",
            &format!("/v1/me/installations/{installation}"),
            Some(&workspace.admin.token),
            json!(null),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(harness.installation_is_revoked(installation).await);
}

#[tokio::test]
async fn removing_a_member_revokes_the_installations_they_still_hold() {
    let harness = harness!();
    let workspace = harness.workspace("offboard").await;
    let (installation, installation_token) = harness
        .create_installation(workspace.organization_id, Some(workspace.viewer.user_id))
        .await;

    // The client is ingesting happily before the member is offboarded.
    assert!(!harness.installation_is_revoked(installation).await);

    let (status, _) = harness
        .send(
            "DELETE",
            &format!("/v1/org/members/{}", workspace.viewer.user_id),
            Some(&workspace.admin.token),
            json!(null),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert!(
        harness.installation_is_revoked(installation).await,
        "an offboarded member's installation token still ingests"
    );

    // And the token itself is no longer accepted by the ingest route.
    let (status, _) = harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(&installation_token),
            json!({
                "schemaVersion": metrune_core::SCHEMA_VERSION,
                "batchId": "batch-1",
                "sentAt": chrono::Utc::now(),
                "snapshots": [],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_enrollment_code_only_enrolls_into_its_own_organization() {
    let harness = harness!();
    let workspace = harness.workspace("enroll-scope").await;
    let (status, created) = harness
        .send(
            "POST",
            "/v1/me/enrollment-codes",
            Some(&workspace.admin.token),
            json!({"installationName": "laptop", "platform": "linux"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let code = created["code"]
        .as_str()
        .expect("enrollment code")
        .to_string();

    let (status, enrolled) = harness
        .send(
            "POST",
            "/v1/enroll",
            None,
            json!({"enrollmentToken": code, "installationName": "laptop"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        enrolled["organizationId"].as_str(),
        Some(workspace.organization_id.to_string().as_str())
    );

    // A one-time code must not enroll a second machine.
    let (status, _) = harness
        .send(
            "POST",
            "/v1/enroll",
            None,
            json!({"enrollmentToken": code, "installationName": "laptop-2"}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enrollment_rejects_unbounded_names_and_unknown_platforms() {
    let harness = harness!();
    let workspace = harness.workspace("enroll-validation").await;
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
        .to_string();

    for name in [
        String::new(),
        "   ".into(),
        "a".repeat(121),
        "bad\u{1b}[2Jname".into(),
    ] {
        let (status, _) = harness
            .send(
                "POST",
                "/v1/enroll",
                None,
                json!({"enrollmentToken": code, "installationName": name}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the installation name {name:?} was accepted"
        );
    }

    let (status, _) = harness
        .send(
            "POST",
            "/v1/enroll",
            None,
            json!({"enrollmentToken": code, "installationName": "laptop", "platform": "solaris"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The rejections must not have burned the one-time code.
    let (status, _) = harness
        .send(
            "POST",
            "/v1/enroll",
            None,
            json!({"enrollmentToken": code, "installationName": "laptop"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_last_admin_cannot_be_demoted_or_removed() {
    let harness = harness!();
    let organization_id = harness.create_organization("sole-admin").await;
    let admin = harness
        .create_member(organization_id, "sole", "admin")
        .await;

    let (status, _) = harness
        .send(
            "PATCH",
            &format!("/v1/org/members/{}", admin.user_id),
            Some(&admin.token),
            json!({"role": "viewer"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = harness
        .send(
            "DELETE",
            &format!("/v1/org/members/{}", admin.user_id),
            Some(&admin.token),
            json!(null),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn each_organization_exports_a_different_recovery_key() {
    let harness = harness!();
    let alpha = harness.workspace("vault-alpha").await;
    let beta = harness.workspace("vault-beta").await;

    async fn export(
        harness: &super::harness::Harness,
        token: &str,
        password: &str,
    ) -> (StatusCode, serde_json::Value) {
        harness
            .send(
                "POST",
                "/v1/org/vault/recovery",
                Some(token),
                json!({"password": password}),
            )
            .await
    }

    let (status, alpha_key) = export(&harness, &alpha.admin.token, &alpha.admin.password).await;
    assert_eq!(status, StatusCode::OK);
    let (status, beta_key) = export(&harness, &beta.admin.token, &beta.admin.password).await;
    assert_eq!(status, StatusCode::OK);

    let alpha_key = alpha_key["recoveryKey"].as_str().expect("alpha key");
    let beta_key = beta_key["recoveryKey"].as_str().expect("beta key");
    assert!(alpha_key.starts_with("mvrk_"));
    assert_ne!(
        alpha_key, beta_key,
        "co-tenants received the same vault key, so either can read the other's credentials"
    );

    // The export is one-shot per organization.
    let (status, _) = export(&harness, &alpha.admin.token, &alpha.admin.password).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_recovery_export_requires_the_callers_real_password() {
    let harness = harness!();
    let workspace = harness.workspace("vault-password").await;
    let (status, _) = harness
        .send(
            "POST",
            "/v1/org/vault/recovery",
            Some(&workspace.admin.token),
            json!({"password": "not-the-password"}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A refused attempt must not consume the one-time export.
    let (status, _) = harness
        .send(
            "POST",
            "/v1/org/vault/recovery",
            Some(&workspace.admin.token),
            json!({"password": workspace.admin.password.clone()}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}
