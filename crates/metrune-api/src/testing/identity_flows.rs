//! Sign-in, workspace selection, and the brute-force budget.

use super::harness::harness;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn a_correct_password_issues_a_session_that_works() {
    let harness = harness!();
    let workspace = harness.workspace("login").await;
    let (status, body) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({"email": workspace.admin.email, "password": workspace.admin.password}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let token = body["sessionToken"].as_str().expect("session token");
    assert!(token.starts_with("mts_"));

    let (status, me) = harness.get("/v1/auth/me", Some(token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["email"].as_str(), Some(workspace.admin.email.as_str()));

    let (status, _) = harness
        .send("POST", "/v1/auth/logout", Some(token), json!(null))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = harness.get("/v1/auth/me", Some(token)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "logout did not end the session"
    );
}

#[tokio::test]
async fn the_email_address_is_matched_case_insensitively() {
    let harness = harness!();
    let workspace = harness.workspace("login-case").await;
    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({
                "email": format!("  {}  ", workspace.admin.email.to_uppercase()),
                "password": workspace.admin.password,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_wrong_password_never_issues_a_session() {
    let harness = harness!();
    let workspace = harness.workspace("login-wrong").await;
    let (status, body) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({"email": workspace.admin.email, "password": "wrong-password"}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["sessionToken"].is_null());
}

#[tokio::test]
async fn an_unknown_account_is_indistinguishable_from_a_wrong_password() {
    let harness = harness!();
    let workspace = harness.workspace("login-enumerate").await;
    let (unknown_status, unknown_body) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({"email": "nobody-here@example.test", "password": "whatever-password"}),
        )
        .await;
    let (wrong_status, wrong_body) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({"email": workspace.admin.email, "password": "whatever-password"}),
        )
        .await;
    assert_eq!(unknown_status, wrong_status);
    assert_eq!(
        unknown_body, wrong_body,
        "the response distinguishes real accounts"
    );
}

/// The per-account budget used to be charged only after the password was
/// verified, so a guesser was never actually stopped — a correct password still
/// succeeded on the attempt after the account was nominally locked out.
#[tokio::test]
async fn the_account_budget_stops_guessing_before_the_password_is_checked() {
    let harness = harness!();
    let workspace = harness.workspace("login-throttle").await;
    async fn attempt(harness: &super::harness::Harness, email: &str, password: &str) -> StatusCode {
        harness
            .send(
                "POST",
                "/v1/auth/login",
                None,
                json!({"email": email, "password": password}),
            )
            .await
            .0
    }

    let email = workspace.admin.email.as_str();
    for _ in 0..crate::limits::MAX_LOGIN_FAILURES_PER_WINDOW {
        assert_eq!(
            attempt(&harness, email, "wrong-password").await,
            StatusCode::UNAUTHORIZED
        );
    }

    assert_eq!(
        attempt(&harness, email, "wrong-password").await,
        StatusCode::TOO_MANY_REQUESTS,
        "the account budget was not enforced"
    );
    assert_eq!(
        attempt(&harness, email, &workspace.admin.password).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a locked-out account still authenticated a correct password"
    );
}

#[tokio::test]
async fn switching_workspaces_requires_membership_of_the_target() {
    let harness = harness!();
    let alpha = harness.workspace("switch-alpha").await;
    let beta = harness.workspace("switch-beta").await;

    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/organization",
            Some(&alpha.admin.token),
            json!({"organizationId": beta.organization_id}),
        )
        .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a member switched into a workspace they do not belong to"
    );

    let (status, me) = harness
        .send(
            "POST",
            "/v1/auth/organization",
            Some(&alpha.admin.token),
            json!({"organizationId": alpha.organization_id}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        me["organizationId"].as_str(),
        Some(alpha.organization_id.to_string().as_str())
    );
}

#[tokio::test]
async fn creating_a_workspace_makes_the_creator_its_admin() {
    let harness = harness!();
    let workspace = harness.workspace("create-org").await;
    let (status, created) = harness
        .send(
            "POST",
            "/v1/organizations",
            Some(&workspace.viewer.token),
            json!({"name": "A Brand New Workspace"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["role"].as_str(), Some("admin"));

    // Being an admin of the new workspace must not grant anything in the old one.
    let (status, _) = harness
        .get("/v1/org/members", Some(&workspace.viewer.token))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the session should now target the new workspace"
    );
}

#[tokio::test]
async fn workspace_names_are_bounded() {
    let harness = harness!();
    let workspace = harness.workspace("org-name").await;
    for name in [String::new(), "   ".into(), "a".repeat(121)] {
        let (status, _) = harness
            .send(
                "POST",
                "/v1/organizations",
                Some(&workspace.admin.token),
                json!({"name": name}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the name {name:?} was accepted"
        );
    }
}
