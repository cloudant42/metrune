use chrono::Utc;
use metrune_core::{
    aggregate_session, stable_session_key, CategoryAssignment, Cost, IdentityContext,
    TokenBreakdown, UsageMessage,
};

#[test]
fn snapshot_contains_only_pseudonymous_identity_and_usage_metadata() {
    let identity = IdentityContext {
        pseudonym_key: b"test-key".to_vec(),
        user_alias: "employee-17".into(),
        ..IdentityContext::default()
    };
    let message = UsageMessage {
        source_message_id: "raw-message-id".into(),
        session_id: "raw-session-id".into(),
        project_path: Some("/secret/customer-repo".into()),
        client_id: "codex".into(),
        client_version: None,
        provider_id: "openai".into(),
        model_id: "gpt-5".into(),
        observed_at: Utc::now(),
        tokens: TokenBreakdown {
            input: 10,
            output: 4,
            ..TokenBreakdown::default()
        },
        cost: Cost::default(),
        classification_text: Some("private source code".into()),
    };
    let snapshot =
        aggregate_session(&[message], &identity, 1, CategoryAssignment::default()).unwrap();
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("raw-session-id"));
    assert!(!json.contains("/secret/customer-repo"));
    assert!(!json.contains("private source code"));
    assert_eq!(snapshot.total_tokens(), 14);
}

#[test]
fn session_identity_is_stable_across_installation_identity_keys() {
    let first = IdentityContext {
        pseudonym_key: b"installation-one".to_vec(),
        ..IdentityContext::default()
    };
    let second = IdentityContext {
        pseudonym_key: b"installation-two".to_vec(),
        ..IdentityContext::default()
    };
    let message = UsageMessage {
        source_message_id: "m".into(),
        session_id: "stable-session-id".into(),
        project_path: None,
        client_id: "codex".into(),
        client_version: None,
        provider_id: "openai".into(),
        model_id: "gpt-5".into(),
        observed_at: chrono::Utc::now(),
        tokens: TokenBreakdown {
            input: 1,
            ..TokenBreakdown::default()
        },
        cost: Cost::default(),
        classification_text: None,
    };
    let one = aggregate_session(
        std::slice::from_ref(&message),
        &first,
        1,
        CategoryAssignment::default(),
    )
    .unwrap();
    let two = aggregate_session(
        std::slice::from_ref(&message),
        &second,
        1,
        CategoryAssignment::default(),
    )
    .unwrap();
    assert_eq!(one.session_key, two.session_key);
    assert_eq!(
        one.session_key,
        stable_session_key("codex", "stable-session-id")
    );
    assert_ne!(
        one.session_key,
        stable_session_key("codex", "different-session-id")
    );
    assert_ne!(
        one.session_key,
        stable_session_key("claude", "stable-session-id")
    );
}
