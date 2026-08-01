use chrono::Utc;
use metrune_core::{
    aggregate_session, aggregate_session_v2, stable_session_key, CategoryAssignment,
    ClassificationMethod, Cost, IdentityContext, ModelActivityStep, SignalCount, TokenBreakdown,
    TurnSnapshot, UsageMessage, WorkflowSignal,
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
        session_started_at: None,
        observed_at: Utc::now(),
        tokens: TokenBreakdown {
            input: 10,
            output: 4,
            ..TokenBreakdown::default()
        },
        cost: Cost::default(),
        turn_sequence: 1,
        activity_sequence: 1,
        workflow_signals: vec![],
        signal_capabilities: vec![],
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
fn v2_turn_payload_contains_ordered_metadata_but_no_local_content_or_raw_ids() {
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
        session_started_at: None,
        observed_at: Utc::now(),
        tokens: TokenBreakdown {
            input: 10,
            output: 4,
            ..TokenBreakdown::default()
        },
        cost: Cost::default(),
        turn_sequence: 1,
        activity_sequence: 1,
        workflow_signals: vec![WorkflowSignal::Edited],
        signal_capabilities: WorkflowSignal::ALL.to_vec(),
        classification_text: Some("private prompt and source code".into()),
    };
    let turn = TurnSnapshot {
        sequence: 1,
        category: CategoryAssignment::default(),
        classification_method: ClassificationMethod::Rule,
        classification_cached: false,
        model_activity: vec![ModelActivityStep {
            sequence: 0,
            provider_id: "openai".into(),
            model_id: "gpt-5".into(),
            tokens: message.tokens.clone(),
            cost: Cost::default(),
            call_count: 1,
        }],
        workflow_signals: vec![SignalCount {
            signal: WorkflowSignal::Edited,
            count: 1,
            model_step_index: Some(0),
        }],
    };
    let snapshot =
        aggregate_session_v2(&[message], &identity, 1, vec![turn], Default::default()).unwrap();
    let json = serde_json::to_string(&snapshot).unwrap();
    for secret in [
        "raw-message-id",
        "raw-session-id",
        "/secret/customer-repo",
        "private prompt",
        "source code",
    ] {
        assert!(!json.contains(secret), "serialized local secret: {secret}");
    }
    assert!(json.contains("\"sequence\":1"));
    assert!(json.contains("\"signal\":\"edited\""));
    assert!(!json.contains("observedAt"));
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
        session_started_at: None,
        observed_at: chrono::Utc::now(),
        tokens: TokenBreakdown {
            input: 1,
            ..TokenBreakdown::default()
        },
        cost: Cost::default(),
        turn_sequence: 1,
        activity_sequence: 1,
        workflow_signals: vec![],
        signal_capabilities: vec![],
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
