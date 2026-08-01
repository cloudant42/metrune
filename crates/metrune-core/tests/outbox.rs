use chrono::Utc;
use metrune_core::{
    state::LocalState, CategoryAssignment, Cost, SessionSnapshot, TokenBreakdown, UsageSlice,
    SCHEMA_VERSION,
};
use std::fs;
use uuid::Uuid;

fn snapshot(revision: u64, tokens: u64) -> SessionSnapshot {
    SessionSnapshot {
        schema_version: SCHEMA_VERSION.into(),
        session_key: "a".repeat(64),
        revision,
        user_key: "b".repeat(64),
        project_key: None,
        project_alias: None,
        team_key: None,
        client_id: "codex".into(),
        client_version: None,
        started_at: Utc::now(),
        ended_at: Utc::now(),
        usage_by_model: vec![UsageSlice {
            provider_id: "openai".into(),
            model_id: "gpt-5".into(),
            tokens: TokenBreakdown {
                input: tokens,
                ..TokenBreakdown::default()
            },
            cost: Cost::default(),
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

#[test]
fn outbox_replaces_session_with_newer_revision_and_acknowledges_it() {
    let root = std::env::temp_dir().join(format!("metrune-outbox-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let state = LocalState::open(&root.join("state.db")).unwrap();
    state.queue_snapshot(&snapshot(1, 10)).unwrap();
    state.queue_snapshot(&snapshot(2, 20)).unwrap();
    let batch = state.pending_batch(10).unwrap();
    assert_eq!(batch.snapshots.len(), 1);
    assert_eq!(batch.snapshots[0].revision, 2);
    assert_eq!(batch.snapshots[0].total_tokens(), 20);
    state.acknowledge(&batch.snapshots).unwrap();
    assert!(state.pending_batch(10).unwrap().snapshots.is_empty());
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn partial_acknowledgement_quarantines_only_named_rows() {
    let root = std::env::temp_dir().join(format!("metrune-partial-ack-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let state = LocalState::open(&root.join("state.db")).unwrap();
    let first = snapshot(1, 10);
    let mut second = snapshot(1, 20);
    second.session_key = "c".repeat(64);
    state.queue_snapshot(&first).unwrap();
    state.queue_snapshot(&second).unwrap();
    state
        .acknowledge_session_keys(
            &[first.clone(), second.clone()],
            std::slice::from_ref(&first.session_key),
        )
        .unwrap();
    let pending = state.pending_batch(10).unwrap();
    assert_eq!(pending.snapshots.len(), 1);
    assert_eq!(pending.snapshots[0].session_key, second.session_key);
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pending_batch_id_is_stable_until_its_contents_change() {
    let root = std::env::temp_dir().join(format!("metrune-batch-id-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let state = LocalState::open(&root.join("state.db")).unwrap();
    state.queue_snapshot(&snapshot(1, 10)).unwrap();

    let first = state.pending_batch(10).unwrap();
    let retry = state.pending_batch(10).unwrap();
    assert_eq!(
        first.batch_id, retry.batch_id,
        "a retry must preserve the idempotency key"
    );

    state.queue_snapshot(&snapshot(2, 20)).unwrap();
    let revised = state.pending_batch(10).unwrap();
    assert_ne!(
        first.batch_id, revised.batch_id,
        "a revised payload must not reuse the previous idempotency key"
    );

    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_checkpoint_skips_the_same_fingerprint_and_accepts_changes() {
    let root = std::env::temp_dir().join(format!("metrune-checkpoint-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let source = root.join("session.jsonl");
    fs::write(&source, "first").unwrap();
    let state = LocalState::open(&root.join("state.db")).unwrap();

    assert_eq!(state.fingerprint(&source).unwrap(), None);
    state
        .checkpoint(&source, "parser:classifier:file-v1")
        .unwrap();
    assert_eq!(
        state.fingerprint(&source).unwrap().as_deref(),
        Some("parser:classifier:file-v1")
    );
    assert_eq!(
        state.fingerprint(&source).unwrap().as_deref(),
        Some("parser:classifier:file-v1")
    );

    state
        .checkpoint(&source, "parser:classifier:file-v2")
        .unwrap();
    assert_eq!(
        state.fingerprint(&source).unwrap().as_deref(),
        Some("parser:classifier:file-v2")
    );
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn schema_v2_applies_only_to_sessions_starting_after_activation_and_stays_locked() {
    let root = std::env::temp_dir().join(format!("metrune-schema-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let state = LocalState::open(&root.join("state.db")).unwrap();
    let old = state
        .session_schema_version(&"c".repeat(64), Utc::now() - chrono::Duration::minutes(1))
        .unwrap();
    let new = state
        .session_schema_version(&"d".repeat(64), Utc::now() + chrono::Duration::minutes(1))
        .unwrap();
    assert_eq!(old, metrune_core::LEGACY_SCHEMA_VERSION);
    assert_eq!(new, metrune_core::SCHEMA_VERSION);
    assert_eq!(
        state
            .session_schema_version(&"c".repeat(64), Utc::now() + chrono::Duration::minutes(2))
            .unwrap(),
        metrune_core::LEGACY_SCHEMA_VERSION
    );
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn classification_cache_persists_assignments_without_intent_text() {
    let root = std::env::temp_dir().join(format!("metrune-cache-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let state = LocalState::open(&root.join("state.db")).unwrap();
    let assignment = CategoryAssignment {
        category_id: metrune_core::CategoryId::Research,
        confidence: 0.8,
        ..CategoryAssignment::default()
    };
    state
        .cache_classification("opaque-hmac-key", &assignment)
        .unwrap();
    assert_eq!(
        state
            .cached_classification("opaque-hmac-key")
            .unwrap()
            .unwrap(),
        assignment
    );
    assert!(state
        .cached_classification("private intent text")
        .unwrap()
        .is_none());
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn update_checks_are_gated_for_twenty_four_hours_and_survive_reopen() {
    let root = std::env::temp_dir().join(format!("metrune-update-gate-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("state.db");
    let now = Utc::now();
    let interval = chrono::Duration::hours(24);

    {
        let state = LocalState::open(&path).unwrap();
        assert!(state.update_check_due(now, interval).unwrap());
        state.record_update_check(now).unwrap();
        assert!(!state
            .update_check_due(now + chrono::Duration::hours(23), interval)
            .unwrap());
    }

    let reopened = LocalState::open(&path).unwrap();
    assert!(reopened
        .update_check_due(now + chrono::Duration::hours(24), interval)
        .unwrap());
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn update_check_claim_is_atomic_and_revisions_are_monotonic() {
    let root = std::env::temp_dir().join(format!("metrune-claim-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("state.db");
    let now = Utc::now();
    let state = LocalState::open(&path).unwrap();
    let interval = chrono::Duration::hours(24);
    assert!(state.claim_update_check(now, interval).unwrap());
    assert!(!state
        .claim_update_check(now + chrono::Duration::minutes(1), interval)
        .unwrap());
    assert_eq!(state.next_revision(100).unwrap(), 100);
    assert_eq!(state.next_revision(100).unwrap(), 101);
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn state_database_and_sidecars_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("metrune-permissions-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("state.db");
    let state = LocalState::open(&path).unwrap();
    state.queue_snapshot(&snapshot(1, 1)).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    drop(state);
    fs::remove_dir_all(root).unwrap();
}
