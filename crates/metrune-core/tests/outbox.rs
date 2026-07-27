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
