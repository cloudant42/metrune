use metrune_core::adapters::{ClaudeAdapter, CodexAdapter, OpenCodeAdapter, SourceAdapter};
use rusqlite::Connection;
use std::fs;
use uuid::Uuid;

fn test_root() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("metrune-adapter-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn parses_claude_and_codex_jsonl_without_persisting_content() {
    let root = test_root();
    let claude_path = root.join("claude.jsonl");
    fs::write(&claude_path, r#"{"id":"m1","session_id":"s1","role":"assistant","model":"claude-sonnet-4-5","provider":"anthropic","timestamp":"2026-07-22T10:00:00Z","usage":{"input_tokens":120,"output_tokens":45},"content":"private implementation detail"}
"#).unwrap();
    let claude = ClaudeAdapter.parse(&claude_path).unwrap();
    assert_eq!(claude.len(), 1);
    assert_eq!(claude[0].tokens.total(), 165);
    assert_eq!(
        claude[0].classification_text.as_deref(),
        Some("private implementation detail")
    );

    let codex_path = root.join("codex.jsonl");
    fs::write(&codex_path, r#"{"type":"event_msg","payload":{"id":"m2","session_id":"s2","role":"assistant","model":"gpt-5","provider":"openai","timestamp":"2026-07-22T11:00:00Z","usage":{"input_tokens":90,"output_tokens":30,"reasoning_tokens":20}}}
"#).unwrap();
    let codex = CodexAdapter.parse(&codex_path).unwrap();
    assert_eq!(codex.len(), 1);
    assert_eq!(codex[0].tokens.total(), 140);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parses_current_codex_token_count_events() {
    let root = test_root();
    let codex_path = root.join("current-codex.jsonl");
    fs::write(
        &codex_path,
        r#"{"type":"session_meta","payload":{"session_id":"s-current","timestamp":"2026-07-22T11:00:00Z","cwd":"/private/project","cli_version":"0.144.5","model_provider":"openai"}}
{"type":"turn_context","payload":{"model":"gpt-5-codex"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"private debugging task"}]}}
{"type":"event_msg","timestamp":"2026-07-22T11:04:00Z","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":19119,"cached_input_tokens":4096,"output_tokens":86,"reasoning_output_tokens":68,"total_tokens":19205}}}}
"#,
    )
    .unwrap();

    let messages = CodexAdapter.parse(&codex_path).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].session_id, "s-current");
    assert_eq!(
        messages[0].project_path.as_deref(),
        Some("/private/project")
    );
    assert_eq!(messages[0].client_version.as_deref(), Some("0.144.5"));
    assert_eq!(messages[0].model_id, "gpt-5-codex");
    assert_eq!(messages[0].tokens.input, 19119);
    assert_eq!(messages[0].tokens.cache_read, 4096);
    assert_eq!(messages[0].tokens.output, 86);
    assert_eq!(messages[0].tokens.reasoning, 68);
    assert_eq!(
        messages[0].classification_text.as_deref(),
        Some("private debugging task")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn codex_without_session_metadata_uses_a_source_stable_fallback() {
    let root = test_root();
    let codex_path = root.join("legacy-codex.jsonl");
    fs::write(
        &codex_path,
        r#"{"type":"event_msg","payload":{"role":"assistant","model":"gpt-5","provider":"openai","timestamp":"2026-07-22T11:00:00Z","usage":{"input_tokens":9,"output_tokens":3}}}
"#,
    )
    .unwrap();

    let messages = CodexAdapter.parse(&codex_path).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].session_id, codex_path.display().to_string());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parses_opencode_sqlite_read_only() {
    let root = test_root();
    let db = root.join("opencode.db");
    let connection = Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE session(id TEXT PRIMARY KEY, directory TEXT);
         CREATE TABLE message(id TEXT PRIMARY KEY, session_id TEXT, data TEXT);
         INSERT INTO session VALUES ('session-1', '/private/project');",
        )
        .unwrap();
    connection.execute(
        "INSERT INTO message VALUES (?1, ?2, ?3)",
        ("message-1", "session-1", r#"{"role":"assistant","modelID":"k3","providerID":"kimi-for-coding","timestamp":"2026-07-22T12:00:00Z","tokens":{"input":200,"output":80,"cache":{"read":40,"write":10}}}"#),
    ).unwrap();
    drop(connection);

    let messages = OpenCodeAdapter.parse(&db).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].session_id, "session-1");
    assert_eq!(messages[0].model_id, "k3");
    assert_eq!(messages[0].provider_id, "kimi-for-coding");
    assert_eq!(
        messages[0].project_path.as_deref(),
        Some("/private/project")
    );
    assert_eq!(messages[0].tokens.total(), 330);
    fs::remove_dir_all(root).unwrap();
}
