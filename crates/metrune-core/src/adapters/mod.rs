mod claude;
mod codex;
mod common;
mod opencode;

pub use claude::ClaudeAdapter;
pub use codex::CodexAdapter;
pub use opencode::OpenCodeAdapter;

use crate::UsageMessage;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub trait SourceAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn discover(&self, home: &Path, extra_roots: &[PathBuf]) -> Result<Vec<PathBuf>>;
    fn parse(&self, source: &Path) -> Result<Vec<UsageMessage>>;
}

pub fn built_in_adapters() -> Vec<Box<dyn SourceAdapter>> {
    vec![
        Box::new(OpenCodeAdapter),
        Box::new(ClaudeAdapter),
        Box::new(CodexAdapter),
    ]
}
