use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

const KEYRING_SERVICE: &str = "metrune";

#[derive(Debug, Default, Serialize, Deserialize)]
struct FallbackCredentials {
    #[serde(default)]
    values: BTreeMap<String, String>,
}

pub struct CredentialStore {
    fallback_path: PathBuf,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self {
            fallback_path: default_fallback_path(),
        }
    }
}

impl CredentialStore {
    pub fn get(&self, credential_id: &str) -> Result<Option<String>> {
        if let Ok(entry) = keyring_entry(credential_id) {
            if let Ok(value) = entry.get_password() {
                return Ok(Some(value));
            }
        }
        Ok(self.read_fallback()?.values.get(credential_id).cloned())
    }

    pub fn set(&self, credential_id: &str, value: &str) -> Result<&'static str> {
        if let Ok(entry) = keyring_entry(credential_id) {
            if entry.set_password(value).is_ok() {
                self.remove_from_fallback(credential_id)?;
                return Ok("system keyring");
            }
        }

        let mut credentials = self.read_fallback()?;
        credentials
            .values
            .insert(credential_id.to_string(), value.to_string());
        self.write_fallback(&credentials)?;
        Ok("0600 fallback file")
    }

    pub fn delete(&self, credential_id: &str) -> Result<()> {
        if let Ok(entry) = keyring_entry(credential_id) {
            let _ = entry.delete_credential();
        }
        self.remove_from_fallback(credential_id)
    }

    fn read_fallback(&self) -> Result<FallbackCredentials> {
        if !self.fallback_path.exists() {
            return Ok(FallbackCredentials::default());
        }
        serde_json::from_slice(&std::fs::read(&self.fallback_path).with_context(|| {
            format!("read credential fallback {}", self.fallback_path.display())
        })?)
        .with_context(|| format!("parse credential fallback {}", self.fallback_path.display()))
    }

    fn write_fallback(&self, credentials: &FallbackCredentials) -> Result<()> {
        if let Some(parent) = self.fallback_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.fallback_path, serde_json::to_vec_pretty(credentials)?)?;
        set_private_permissions(&self.fallback_path)?;
        Ok(())
    }

    fn remove_from_fallback(&self, credential_id: &str) -> Result<()> {
        if !self.fallback_path.exists() {
            return Ok(());
        }
        let mut credentials = self.read_fallback()?;
        if credentials.values.remove(credential_id).is_some() {
            self.write_fallback(&credentials)?;
        }
        Ok(())
    }
}

fn keyring_entry(credential_id: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, &format!("classifier:{credential_id}"))
        .context("create system keyring entry")
}

fn default_fallback_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(path) = env::var_os("APPDATA") {
            return PathBuf::from(path).join("Metrune/credentials.json");
        }
    }

    if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(path).join("metrune/credentials.json");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/metrune/credentials.json")
}

pub(crate) fn set_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
