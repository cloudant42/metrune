use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    use_keyring: bool,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self {
            fallback_path: default_fallback_path(),
            use_keyring: true,
        }
    }
}

impl CredentialStore {
    #[cfg(test)]
    pub(crate) fn for_tests(fallback_path: PathBuf) -> Self {
        Self {
            fallback_path,
            use_keyring: false,
        }
    }

    /// Same as [`Self::for_tests`] but keeps the system keyring enabled, so a
    /// test can prove the native backend is really being used. The fallback
    /// path still points somewhere disposable: if the keyring is unavailable
    /// the store silently writes there instead, and the test asserts on the
    /// returned storage mode to catch exactly that.
    #[cfg(test)]
    pub(crate) fn for_native_keyring_tests(fallback_path: PathBuf) -> Self {
        Self {
            fallback_path,
            use_keyring: true,
        }
    }

    /// Classifier credentials are scoped to the server that provisioned them.
    /// Provider IDs such as `openrouter` are not globally unique, and reusing
    /// one key across two servers can silently send semantic text to the
    /// wrong provider account.
    pub fn get_for_server(&self, server_url: &str, credential_id: &str) -> Result<Option<String>> {
        let scoped = scoped_classifier_id(server_url, credential_id);
        self.get_scoped("classifier", &scoped, &format!("classifier:{scoped}"))
    }

    pub fn set_for_server(
        &self,
        server_url: &str,
        credential_id: &str,
        value: &str,
    ) -> Result<&'static str> {
        let scoped = scoped_classifier_id(server_url, credential_id);
        self.set_scoped(
            "classifier",
            &scoped,
            &format!("classifier:{scoped}"),
            value,
        )
    }

    pub fn delete_for_server(&self, server_url: &str, credential_id: &str) -> Result<()> {
        let scoped = scoped_classifier_id(server_url, credential_id);
        self.delete_scoped("classifier", &scoped, &format!("classifier:{scoped}"))
    }

    pub fn get_installation(&self, credential_id: &str) -> Result<Option<String>> {
        let fallback_key = format!("installation:{credential_id}");
        self.get_scoped("installation", credential_id, &fallback_key)
    }

    pub fn set_installation(&self, credential_id: &str, value: &str) -> Result<&'static str> {
        let fallback_key = format!("installation:{credential_id}");
        self.set_scoped("installation", credential_id, &fallback_key, value)
    }

    pub fn delete_installation(&self, credential_id: &str) -> Result<()> {
        let fallback_key = format!("installation:{credential_id}");
        self.delete_scoped("installation", credential_id, &fallback_key)
    }

    fn get_scoped(
        &self,
        scope: &str,
        credential_id: &str,
        fallback_key: &str,
    ) -> Result<Option<String>> {
        if self.use_keyring {
            if let Ok(entry) = keyring_entry(scope, credential_id) {
                if let Ok(value) = entry.get_password() {
                    return Ok(Some(value));
                }
            }
        }
        Ok(self.read_fallback()?.values.get(fallback_key).cloned())
    }

    fn set_scoped(
        &self,
        scope: &str,
        credential_id: &str,
        fallback_key: &str,
        value: &str,
    ) -> Result<&'static str> {
        if self.use_keyring {
            if let Ok(entry) = keyring_entry(scope, credential_id) {
                if entry.set_password(value).is_ok() {
                    self.remove_from_fallback(fallback_key)?;
                    return Ok("system keyring");
                }
            }
        }

        let mut credentials = self.read_fallback()?;
        credentials
            .values
            .insert(fallback_key.to_string(), value.to_string());
        self.write_fallback(&credentials)?;
        Ok("0600 fallback file")
    }

    fn delete_scoped(&self, scope: &str, credential_id: &str, fallback_key: &str) -> Result<()> {
        if self.use_keyring {
            if let Ok(entry) = keyring_entry(scope, credential_id) {
                let _ = entry.delete_credential();
            }
        }
        self.remove_from_fallback(fallback_key)
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
        let contents = serde_json::to_vec_pretty(credentials)?;
        // Create the file already private. Writing first and chmod-ing after
        // leaves the plaintext credentials readable to every local account for
        // the width of that window.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.fallback_path).with_context(|| {
            format!("open credential fallback {}", self.fallback_path.display())
        })?;
        std::io::Write::write_all(&mut file, &contents)?;
        // An existing file keeps its original mode, so re-assert it.
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

fn keyring_entry(scope: &str, credential_id: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, &format!("{scope}:{credential_id}"))
        .context("create system keyring entry")
}

fn scoped_classifier_id(server_url: &str, credential_id: &str) -> String {
    let normalized = server_url.trim().trim_end_matches('/');
    let digest = Sha256::digest(format!("{normalized}\0{credential_id}").as_bytes());
    format!("{}-{}", credential_id, &hex::encode(digest)[..16])
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "metrune-credentials-{label}-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn fallback_credentials_round_trip_in_a_private_file_and_delete_cleanly() {
        let path = test_path("roundtrip");
        let store = CredentialStore::for_tests(path.clone());
        let credentials = FallbackCredentials {
            values: BTreeMap::from([("provider-key".into(), "super-secret".into())]),
        };

        store
            .write_fallback(&credentials)
            .expect("write fallback credentials");
        assert_eq!(
            store
                .read_fallback()
                .expect("read fallback credentials")
                .values
                .get("provider-key")
                .map(String::as_str),
            Some("super-secret")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("credential metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        store
            .remove_from_fallback("provider-key")
            .expect("delete fallback credential");
        assert!(store
            .read_fallback()
            .expect("read emptied fallback")
            .values
            .is_empty());
        std::fs::remove_file(path).expect("remove test credential file");
    }

    #[test]
    fn malformed_fallback_credentials_fail_closed() {
        let path = test_path("malformed");
        std::fs::write(&path, b"{not-json").expect("write malformed fallback");
        let store = CredentialStore::for_tests(path.clone());
        let error = store
            .read_fallback()
            .expect_err("malformed credentials must not look empty");
        assert!(format!("{error:#}").contains("parse credential fallback"));
        std::fs::remove_file(path).expect("remove malformed fallback");
    }

    #[test]
    fn installation_and_classifier_fallback_keys_cannot_collide() {
        let path = test_path("scopes");
        let store = CredentialStore::for_tests(path.clone());
        let mut credentials = FallbackCredentials::default();
        credentials
            .values
            .insert("shared-id".into(), "classifier-secret".into());
        credentials.values.insert(
            "installation:shared-id".into(),
            "installation-secret".into(),
        );
        store
            .write_fallback(&credentials)
            .expect("write scoped credentials");
        assert_eq!(
            store
                .read_fallback()
                .expect("read scoped credentials")
                .values
                .get("shared-id")
                .map(String::as_str),
            Some("classifier-secret")
        );
        assert_eq!(
            store
                .read_fallback()
                .expect("read scoped credentials")
                .values
                .get("installation:shared-id")
                .map(String::as_str),
            Some("installation-secret")
        );
        std::fs::remove_file(path).expect("remove scoped fallback");
    }

    #[test]
    fn classifier_credentials_are_isolated_per_server() {
        let path = test_path("server-scope");
        let store = CredentialStore::for_tests(path.clone());
        store
            .set_for_server("https://one.example/", "openrouter", "one-secret")
            .expect("store first server credential");
        store
            .set_for_server("https://two.example", "openrouter", "two-secret")
            .expect("store second server credential");
        assert_eq!(
            store
                .get_for_server("https://one.example", "openrouter")
                .expect("read first server credential")
                .as_deref(),
            Some("one-secret")
        );
        assert_eq!(
            store
                .get_for_server("https://two.example/", "openrouter")
                .expect("read second server credential")
                .as_deref(),
            Some("two-secret")
        );
        store
            .delete_for_server("https://one.example", "openrouter")
            .expect("delete first server credential");
        assert!(store
            .get_for_server("https://one.example", "openrouter")
            .expect("read deleted credential")
            .is_none());
        assert!(store
            .get_for_server("https://two.example", "openrouter")
            .expect("read retained credential")
            .is_some());
        std::fs::remove_file(path).expect("remove server-scoped fallback");
    }

    /// Removes the keyring entry even when an assertion unwinds, so a failing
    /// run cannot leave a credential behind in a developer's login keychain.
    struct KeyringGuard {
        credential_id: String,
        fallback_path: PathBuf,
    }

    impl Drop for KeyringGuard {
        fn drop(&mut self) {
            if let Ok(entry) = keyring_entry("installation", &self.credential_id) {
                let _ = entry.delete_credential();
            }
            // The store writes here if the keyring turns out to be unavailable,
            // which is precisely the case this test is asserting against.
            let _ = std::fs::remove_file(&self.fallback_path);
        }
    }

    /// Proves the client really stores installation tokens in the operating
    /// system's credential store, rather than quietly degrading to the
    /// fallback file. `docs/RELEASING.md` makes this a release gate for the
    /// macOS and Windows clients.
    ///
    /// Ignored by default: it writes to the real login keychain, and CI images
    /// without a secret service (Linux) would legitimately fall back. Run it on
    /// a native runner with `cargo test -p metrune --ignored native_keyring`.
    #[test]
    #[ignore = "requires a real OS credential store; run on a native macOS or Windows runner"]
    fn an_installation_token_round_trips_through_the_native_keyring() {
        let path = test_path("native-keyring");
        let store = CredentialStore::for_native_keyring_tests(path.clone());
        let credential_id = format!(
            "e2e-native-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after the epoch")
                .as_nanos()
        );
        let _guard = KeyringGuard {
            credential_id: credential_id.clone(),
            fallback_path: path.clone(),
        };
        let token = "mti_native_keyring_probe";

        let storage = store
            .set_installation(&credential_id, token)
            .expect("store the installation token");
        assert_eq!(
            storage, "system keyring",
            "the native credential store was unavailable, so the token fell back to a file"
        );
        assert!(
            !path.exists(),
            "a keyring write must not also leave the token in the fallback file"
        );

        assert_eq!(
            store
                .get_installation(&credential_id)
                .expect("read the installation token")
                .as_deref(),
            Some(token)
        );

        store
            .delete_installation(&credential_id)
            .expect("delete the installation token");
        // Read straight through the backend: `get_installation` would report
        // `None` for a fallback miss even if the keyring entry survived, and
        // `delete_scoped` ignores keyring deletion errors.
        let entry = keyring_entry("installation", &credential_id)
            .expect("open the keyring entry after deletion");
        assert!(
            entry.get_password().is_err(),
            "the credential is still present in the native keyring after deletion"
        );
    }
}
