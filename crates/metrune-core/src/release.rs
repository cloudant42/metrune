//! The client release manifest.
//!
//! Distribution is split deliberately: the GitHub release is the canonical,
//! attested artifact store, and a Metrune server is an optional mirror in front
//! of it for networks whose workstations cannot reach GitHub. The manifest is
//! the contract between the two — it names the current and minimum client
//! versions and pins a SHA-256 for every artifact, so a mirror can only serve
//! bytes the release already vouches for.
//!
//! The manifest is signed with the Metrune release key, never with a
//! per-deployment key: a compromised self-hosted server must not be able to
//! hand a backdoored client to its own developers.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Bump when the manifest gains a field a client must understand to stay safe.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Explicit client version sent on requests to a Metrune server.
pub const CLIENT_VERSION_HEADER: &str = "x-metrune-client-version";
/// Stable machine-readable code for a terminal compatibility rejection.
pub const CLIENT_UNSUPPORTED_ERROR_CODE: &str = "client_unsupported";

/// Public server capabilities used by clients before an authenticated upload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub server_version: String,
    pub supported_schema_versions: Vec<String>,
    pub minimum_client_version: Option<String>,
}

/// Body returned with HTTP 426 when a client cannot speak to this server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientUnsupportedResponse {
    pub error: String,
    pub code: String,
    pub minimum_client_version: Option<String>,
}

/// Where a client can fetch an artifact from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactSource {
    /// Served by the Metrune server's own mirror cache.
    Mirror,
    /// Served by the canonical GitHub release.
    Upstream,
}

/// The support tier a platform ships under, carried through from the release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SupportTier {
    Supported,
    Experimental,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseArtifact {
    /// Stable target key, e.g. `linux-x86_64`.
    pub target: String,
    /// Release asset file name, e.g. `metrune-linux-x86_64`.
    pub artifact: String,
    /// Lowercase hex SHA-256 of the artifact bytes.
    pub sha256: String,
    pub tier: SupportTier,
    /// Absolute download URL. The server rewrites this per request; in the
    /// manifest as published by CI it always points at the GitHub release.
    pub url: String,
    /// Whether `url` currently resolves to the mirror or to upstream.
    #[serde(default = "upstream_source")]
    pub source: ArtifactSource,
}

fn upstream_source() -> ArtifactSource {
    ArtifactSource::Upstream
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientReleaseManifest {
    pub schema_version: u32,
    /// The version this manifest publishes, e.g. `0.1.0`.
    pub version: String,
    /// The oldest client version the server still accepts uploads from.
    pub minimum_version: String,
    pub released_at: String,
    /// Canonical release the artifacts came from.
    pub upstream_base_url: String,
    pub artifacts: Vec<ReleaseArtifact>,
    /// Base64 ed25519 signature over the manifest with this field absent.
    /// Set by the release pipeline and relayed untouched by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ClientReleaseManifest {
    pub fn artifact_for(&self, target: &str) -> Option<&ReleaseArtifact> {
        self.artifacts.iter().find(|entry| entry.target == target)
    }

    pub fn artifact_named(&self, artifact: &str) -> Option<&ReleaseArtifact> {
        self.artifacts
            .iter()
            .find(|entry| entry.artifact == artifact)
    }

    /// The exact bytes the signature covers.
    ///
    /// Only the fields a mirror must not be able to change are included: the
    /// versions, and each artifact's name and digest. `url` and `source` are
    /// deliberately outside the signature, because rewriting them to point at a
    /// mirror is exactly what a deployment is allowed to do — and it is safe,
    /// since the client verifies whatever it downloads against the signed
    /// SHA-256 before running it.
    ///
    /// Both signer and verifier build these bytes from the struct rather than
    /// from the transported file, so key order and whitespace cannot affect the
    /// result.
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SignedArtifact<'a> {
            target: &'a str,
            artifact: &'a str,
            sha256: &'a str,
            tier: SupportTier,
        }

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SignedFields<'a> {
            schema_version: u32,
            version: &'a str,
            minimum_version: &'a str,
            released_at: &'a str,
            upstream_base_url: &'a str,
            artifacts: Vec<SignedArtifact<'a>>,
        }

        serde_json::to_vec(&SignedFields {
            schema_version: self.schema_version,
            version: &self.version,
            minimum_version: &self.minimum_version,
            released_at: &self.released_at,
            upstream_base_url: &self.upstream_base_url,
            artifacts: self
                .artifacts
                .iter()
                .map(|artifact| SignedArtifact {
                    target: &artifact.target,
                    artifact: &artifact.artifact,
                    sha256: &artifact.sha256,
                    tier: artifact.tier,
                })
                .collect(),
        })
    }

    /// True when the manifest is newer than `current`. Release tags may carry
    /// a leading `v`; normal semantic-version prerelease ordering applies.
    /// A malformed manifest can never claim to be an upgrade.
    pub fn is_newer_than(&self, current: &str) -> bool {
        compare_versions(&self.version, current).is_some_and(std::cmp::Ordering::is_gt)
    }

    /// True when `current` is older than the minimum this release supports.
    pub fn requires_upgrade(&self, current: &str) -> bool {
        version_is_older(current, &self.minimum_version)
    }
}

/// The artifacts a release publishes, and the tier each platform ships under.
pub const PUBLISHED_TARGETS: [(&str, &str, SupportTier); 4] = [
    (
        "linux-x86_64",
        "metrune-linux-x86_64",
        SupportTier::Supported,
    ),
    (
        "windows-x86_64",
        "metrune-windows-x86_64.exe",
        SupportTier::Experimental,
    ),
    (
        "macos-x86_64",
        "metrune-macos-x86_64",
        SupportTier::Experimental,
    ),
    (
        "macos-arm64",
        "metrune-macos-arm64",
        SupportTier::Experimental,
    ),
];

/// Build the manifest a release publishes, before any server rewrites a URL.
/// `digests` maps an artifact file name to its lowercase hex SHA-256; artifacts
/// missing from it are left out, so a partial matrix publishes a manifest that
/// is honest about what actually built.
pub fn upstream_manifest(
    version: &str,
    minimum_version: &str,
    released_at: &str,
    upstream_base_url: &str,
    digests: &std::collections::BTreeMap<String, String>,
) -> ClientReleaseManifest {
    let base = upstream_base_url.trim_end_matches('/').to_string();
    ClientReleaseManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        version: version.into(),
        minimum_version: minimum_version.into(),
        released_at: released_at.into(),
        upstream_base_url: base.clone(),
        artifacts: PUBLISHED_TARGETS
            .iter()
            .filter_map(|(target, artifact, tier)| {
                digests.get(*artifact).map(|sha256| ReleaseArtifact {
                    target: (*target).into(),
                    artifact: (*artifact).into(),
                    sha256: sha256.to_ascii_lowercase(),
                    tier: *tier,
                    url: format!("{base}/{artifact}"),
                    source: ArtifactSource::Upstream,
                })
            })
            .collect(),
        signature: None,
    }
}

/// Why a manifest could not be trusted. Kept separate from transport errors so
/// callers can refuse to install without having to match on strings.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("the manifest is not signed")]
    Missing,
    #[error("the configured release public key is not valid base64 ed25519")]
    InvalidKey,
    #[error("the manifest signature is not valid base64 ed25519")]
    InvalidSignature,
    #[error("the manifest could not be serialized for verification: {0}")]
    Payload(#[from] serde_json::Error),
    #[error("the manifest signature does not match the Metrune release key")]
    Mismatch,
}

/// Why a release manifest cannot be consumed.  Keep this validation in the
/// shared crate so the API mirror, updater, and release builder all enforce
/// the same fail-closed contract.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported client manifest schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid release version {0:?}")]
    InvalidVersion(String),
    #[error("minimum client version {minimum:?} is newer than release {version:?}")]
    MinimumAfterRelease { minimum: String, version: String },
    #[error("client manifest has no artifacts")]
    EmptyArtifacts,
    #[error("client manifest repeats artifact target {0:?}")]
    DuplicateTarget(String),
    #[error("client manifest repeats artifact name {0:?}")]
    DuplicateArtifact(String),
    #[error("client manifest contains an unknown target {0:?}")]
    UnknownTarget(String),
    #[error("client manifest contains an unsafe artifact name {0:?}")]
    UnsafeArtifact(String),
    #[error("client manifest contains an invalid SHA-256 for {artifact:?}")]
    InvalidDigest { artifact: String },
    #[error("client manifest contains a non-HTTPS artifact URL for {artifact:?}")]
    InsecureUrl { artifact: String },
    #[error("client manifest has an invalid upstream URL")]
    InvalidUpstreamUrl,
    #[error("client manifest has an invalid release timestamp")]
    InvalidReleaseTimestamp,
}

impl ClientReleaseManifest {
    /// Validate transported metadata before using it as a download allowlist.
    /// Partial mirrors are allowed (for example a development image carrying
    /// only Linux), but every entry must be one of the published targets and
    /// must have an unambiguous, HTTPS download URL and full SHA-256 digest.
    /// Loopback HTTP artifact URLs are accepted for local development stacks;
    /// remote mirrors must always use HTTPS.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchema(self.schema_version));
        }
        let version = parsed_version(&self.version)
            .ok_or_else(|| ManifestError::InvalidVersion(self.version.clone()))?;
        let minimum = parsed_version(&self.minimum_version)
            .ok_or_else(|| ManifestError::InvalidVersion(self.minimum_version.clone()))?;
        if minimum > version {
            return Err(ManifestError::MinimumAfterRelease {
                minimum: self.minimum_version.clone(),
                version: self.version.clone(),
            });
        }
        if chrono::DateTime::parse_from_rfc3339(&self.released_at).is_err() {
            return Err(ManifestError::InvalidReleaseTimestamp);
        }
        if !is_https_url(&self.upstream_base_url) {
            return Err(ManifestError::InvalidUpstreamUrl);
        }
        if self.artifacts.is_empty() {
            return Err(ManifestError::EmptyArtifacts);
        }
        let known_targets: HashSet<&str> = PUBLISHED_TARGETS.iter().map(|entry| entry.0).collect();
        let mut targets = HashSet::new();
        let mut artifacts = HashSet::new();
        for entry in &self.artifacts {
            if !known_targets.contains(entry.target.as_str()) {
                return Err(ManifestError::UnknownTarget(entry.target.clone()));
            }
            if !targets.insert(entry.target.as_str()) {
                return Err(ManifestError::DuplicateTarget(entry.target.clone()));
            }
            if !artifacts.insert(entry.artifact.as_str()) {
                return Err(ManifestError::DuplicateArtifact(entry.artifact.clone()));
            }
            if entry.artifact.is_empty()
                || entry.artifact == "."
                || entry.artifact == ".."
                || entry.artifact.contains('/')
                || entry.artifact.contains('\\')
                || entry.artifact.contains('\0')
                || entry.artifact.chars().any(char::is_whitespace)
            {
                return Err(ManifestError::UnsafeArtifact(entry.artifact.clone()));
            }
            if entry.sha256.len() != 64
                || !entry
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ManifestError::InvalidDigest {
                    artifact: entry.artifact.clone(),
                });
            }
            if !is_secure_download_url(&entry.url) {
                return Err(ManifestError::InsecureUrl {
                    artifact: entry.artifact.clone(),
                });
            }
        }
        Ok(())
    }

    /// Sign the manifest with the base64 ed25519 release key. Used by the
    /// release pipeline only; the key never leaves CI and never reaches a
    /// deployment, which is what keeps a mirror unable to mint its own release.
    pub fn sign(&mut self, signing_key_base64: &str) -> Result<(), SignatureError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let key_bytes: [u8; 32] = STANDARD
            .decode(signing_key_base64.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(SignatureError::InvalidKey)?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        self.signature = None;
        let signature = signing_key.sign(&self.signing_payload()?);
        self.signature = Some(STANDARD.encode(signature.to_bytes()));
        Ok(())
    }

    /// The base64 public key matching a base64 ed25519 signing key, so the
    /// pipeline can print the value operators pin in their clients.
    pub fn public_key_for(signing_key_base64: &str) -> Result<String, SignatureError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::SigningKey;

        let key_bytes: [u8; 32] = STANDARD
            .decode(signing_key_base64.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(SignatureError::InvalidKey)?;
        Ok(STANDARD.encode(
            SigningKey::from_bytes(&key_bytes)
                .verifying_key()
                .to_bytes(),
        ))
    }

    /// Verify the manifest against a base64 ed25519 public key. The key belongs
    /// to the release pipeline, so this holds even when the manifest arrived
    /// through a mirror the client does not otherwise trust with code.
    pub fn verify_signature(&self, public_key_base64: &str) -> Result<(), SignatureError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::{Signature, VerifyingKey};

        // The configured key is checked first: a deployment that pinned a
        // malformed key should hear about its own misconfiguration rather than
        // about the manifest it happened to fetch.
        let key_bytes: [u8; 32] = STANDARD
            .decode(public_key_base64.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(SignatureError::InvalidKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| SignatureError::InvalidKey)?;
        let signature = self.signature.as_deref().ok_or(SignatureError::Missing)?;
        let signature_bytes = STANDARD
            .decode(signature.trim())
            .map_err(|_| SignatureError::InvalidSignature)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| SignatureError::InvalidSignature)?;
        verifying_key
            .verify_strict(&self.signing_payload()?, &signature)
            .map_err(|_| SignatureError::Mismatch)
    }
}

fn is_https_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn is_secure_download_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        let has_safe_authority = url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none();
        let local_http = url.scheme() == "http"
            && matches!(
                url.host_str(),
                Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
            );
        has_safe_authority && (url.scheme() == "https" || local_http)
    })
}

/// The build target of the running binary, matching `ReleaseArtifact::target`.
/// Returns `None` on a platform we do not publish, so callers report that
/// rather than downloading something that cannot run.
pub fn current_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("windows", "x86_64") => Some("windows-x86_64"),
        ("macos", "x86_64") => Some("macos-x86_64"),
        ("macos", "aarch64") => Some("macos-arm64"),
        _ => None,
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn parsed_version(version: &str) -> Option<semver::Version> {
    semver::Version::parse(version.trim().trim_start_matches('v')).ok()
}

/// Whether a value is a complete semantic version, optionally prefixed by
/// `v`. Operators use this to fail startup on a misspelled version floor.
pub fn is_valid_version(version: &str) -> bool {
    parsed_version(version).is_some()
}

/// Return the compatibility major for a complete semantic version.
///
/// Metrune's server and client are released independently, but the major
/// number is their wire-compatibility line. Minor releases add features and
/// patches fix or secure an existing line; a different major requires a
/// coordinated compatibility release.
pub fn major_version(version: &str) -> Option<u64> {
    parsed_version(version).map(|parsed| parsed.major)
}

/// Whether two server/client versions belong to the same compatibility line.
pub fn versions_share_major(left: &str, right: &str) -> bool {
    major_version(left).is_some_and(|major| major_version(right) == Some(major))
}

/// Compare two semantic versions. Invalid values do not participate in an
/// ordering, which prevents malformed release metadata from advertising an
/// update.
pub fn compare_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    Some(parsed_version(left)?.cmp(&parsed_version(right)?))
}

/// True when `current` is below `minimum`. An invalid current version is
/// conservatively considered too old; an invalid minimum must be rejected by
/// server configuration validation and therefore does not create a floor.
pub fn version_is_older(current: &str, minimum: &str) -> bool {
    match (parsed_version(current), parsed_version(minimum)) {
        (Some(current), Some(minimum)) => current < minimum,
        (None, Some(_)) => true,
        (_, None) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, minimum: &str) -> ClientReleaseManifest {
        ClientReleaseManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            version: version.into(),
            minimum_version: minimum.into(),
            released_at: "2026-07-28T00:00:00Z".into(),
            upstream_base_url: "https://example.test/download".into(),
            artifacts: vec![ReleaseArtifact {
                target: "linux-x86_64".into(),
                artifact: "metrune-linux-x86_64".into(),
                sha256: "aa".into(),
                tier: SupportTier::Supported,
                url: "https://example.test/download/metrune-linux-x86_64".into(),
                source: ArtifactSource::Upstream,
            }],
            signature: None,
        }
    }

    #[test]
    fn compares_versions_numerically_not_lexically() {
        let release = manifest("v0.10.0", "v0.2.0");
        assert!(release.is_newer_than("0.9.0"));
        assert!(!release.is_newer_than("0.10.0"));
        assert!(!release.is_newer_than("v0.11.0"));
    }

    #[test]
    fn tolerates_a_v_prefix_on_either_side() {
        let release = manifest("v0.3.0", "v0.2.0");
        assert!(release.is_newer_than("v0.2.9"));
        assert!(release.requires_upgrade("0.1.4"));
        assert!(!release.requires_upgrade("v0.2.0"));
    }

    #[test]
    fn compares_prereleases_with_semver_precedence() {
        let release = manifest("v0.2.0", "v0.2.0-beta.2");
        assert!(release.is_newer_than("0.2.0-beta.2"));
        assert!(release.requires_upgrade("0.2.0-beta.1"));
        assert!(!release.requires_upgrade("0.2.0-beta.2"));
        assert!(!release.requires_upgrade("0.2.0"));
    }

    #[test]
    fn version_validation_rejects_partial_or_descriptive_values() {
        assert!(is_valid_version("v1.2.3"));
        assert!(is_valid_version("1.2.3-alpha.1"));
        assert!(!is_valid_version("1.2"));
        assert!(!is_valid_version("latest"));
        assert!(version_is_older("not-a-version", "1.0.0"));
    }

    #[test]
    fn treats_an_unparsable_version_as_oldest() {
        let release = manifest("not-a-version", "v0.2.0");
        assert!(!release.is_newer_than("0.1.0"));
    }

    #[test]
    fn signing_payload_ignores_the_signature_field() {
        let mut release = manifest("v0.3.0", "v0.2.0");
        let unsigned = release.signing_payload().expect("payload");
        release.signature = Some("c2lnbmF0dXJl".into());
        assert_eq!(unsigned, release.signing_payload().expect("payload"));
    }

    #[test]
    fn round_trips_a_signature_and_rejects_a_tampered_manifest() {
        let signing_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
        let public_key =
            ClientReleaseManifest::public_key_for(&signing_key).expect("derive public key");
        let mut release = manifest("v0.3.0", "v0.2.0");
        release.sign(&signing_key).expect("sign");
        release.verify_signature(&public_key).expect("verify");

        // A mirror that swaps a digest invalidates the signature it relayed.
        release.artifacts[0].sha256 = "bb".into();
        assert!(matches!(
            release.verify_signature(&public_key),
            Err(SignatureError::Mismatch)
        ));
    }

    #[test]
    fn a_mirror_may_rewrite_urls_without_breaking_the_signature() {
        // Pointing an artifact at the local mirror is what a deployment is for,
        // and it stays safe because the digest the signature covers is what the
        // client checks the downloaded bytes against.
        let signing_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [9u8; 32]);
        let public_key =
            ClientReleaseManifest::public_key_for(&signing_key).expect("derive public key");
        let mut release = manifest("v0.3.0", "v0.2.0");
        release.sign(&signing_key).expect("sign");
        release.artifacts[0].url = "https://mirror.test/v1/downloads/metrune-linux-x86_64".into();
        release.artifacts[0].source = ArtifactSource::Mirror;
        release.verify_signature(&public_key).expect("verify");
    }

    #[test]
    fn a_mirror_may_not_rewrite_a_digest_or_a_version() {
        let signing_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [11u8; 32]);
        let public_key =
            ClientReleaseManifest::public_key_for(&signing_key).expect("derive public key");
        let signed = {
            let mut release = manifest("v0.3.0", "v0.2.0");
            release.sign(&signing_key).expect("sign");
            release
        };

        let mut tampered = signed.clone();
        tampered.artifacts[0].artifact = "metrune-linux-x86_64-backdoor".into();
        assert!(tampered.verify_signature(&public_key).is_err());

        let mut tampered = signed.clone();
        tampered.minimum_version = "v9.9.9".into();
        assert!(tampered.verify_signature(&public_key).is_err());
    }

    #[test]
    fn refuses_an_unsigned_manifest_and_a_malformed_key() {
        let release = manifest("v0.3.0", "v0.2.0");
        assert!(matches!(
            release.verify_signature("AAAA"),
            Err(SignatureError::InvalidKey)
        ));
        let signing_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [3u8; 32]);
        let public_key =
            ClientReleaseManifest::public_key_for(&signing_key).expect("derive public key");
        assert!(matches!(
            release.verify_signature(&public_key),
            Err(SignatureError::Missing)
        ));
    }

    #[test]
    fn upstream_manifest_only_lists_artifacts_that_built() {
        let digests = std::collections::BTreeMap::from([(
            "metrune-linux-x86_64".to_string(),
            "AB".repeat(32),
        )]);
        let release = upstream_manifest(
            "v0.3.0",
            "v0.2.0",
            "2026-07-28T00:00:00Z",
            "https://github.test/releases/download/v0.3.0/",
            &digests,
        );
        assert_eq!(release.artifacts.len(), 1);
        let linux = release.artifact_for("linux-x86_64").expect("linux");
        assert_eq!(linux.sha256, "ab".repeat(32));
        assert_eq!(
            linux.url,
            "https://github.test/releases/download/v0.3.0/metrune-linux-x86_64"
        );
    }

    #[test]
    fn finds_artifacts_by_target_and_name() {
        let release = manifest("v0.3.0", "v0.2.0");
        assert!(release.artifact_for("linux-x86_64").is_some());
        assert!(release.artifact_for("linux-aarch64").is_none());
        assert!(release.artifact_named("metrune-linux-x86_64").is_some());
    }

    #[test]
    fn validates_transport_and_download_metadata() {
        let mut release = manifest("v0.3.0", "v0.2.0");
        release.artifacts[0].sha256 = "ab".repeat(32);
        release.validate().expect("valid manifest");

        release.artifacts[0].url = "http://mirror.test/client".into();
        assert!(matches!(
            release.validate(),
            Err(ManifestError::InsecureUrl { .. })
        ));

        release.artifacts[0].url = "http://localhost:8080/v1/downloads/client".into();
        release.validate().expect("loopback development URL");
    }

    #[test]
    fn major_versions_define_the_server_client_compatibility_line() {
        assert!(versions_share_major("0.1.0", "0.9.4"));
        assert!(versions_share_major("v1.2.0", "1.0.0"));
        assert!(!versions_share_major("0.1.0", "1.0.0"));
        assert!(!versions_share_major("not-a-version", "0.1.0"));
    }

    #[test]
    fn rejects_duplicate_targets_and_unsafe_artifact_names() {
        let mut release = manifest("v0.3.0", "v0.2.0");
        release.artifacts[0].sha256 = "ab".repeat(32);
        release.artifacts.push(release.artifacts[0].clone());
        assert!(matches!(
            release.validate(),
            Err(ManifestError::DuplicateTarget(_))
        ));
        release.artifacts.truncate(1);
        release.artifacts[0].artifact = "../metrune".into();
        assert!(matches!(
            release.validate(),
            Err(ManifestError::UnsafeArtifact(_))
        ));
    }
}
