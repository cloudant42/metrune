//! Client distribution: the server as an optional mirror in front of the
//! canonical GitHub release.
//!
//! The GitHub release stays the source of truth — it is what CI signs and
//! attests. A deployment that mirrors the binaries only ever serves bytes whose
//! SHA-256 the release manifest already pins, and it relays the manifest's
//! signature untouched, so a workstation that cannot reach GitHub gets the same
//! guarantees as one that can.
//!
//! Everything here is unauthenticated on purpose: a developer has to install
//! the client before they can enroll it, so requiring a credential would be
//! circular. Nothing served is secret — the same bytes are public on GitHub.

use crate::error::ApiError;
use axum::{
    extract::{Path, State},
    http::{
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE},
        HeaderValue,
    },
    response::{IntoResponse, Response},
    Json,
};
use metrune_core::release::{sha256_hex, ArtifactSource, ClientReleaseManifest};
use std::{collections::BTreeMap, env, path::PathBuf};

use crate::app::AppState;

/// A manifest is a few kilobytes; anything larger is a misconfiguration and is
/// refused rather than read into memory.
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

const DEFAULT_DOWNLOAD_DIR: &str = "/usr/share/metrune/downloads";
const MANIFEST_FILE_NAME: &str = "client-manifest.json";

/// Deprecated per-artifact overrides. Kept so deployments written against the
/// original download endpoint keep working; new deployments set one directory.
const LEGACY_PATH_VARS: [(&str, &str); 4] = [
    ("metrune-linux-x86_64", "METRUNE_LINUX_CLIENT_PATH"),
    ("metrune-windows-x86_64.exe", "METRUNE_WINDOWS_CLIENT_PATH"),
    ("metrune-macos-arm64", "METRUNE_MACOS_ARM64_CLIENT_PATH"),
    ("metrune-macos-x86_64", "METRUNE_MACOS_X86_64_CLIENT_PATH"),
];

#[derive(Clone, Debug)]
pub(crate) struct ClientDistribution {
    manifest_path: PathBuf,
    download_dir: PathBuf,
    public_base_url: Option<String>,
    release_public_key: Option<String>,
    legacy_paths: BTreeMap<String, PathBuf>,
}

impl ClientDistribution {
    pub(crate) fn from_env() -> Self {
        let download_dir = PathBuf::from(
            env::var("METRUNE_CLIENT_DOWNLOAD_DIR").unwrap_or_else(|_| DEFAULT_DOWNLOAD_DIR.into()),
        );
        let manifest_path = env::var("METRUNE_CLIENT_MANIFEST_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| download_dir.join(MANIFEST_FILE_NAME));
        let legacy_paths = LEGACY_PATH_VARS
            .iter()
            .filter_map(|(artifact, variable)| {
                env::var(variable)
                    .ok()
                    .map(|path| ((*artifact).to_string(), PathBuf::from(path)))
            })
            .collect();
        Self {
            manifest_path,
            download_dir,
            public_base_url: env::var("METRUNE_PUBLIC_API_URL")
                .ok()
                .map(|value| value.trim_end_matches('/').to_string())
                .filter(|value| !value.is_empty()),
            release_public_key: env::var("METRUNE_RELEASE_PUBKEY")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            legacy_paths,
        }
    }

    /// Read the manifest as published by the release pipeline, then rewrite it
    /// for this deployment: every artifact this server actually holds points at
    /// the mirror, everything else keeps pointing upstream. Signature and
    /// digests are never touched — only the `url` and `source` the client uses
    /// to fetch bytes it will verify anyway.
    async fn manifest(&self) -> Result<ClientReleaseManifest, ApiError> {
        let metadata = tokio::fs::metadata(&self.manifest_path).await.map_err(|_| {
            ApiError::not_found(
                "this server publishes no client release manifest; install from the Metrune release page",
            )
        })?;
        if metadata.len() > MAX_MANIFEST_BYTES {
            tracing::error!(
                path = %self.manifest_path.display(),
                "client release manifest is larger than the allowed size"
            );
            return Err(ApiError::not_found(
                "the client release manifest on this server is not usable",
            ));
        }
        let raw = tokio::fs::read(&self.manifest_path).await.map_err(|error| {
            tracing::error!(error = %error, path = %self.manifest_path.display(), "could not read the client release manifest");
            ApiError::not_found("the client release manifest on this server is not usable")
        })?;
        let mut manifest: ClientReleaseManifest = serde_json::from_slice(&raw).map_err(|error| {
            tracing::error!(error = %error, path = %self.manifest_path.display(), "the client release manifest is not valid JSON");
            ApiError::not_found("the client release manifest on this server is not usable")
        })?;
        manifest.validate().map_err(|error| {
            tracing::error!(error = %error, path = %self.manifest_path.display(), "the client release manifest failed validation");
            ApiError::not_found("the client release manifest on this server is not usable")
        })?;
        for artifact in &mut manifest.artifacts {
            if let (Some(base), true) = (
                self.public_base_url.as_deref(),
                self.mirrored(&artifact.artifact).await,
            ) {
                artifact.url = format!("{base}/v1/downloads/{}", artifact.artifact);
                artifact.source = ArtifactSource::Mirror;
            }
        }
        Ok(manifest)
    }

    fn artifact_path(&self, artifact: &str) -> PathBuf {
        self.legacy_paths
            .get(artifact)
            .cloned()
            .unwrap_or_else(|| self.download_dir.join(artifact))
    }

    async fn mirrored(&self, artifact: &str) -> bool {
        tokio::fs::metadata(self.artifact_path(artifact))
            .await
            .is_ok_and(|metadata| metadata.is_file())
    }
}

pub(crate) async fn client_manifest(State(state): State<AppState>) -> Result<Response, ApiError> {
    let manifest = state.distribution.manifest().await?;
    Ok((
        [(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        )],
        Json(manifest),
    )
        .into_response())
}

/// Serve a mirrored artifact. The manifest is the allow-list, which is both the
/// path-traversal guard and the reason a mirror cannot serve a binary the
/// release does not know about.
pub(crate) async fn download_client(
    State(state): State<AppState>,
    Path(artifact): Path<String>,
) -> Result<Response, ApiError> {
    let manifest = state.distribution.manifest().await?;
    let entry = manifest
        .artifact_named(&artifact)
        .ok_or_else(|| ApiError::not_found("Unknown client artifact"))?;
    let path = state.distribution.artifact_path(&entry.artifact);
    let metadata = tokio::fs::metadata(&path).await.map_err(|_| {
        ApiError::not_found(format!(
            "{} is not mirrored by this server; download it from {}",
            entry.artifact, entry.url
        ))
    })?;
    if !metadata.is_file() {
        return Err(ApiError::not_found("Unknown client artifact"));
    }
    if metadata.len() > MAX_ARTIFACT_BYTES {
        tracing::error!(
            artifact = %entry.artifact,
            path = %path.display(),
            bytes = metadata.len(),
            "mirrored client artifact exceeds the configured size limit"
        );
        return Err(ApiError::payload_too_large(
            "the mirrored client artifact exceeds the configured size limit",
        ));
    }
    let binary = tokio::fs::read(&path).await.map_err(|_| {
        ApiError::not_found(format!(
            "{} is not mirrored by this server; download it from {}",
            entry.artifact, entry.url
        ))
    })?;
    let digest = sha256_hex(&binary);
    if !digest.eq_ignore_ascii_case(&entry.sha256) {
        // The mirror and the release disagree: refuse rather than hand a
        // developer a binary the release never vouched for.
        tracing::error!(
            artifact = %entry.artifact,
            path = %path.display(),
            expected = %entry.sha256,
            actual = %digest,
            "mirrored client artifact does not match the release manifest digest"
        );
        return Err(ApiError::not_found(format!(
            "{} on this server does not match the release manifest; download it from {}",
            entry.artifact, manifest.upstream_base_url
        )));
    }
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", entry.artifact))
            .map_err(|_| ApiError::bad_request("invalid client artifact filename"))?;
    let digest_header = HeaderValue::from_str(&format!("sha-256=:{}:", entry.sha256))
        .map_err(|_| ApiError::bad_request("invalid client artifact digest"))?;
    Ok((
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (CONTENT_DISPOSITION, content_disposition),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                axum::http::header::HeaderName::from_static("repr-digest"),
                digest_header,
            ),
        ],
        binary,
    )
        .into_response())
}

/// A dependency-free installer. The server renders the URLs and digests into
/// the script from the manifest it already holds, so the script needs no JSON
/// parser on the workstation and still verifies what it downloads.
pub(crate) async fn install_script(State(state): State<AppState>) -> Result<Response, ApiError> {
    let manifest = state.distribution.manifest().await?;
    let Some(public_key) = state.distribution.release_public_key.as_deref() else {
        return Err(ApiError::service_unavailable(
            "the server has no release public key configured; the shell installer is disabled",
        ));
    };
    manifest.verify_signature(public_key).map_err(|error| {
        tracing::error!(error = %error, "refusing to render an installer for an untrusted release manifest");
        ApiError::service_unavailable(
            "the server release manifest is not signed by the configured release key",
        )
    })?;
    let script = render_install_script(&manifest);
    Ok((
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
            ),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        script,
    )
        .into_response())
}

fn render_install_script(manifest: &ClientReleaseManifest) -> String {
    let mut cases = String::new();
    for artifact in &manifest.artifacts {
        if artifact.target == "windows-x86_64" {
            continue;
        }
        let (uname_os, uname_arch) = match artifact.target.as_str() {
            "linux-x86_64" => ("Linux", "x86_64"),
            "macos-x86_64" => ("Darwin", "x86_64"),
            "macos-arm64" => ("Darwin", "arm64"),
            _ => continue,
        };
        cases.push_str(&format!(
            "  {uname_os}:{uname_arch}) url={}; sha={} ;;\n",
            shell_quote(&artifact.url),
            shell_quote(&artifact.sha256),
        ));
    }
    format!(
        r#"#!/bin/sh
# Metrune client installer for {version}.
# Downloads the client for this platform and verifies it against the SHA-256
# published in the signed release manifest before installing it.
set -eu

target="${{METRUNE_INSTALL_DIR:-/usr/local/bin}}"
case "$(uname -s):$(uname -m)" in
{cases}  *) echo "metrune: no published client for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "metrune: downloading {version} from $url"
curl -fsSL "$url" -o "$tmp/metrune"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/metrune" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/metrune" | cut -d' ' -f1)"
else
  echo "metrune: no sha256sum or shasum available to verify the download" >&2
  exit 1
fi
if [ "$actual" != "$sha" ]; then
  echo "metrune: checksum mismatch (expected $sha, got $actual)" >&2
  exit 1
fi

chmod +x "$tmp/metrune"
# A stock macOS install has no /usr/local/bin, and `install` will not create the
# destination directory for us.
if [ ! -d "$target" ]; then
  mkdir -p "$target" 2>/dev/null || sudo mkdir -p "$target"
fi
if [ -w "$target" ]; then
  install "$tmp/metrune" "$target/metrune"
else
  sudo install "$tmp/metrune" "$target/metrune"
fi
echo "metrune: installed {version} to $target/metrune"
echo "metrune: enroll it with 'metrune enroll --server <url>' and approve the device in your browser"
"#,
        version = manifest.version,
        cases = cases,
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_download_dir(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "metrune-distribution-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create test download directory");
        path
    }

    fn manifest() -> ClientReleaseManifest {
        let digests = BTreeMap::from([
            ("metrune-linux-x86_64".to_string(), "a".repeat(64)),
            ("metrune-macos-arm64".to_string(), "b".repeat(64)),
            ("metrune-windows-x86_64.exe".to_string(), "c".repeat(64)),
        ]);
        metrune_core::release::upstream_manifest(
            "v0.3.0",
            "v0.2.0",
            "2026-07-28T00:00:00Z",
            "https://github.test/metrune/releases/download/v0.3.0/",
            &digests,
        )
    }

    #[test]
    fn upstream_manifest_points_every_artifact_at_the_release() {
        let manifest = manifest();
        assert_eq!(manifest.artifacts.len(), 3);
        let linux = manifest.artifact_for("linux-x86_64").expect("linux");
        assert_eq!(
            linux.url,
            "https://github.test/metrune/releases/download/v0.3.0/metrune-linux-x86_64"
        );
        assert_eq!(linux.source, ArtifactSource::Upstream);
        assert!(manifest.artifact_for("macos-x86_64").is_none());
    }

    #[test]
    fn install_script_verifies_every_platform_it_offers() {
        let script = render_install_script(&manifest());
        assert!(script.contains("Linux:x86_64)"));
        assert!(script.contains("Darwin:arm64)"));
        // Windows has no shell installer; it must not appear as a case arm.
        assert!(!script.contains("metrune-windows-x86_64.exe"));
        assert!(script.contains("checksum mismatch"));
        assert!(script.contains(&"a".repeat(64)));
    }

    #[test]
    fn install_script_creates_a_missing_destination_directory() {
        // A stock macOS install has no /usr/local/bin, and `install` fails with
        // "No such file or directory" rather than creating it.
        let script = render_install_script(&manifest());
        let create = script
            .find("mkdir -p \"$target\"")
            .expect("the installer must create a missing destination");
        let copy = script
            .find("install \"$tmp/metrune\"")
            .expect("the installer must copy the binary");
        assert!(create < copy, "the destination is created after the copy");
    }

    #[test]
    fn install_script_pins_the_version_it_was_rendered_for() {
        let script = render_install_script(&manifest());
        assert!(script.contains("downloading v0.3.0"));
    }

    #[tokio::test]
    async fn a_mirror_rewrites_only_artifacts_it_actually_holds() {
        let download_dir = temp_download_dir("rewrite");
        let manifest_path = download_dir.join(MANIFEST_FILE_NAME);
        let linux_bytes = b"verified linux client";
        let mut release = manifest();
        release.signature = Some("release-signature".into());
        release
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.target == "linux-x86_64")
            .expect("linux artifact")
            .sha256 = sha256_hex(linux_bytes);
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&release).expect("serialize manifest"),
        )
        .expect("write manifest");
        std::fs::write(download_dir.join("metrune-linux-x86_64"), linux_bytes)
            .expect("write mirrored client");
        let distribution = ClientDistribution {
            manifest_path,
            download_dir: download_dir.clone(),
            public_base_url: Some("https://metrune.example.test".into()),
            release_public_key: None,
            legacy_paths: BTreeMap::new(),
        };

        let rewritten = distribution.manifest().await.expect("read manifest");
        let linux = rewritten.artifact_for("linux-x86_64").expect("linux");
        assert_eq!(linux.source, ArtifactSource::Mirror);
        assert_eq!(
            linux.url,
            "https://metrune.example.test/v1/downloads/metrune-linux-x86_64"
        );
        let mac = rewritten.artifact_for("macos-arm64").expect("mac");
        assert_eq!(mac.source, ArtifactSource::Upstream);
        assert!(mac.url.starts_with("https://github.test/"));
        assert_eq!(rewritten.signature.as_deref(), Some("release-signature"));

        std::fs::remove_dir_all(download_dir).expect("remove test download directory");
    }

    #[tokio::test]
    async fn unusable_manifests_fail_closed_without_leaking_file_errors() {
        for (label, bytes) in [
            ("malformed", b"{not-json".to_vec()),
            ("oversized", vec![b'x'; MAX_MANIFEST_BYTES as usize + 1]),
        ] {
            let download_dir = temp_download_dir(label);
            let manifest_path = download_dir.join(MANIFEST_FILE_NAME);
            std::fs::write(&manifest_path, bytes).expect("write unusable manifest");
            let distribution = ClientDistribution {
                manifest_path,
                download_dir: download_dir.clone(),
                public_base_url: None,
                release_public_key: None,
                legacy_paths: BTreeMap::new(),
            };
            let error = distribution
                .manifest()
                .await
                .expect_err("an unusable manifest must not be served");
            assert_eq!(error.status, axum::http::StatusCode::NOT_FOUND);
            std::fs::remove_dir_all(download_dir).expect("remove test download directory");
        }
    }
}
