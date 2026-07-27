# Release procedure

Metrune is not yet at a stable production release. This procedure describes
the current client release automation and the checks still required before
calling a release supported.

## Client release

1. Update the version and changelog in a focused pull request.
2. Run `make check`, `git diff --check`, and the clean-install test.
3. Review migration ordering, rollback limits, supported client versions, and
   the production Compose/Helm configuration.
4. Create and push an annotated `vX.Y.Z` tag from the reviewed commit.
5. GitHub Actions builds Linux x86_64, Windows x86_64, Intel macOS, and Apple
   Silicon macOS artifacts.
6. The workflow publishes `SHA256SUMS` and `RELEASE_MANIFEST.txt` alongside the
   binaries and creates GitHub build-provenance attestations.
7. Verify the downloaded checksums and attestations from a clean machine before
   distributing artifacts.

The current workflow does not yet sign binaries with a maintainer-controlled
release key. That remains a release blocker for a production-oriented release.

## Server images

`.github/workflows/release-server.yml` publishes the API and web images. It
runs on every `v*` tag, and can be dispatched manually with an explicit
version.

For each component it builds from the tagged commit, pushes
`ghcr.io/<owner>/<repo>-<component>:<version>`, generates an SBOM and build
provenance, scans the pushed image with Trivy and fails on HIGH or CRITICAL
findings, and attests the provenance to the registry. A final job collects the
per-component digests into `SERVER_IMAGE_MANIFEST.txt` and attaches it to the
GitHub release.

No `latest` tag is published. Deployments pin an immutable digest, and a moving
tag makes a rollback ambiguous.

Before rollout, pin the published digests:

```yaml
# deploy/helm/metrune/values.yaml
api:
  image: ghcr.io/<owner>/<repo>-api@sha256:<digest>
web:
  image: ghcr.io/<owner>/<repo>-web@sha256:<digest>
```

Verify the attestation from a clean machine before deploying:

```bash
gh attestation verify \
  oci://ghcr.io/<owner>/<repo>-api@sha256:<digest> \
  --repo <owner>/<repo>
```

## Server release

Build API and web images from the same reviewed commit, scan the images, pin
the deployed image digests, and back up PostgreSQL, ClickHouse, and the vault
key before rollout. Run one migration-capable API instance first, verify
`/v1/readyz`, then scale the service. Keep the previous image and backups
available until the upgrade and rollback window closes.

Run `./scripts/restore-drill.sh` before a release candidate so the backups the
rollout depends on are known to restore. See
[OPERATIONS.md](OPERATIONS.md#recovery-drill).

## Client compatibility

The client preserves its local outbox while the server is unavailable. Before
enforcing a minimum client version, publish the supported-version window and
allow enough time for endpoint-management systems to distribute the update.
Emergency security releases may shorten that window when the vulnerability is
actively exploited.
