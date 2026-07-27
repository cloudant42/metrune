# Open-source readiness checklist

Metrune is currently a development-stage, self-hosted project. This checklist
records what is already present, what must be completed before a public
production-oriented release, and what belongs to the enterprise roadmap.

## Current foundations

- [x] Apache-2.0 license is present.
- [x] Client uploads contain sanitized usage metadata rather than prompts,
      source code, outputs, raw session IDs, or full filesystem paths.
- [x] Local classification can use a local or company-approved endpoint without
      routing classification text through the Metrune API.
- [x] Installation, enrollment, and dashboard tokens are stored hashed at rest.
- [x] Provider credentials use an authenticated encrypted vault and protected
      client-side storage.
- [x] Organization-scoped analytics, owner-scoped profile analytics, retention,
      installation revocation, and basic audit events exist.
- [x] Rust tests, web typechecking/build, Compose configuration validation, and
      GitHub CI are available.
- [x] Docker Compose and a Helm deployment baseline are included.
- [x] Linux, Windows, Intel macOS, and Apple Silicon macOS client release
      builds are defined.

## Before calling the project open-source production-ready

### Security and safe defaults

- [x] Split development and production Compose configuration and require
      production credentials through an override env file.
- [x] Make API production startup require an HTTPS public URL and reject known
      development database/bootstrap credentials.
- [x] Make the production deployment fail closed when development tokens or
      seeded identities are still configured.
- [ ] Document and enforce the external TLS/reverse-proxy boundary.
- [x] Add request IDs, keep sensitive headers out of HTTP traces, and document
      the logging policy and TLS boundary.
- [x] Add a global request-body limit, ingestion batch ceiling, request timeout,
      and login-attempt throttle.
- [x] Add per-identity/IP rate limits for enrollment, provisioning, ingestion,
      and expensive analytics queries.
- [x] Complete a dependency, container-image, and GitHub Actions security scan.
- [x] Review authorization for every organization, team, installation, pricing,
      credential, vault, and export operation.

### Data protection and operations

- [x] Document PostgreSQL, ClickHouse, and vault-key backup procedures.
- [x] Test a complete restore, including the vault master key and encrypted
      classifier credentials.
- [x] Document retention, deletion, export, and disaster-recovery behavior.
- [ ] Separate schema migrations from normal application startup where an
      operator-controlled migration job is required.
- [ ] Version ClickHouse schema changes consistently with PostgreSQL migrations.
- [x] Document upgrade ordering, rollback limits, and recovery from a failed
      migration.
- [ ] Add production Helm values for persistence and disruption budgets.
- [x] Add production Helm values for resource requests, security contexts, and
      explicit vault-key Secret management.
- [ ] Add operational alerts for readiness failures, ingestion failures, stale
      installations, outbox growth, ClickHouse lag, and vault-key errors.

### Release and supply chain

- [x] Publish versioned API and web container images.
- [ ] Publish client checksums and signed release artifacts.
- [ ] Generate SBOMs and build provenance for binaries and images. Images carry
      both; client binaries still have provenance only.
- [ ] Pin production container images by immutable digest.
- [x] Add a release manifest containing supported platforms and client versions.
- [ ] Add a clean-install test from a fresh checkout.
- [ ] Test upgrades from at least the previous schema and client protocol
      versions.
- [ ] Define a supported-version and deprecation policy for clients and APIs.

### Community and legal readiness

- [x] Add `CONTRIBUTING.md` with development setup, checks, and pull-request
      expectations.
- [x] Add `SECURITY.md` with a private vulnerability-reporting path and response
      expectations.
- [x] Add a code of conduct, pull-request template, and issue templates.
- [ ] Document third-party licenses and release-artifact notices.
- [ ] Document the privacy model, employee-monitoring implications, retention,
      and the organization operator's responsibilities.
- [ ] Add a public troubleshooting guide and a sanitized diagnostic procedure.
- [ ] State clearly which adapters, operating systems, databases, and deployment
      modes are supported.

## Enterprise roadmap

These features are not required for the first development snapshot, but they
should be completed before presenting Metrune as enterprise-ready:

- [ ] OIDC/SSO with Entra ID, Okta, Keycloak, and Google Workspace.
- [ ] Group-claim role and team mapping.
- [ ] SCIM provisioning for joiner, mover, and leaver workflows.
- [ ] User invitations, role management, password reset, and session/device
      revocation.
- [ ] Team-level authorization rather than organization-wide aggregate access
      for every signed-in member.
- [ ] Audit-log browsing and export with durable actor user IDs.
- [ ] Installation token rotation and fleet-wide client version inventory.
- [ ] Signed client update manifests with stable, canary, and pinned channels.
- [ ] Enterprise-controlled server upgrades with maintenance windows and
      emergency security-release procedures.

## Product roadmap after release hardening

- [ ] Cost budgets, alerts, and anomaly detection.
- [ ] Reclassification and taxonomy migration workflows.
- [ ] Privacy-preserving user and organization data export/deletion flows.
- [ ] Prometheus/webhook integrations for operational reporting.
- [ ] OpenAPI documentation and a versioned public API contract.
- [ ] Additional coding-agent adapters based on real user demand.

## Update policy

Security updates should not be manual-only. The recommended enterprise model is
automated dependency detection, signed builds, staged deployment, production
approval, and an emergency path for actively exploited vulnerabilities.

- **Server and web:** build and scan automatically, deploy to development first,
  require production approval, and keep rollback/migration instructions with
  each release.
- **Client:** publish signed artifacts and a signed version manifest. Individual
  users may use an update command, while enterprises should deploy through their
  normal endpoint-management or internal package distribution system.
- **Compatibility:** advertise the latest and minimum supported client versions,
  preserve the local outbox during upgrades, and allow a defined grace period
  before enforcing a minimum version.
- **Dependencies:** use automated security-update pull requests and scheduled
  rebuilds for Rust, npm, base images, and GitHub Actions.

Useful references:

- [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [OWASP API4: Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [Sigstore artifact verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [Kubernetes image digests](https://kubernetes.io/docs/concepts/containers/images/)

## Release gate

Before a public release candidate, all of the following should pass from a
clean checkout:

```bash
make check
git diff --check
docker compose config --quiet
./scripts/restore-drill.sh
```

The `Security scans` workflow must also be green: it covers Rust and npm
dependencies, the built API and web images, repository configuration, and the
GitHub Actions workflows themselves.

Then verify a clean Compose startup, enrollment, scan, upload, dashboard login,
retention behavior, client download, and an upgrade from the previous release
candidate. `scripts/restore-drill.sh` covers the backup/restore path,
including the vault master key and encrypted classifier credentials; see
[OPERATIONS.md](OPERATIONS.md#recovery-drill) for what it does not cover.

The reviewed per-endpoint authorization rules are recorded in
[AUTHORIZATION.md](AUTHORIZATION.md), which also lists the accepted limits of
the current model.
