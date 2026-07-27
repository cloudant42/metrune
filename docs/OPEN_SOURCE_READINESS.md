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

- [ ] Split development and production Compose configuration.
- [ ] Make production startup fail when development passwords, tokens, or
      seeded development identities are still configured.
- [ ] Document and enforce the external TLS/reverse-proxy boundary.
- [ ] Add request IDs, sensitive-header redaction, and a documented logging
      policy.
- [ ] Add global request-body and batch-size limits, field-length validation,
      execution timeouts, and rate limits for login, enrollment, provisioning,
      ingestion, and expensive analytics queries.
- [ ] Complete a dependency, container-image, and GitHub Actions security scan.
- [ ] Review authorization for every organization, team, installation, pricing,
      credential, vault, and export operation.

### Data protection and operations

- [ ] Document PostgreSQL, ClickHouse, and vault-key backup procedures.
- [ ] Test a complete restore, including the vault master key and encrypted
      classifier credentials.
- [ ] Document retention, deletion, export, and disaster-recovery behavior.
- [ ] Separate schema migrations from normal application startup where an
      operator-controlled migration job is required.
- [ ] Version ClickHouse schema changes consistently with PostgreSQL migrations.
- [ ] Document upgrade ordering, rollback limits, and recovery from a failed
      migration.
- [ ] Add production Helm values for resources, security contexts, persistence,
      disruption budgets, and secret management.
- [ ] Add operational alerts for readiness failures, ingestion failures, stale
      installations, outbox growth, ClickHouse lag, and vault-key errors.

### Release and supply chain

- [ ] Publish versioned API and web container images.
- [ ] Publish client checksums and signed release artifacts.
- [ ] Generate SBOMs and build provenance for binaries and images.
- [ ] Pin production container images by immutable digest.
- [ ] Add a release manifest containing supported platforms and client versions.
- [ ] Add a clean-install test from a fresh checkout.
- [ ] Test upgrades from at least the previous schema and client protocol
      versions.
- [ ] Define a supported-version and deprecation policy for clients and APIs.

### Community and legal readiness

- [ ] Add `CONTRIBUTING.md` with development setup, checks, and pull-request
      expectations.
- [ ] Add `SECURITY.md` with a private vulnerability-reporting path and response
      expectations.
- [ ] Add a code of conduct and issue templates.
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
```

Then verify a clean Compose startup, enrollment, scan, upload, dashboard login,
retention behavior, client download, backup/restore, and an upgrade from the
previous release candidate.
