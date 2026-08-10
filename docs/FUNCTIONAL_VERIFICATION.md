# Functional verification report

Full-system verification was rerun on 2026-08-09 from the active working tree,
including client/server compatibility, version telemetry, analytics, web,
security, browser, SSO, and recovery gates.

## Result

- Rust: 214 tests passed (`25` CLI, `133` API, `30` core, `11` adapter,
  `3` contract, `9` outbox, and `3` pricing tests), with one native-keyring test
  intentionally reserved for macOS/Windows release runners. The API suite also
  passed against fresh PostgreSQL 17 and ClickHouse 24.8 containers.
- The current tree adds targeted normal tests for viewer session scope,
  manual invitations and SMTP-less password-reset refusal, classifier/scan CLI
  parsing, and nested Claude usage, plus an ignored native-keyring round-trip
  gate. The complete release gate passed with those additions.
- Compatibility: semantic-version ordering, the 24-hour SQLite gate, explicit
  CLI version headers, unauthenticated server information, typed 426 rejection,
  same-major server/client enforcement, terminal CLI instructions, retained
  outbox behavior, migration 017, and both installation API version fields
  passed focused unit and live integration tests. The independent stable
  release contract is documented in `docs/VERSIONING.md` and validated by the
  namespaced release-tag checks.
- Browser (full run 2026-08-09): 10 Playwright scenarios passed across freshly
  built password-mode and OIDC deployments. The same E2E gate installed the
  server-distributed Linux client and completed a real non-empty enrollment,
  scan, upload, update, and revocation lifecycle.
- `scripts/test-e2e.sh` now also supports macOS and builds the client from the
  checkout there; that host path was not part of the dated browser run.
- Web: ESLint, TypeScript, Next production build, and all 45 generated Next
  routes passed.
- Packaging: release Rust workspace build, API image, web image, development
  Compose, production Compose, and a destructive backup/restore drill passed.
- Security: cargo-audit, cargo-deny, production npm audit, actionlint, offline
  zizmor, Trivy filesystem scan, and Trivy scans of both runtime images passed.
- Product, runtime-rendering, and verification-infrastructure defects were
  found and fixed. They are listed below.

`Verified` means the behavior was executed. `Covered` means a lower-level
contract was executed but a real third-party service or platform was not
available. `Not executed` identifies an explicit remaining external boundary.

## Native client lifecycle verdict

| Question | Verified current behavior | Gap |
|---|---|---|
| Enrollment and upload authentication | `metrune enroll` uses a 10-minute OAuth device grant by default. The browser authenticates through OIDC when configured, confirms the code, machine, workspace, and team, and a concurrent one-time exchange mints the revocable `mti_…` installation bearer used for upload and classifier requests. The CLI never receives the user's web or IdP token. | The installation credential is long-lived until revoked; automatic expiry/rotation is not implemented. |
| Real upload and persistence | A controlled Codex fixture queued a metadata-only snapshot, survived an unavailable server, uploaded to ClickHouse, replaced its prior revision without double-counting, and remained queued after installation revocation. Raw session ID, path, and prompt were absent from export and API results. | Sustained daemon operation and distributed/load behavior remain unexecuted. |
| Default managed semantics | Managed server routing exists, keeps the provider secret in the vault, and was executed against a loopback provider with a real installation token. Normal usage upload remains metadata-only; model outputs are never sent for classification. | The configured/database default is still local/private, not managed. Managed-mode disclosure/consent is still a deployment responsibility. |
| Private semantics | Direct Ollama/custom OpenAI-compatible providers and a developer-supplied `METRUNE_CLASSIFIER_API_KEY` work. The organization may also provision a direct-use key to the client. | A broad organization key provisioned to every client has a larger blast radius; prefer developer BYOK/local inference, managed routing, or a future short-lived installation-scoped provider token. |
| Native updates | `upload` and `watch` check at most once per 24 hours and only print a notice; `METRUNE_NO_UPDATE_CHECK=1` opts out. The server publishes its version/schema/floor, persists reported client versions, and returns terminal structured 426 responses below the floor. `metrune update --check`, target selection, signed-manifest and digest validation, server mirror download, and atomic binary replacement are covered. | No published tag/release exists, and the source API image contains only an unsigned Linux development manifest. Updates are intentionally never installed automatically. |

## Client and core coverage matrix

| Functionality | Tests or executed verification | Status |
|---|---|---|
| Privacy-safe upload schema; no prompts, responses, paths, commands, raw user IDs, or local classification text | `tests/contracts.rs`; adapter fixture tests; Trivy secret scan | Verified |
| Stable pseudonymous session identity | `session_identity_is_stable_across_installation_identity_keys`; adapter fallback identity tests | Verified |
| Claude Code adapter | `parses_claude_and_codex_jsonl_without_persisting_content`; nested usage under the Claude `message` object | Verified with fixtures |
| Codex adapter, current token events, cumulative deltas, counter resets, missing metadata | `tests/adapters.rs` Codex cases | Verified with fixtures |
| OpenCode SQLite adapter | `parses_opencode_sqlite_read_only` | Verified with fixture database |
| Copilot OTEL adapter, discovery, deduplication, missing IDs, zero-token spans, prompt exclusion | `tests/adapters.rs` and `adapters::copilot::tests` | Verified with fixtures |
| Session aggregation, ordered model transitions, conservative rules, taxonomy, unknown category | CLI unit tests; taxonomy unit tests | Verified |
| Local semantic classification | classifier parse/schema/usage tests plus loopback HTTP provider tests | Verified |
| Structured-output fallback | `auto_mode_falls_back_when_a_provider_rejects_structured_output` | Verified |
| Invalid provider JSON repair | `invalid_provider_json_gets_one_bounded_repair_attempt` | Verified |
| Partial batch retry | `a_partial_batch_falls_back_only_for_missing_assignments` | Verified |
| Provider 503 and bounded retry behavior | `upstream_failures_are_reported_without_an_unbounded_retry` | Verified |
| Provider timeout | `a_stalled_provider_is_bounded_by_the_http_timeout` | Verified |
| Classification cache excludes semantic text | `classification_cache_persists_assignments_without_intent_text` | Verified |
| Versioned custom/default/organization pricing precedence | `tests/pricing.rs`; API price lifecycle test | Verified |
| SQLite outbox replacement, acknowledgement, stable batch id, retry retention | `tests/outbox.rs`; real non-empty E2E upload, failed endpoint, revision replacement, and revoked-token retention | Verified |
| Source checkpoints and schema-v2 activation persistence | `tests/outbox.rs` | Verified |
| 24-hour update-check persistence across restart | `update_checks_are_gated_for_twenty_four_hours_and_survive_reopen` | Verified |
| Release manifest signing, verification, version ordering, target selection, tamper rejection | `release::tests`; release build command | Verified |
| Client mirror URL rewrite without invalidating signatures or digests | core release and API distribution tests | Verified |
| Atomic updater replacement | `updater_stages_and_atomically_replaces_the_existing_binary`; server-mirrored artifact checksum in E2E | Verified locally |
| Installation/classifier keyring scopes, fallback permissions, migration, round trip, deletion, malformed-file fail-closed behavior | `credentials::tests`; `legacy_installation_tokens_migrate_out_of_config_without_losing_access`; CLI E2E; ignored native-keyring round-trip test in the release workflow | Fallback verified; native keyring is a release gate, not part of the dated run |

Real Claude, Codex, OpenCode, and Copilot user stores were intentionally not
read. The parsers were executed against controlled fixtures so verification
could prove that private content is discarded without inspecting or queuing
the operator's own sessions.

## CLI coverage matrix

| Command | Behavior exercised | Status |
|---|---|---|
| `metrune enroll` | Real device authorization, local and OIDC-backed browser approval, CLI polling, installation exchange, config without a bearer secret, protected credential storage, classifier selection; legacy `--token` compatibility | Verified E2E |
| `metrune scan` | Adapter fixtures, unknown client, no-classify path, checkpoint and outbox behavior; `--force` parsing and checkpoint bypass path | Verified with targeted coverage; full force-rescan E2E not rerun |
| `metrune export` | Empty and non-empty sanitized envelopes, stable pending batch ID, schema/privacy contracts | Verified |
| `metrune upload` | Non-empty live upload, connection failure retention, retry/idempotency, revision replacement, revoked-token retention, version header, typed 426 parsing, and update-notice decision | Verified E2E and unit |
| `metrune watch` / `daemon` | CLI alias, scan/upload primitives, server-profile refresh selection, 24-hour update gate, opt-out, and terminal compatibility-error branch | Covered; sustained process and signal handling not executed |
| `metrune status` | Real enrolled config, queue state, secret redaction | Verified E2E |
| `metrune classifier provision` | Disabled live configuration; local and managed API provisioning; credential redaction | Verified |
| `metrune classifier configure` | Changes classifier configuration without re-enrollment | Covered by targeted CLI parsing; live provider execution not rerun |
| `metrune classifier status` | Disabled live state and non-secret output | Verified E2E |
| `metrune classifier logout` | Credential-store deletion primitive | Covered; not run against a desktop keyring service |
| `metrune pricing sync-openrouter` | Catalog conversion and merge primitives | Covered; live OpenRouter catalog not requested without credentials/network contract |
| `metrune update --check` / install | Real server manifest/artifact download and checksum, signature/version/default-server contracts, atomic replacement helper | Covered; self-replacement from a canonical signed release not executed |
| hidden `metrune release manifest` | Release build generated a real manifest from SHA256SUMS | Verified |
| `--help`, every subcommand help, and `--version` | Release binary invocation | Verified |

Default `METRUNE_CONFIG`, `METRUNE_STATE_DB`, XDG/Linux, `APPDATA`/Windows,
pricebook and project-label environment paths, plus project alias, team, user
alias, server, pseudonym, and classifier config/flag paths were inspected.
False environment paths formerly shown in `.env.example` were removed. Linux
config/state paths were executed. Windows path selection is compile-covered but
was not executed on Windows.

## API coverage matrix

The Axum router exposes 59 distinct paths and 69 method handlers.

| Path and methods | Primary coverage | Status |
|---|---|---|
| `GET /v1/healthz`, `GET /v1/readyz` | authorization integration test; Compose readiness; E2E and restore drill | Verified |
| `GET /v1/server/info` | unauthenticated version/schema/floor contract and cache policy | Verified |
| `GET /v1/downloads/{artifact}` | mirror file selection/path tests; image contains Linux client | Covered; no Windows/macOS artifact available locally |
| `GET /v1/client/manifest` | malformed/oversized manifest fail closed; partial mirror rewrite; release signing tests | Verified at handler/store boundary |
| `GET /v1/client/install.sh` | platform checksum coverage and pinned-version tests | Covered; clean-host signed installer execution remains required |
| `GET /v1/auth/methods` | local/SSO mode, provider label, fail-closed web rendering | Verified |
| `GET /v1/auth/sso/start` | real discovery authorization URL, state hashing, PKCE S256, nonce, scope, safe continuation, cache policy and rate limit | Verified |
| `GET /v1/auth/sso/callback` | signed-token success; issuer/audience/expiry/nonce/email validation; `client_secret_basic`/`client_secret_post`; replay race; state expiry; PKCE tamper; denial, 503 and timeout; JWKS refresh; JIT modes and identity conflict | Verified with real HTTP/RSA provider |
| `POST /v1/auth/login` | valid, wrong, unknown, case-insensitive, rate-limited, disabled under OIDC, authentication-mode session isolation, and expired/revoked-session tests; browser E2E | Verified |
| `POST /v1/auth/logout` | revoked-session integration test; browser E2E | Verified |
| `GET /v1/auth/me` | authenticated session and web page/proxy E2E | Verified |
| `POST /v1/auth/organization` | membership-scoped switch test; workspace page/proxy E2E | Verified |
| `POST /v1/auth/invitations/inspect` | masked address; invalid/expired/revoked indistinguishability; browser missing-token case | Verified |
| `POST /v1/auth/invitations/accept` | local password and SSO-passwordless new accounts, existing accounts, authorization, concurrent single use, first OIDC binding | Verified |
| `POST /v1/auth/password-reset/request` | local unknown-account masking, SMTP-unavailable response, browser generic response; unavailable under OIDC | Verified |
| `POST /v1/auth/password-reset/complete` | local single use, password change, existing-session revocation, invalid token UI; unavailable under OIDC | Verified |
| `POST /v1/organizations` | creator becomes admin; bounded names; cross-workspace isolation | Verified |
| `POST /v1/enroll` | legacy token tenant binding, validation, and concurrent one-winner behavior | Verified |
| `POST /v1/oauth/device/authorization` | public-client validation, name/platform bounds, high-entropy code generation, hashed persistence, expiry, no-store response, live CLI E2E | Verified |
| `POST /v1/oauth/device/verification` | user-session and active-workspace authorization, human-code normalization, invalid/expired states, browser proxy/UI | Verified |
| `POST /v1/oauth/device/approval` | explicit approve/deny, same-workspace team validation, owner/workspace binding, audit event, browser E2E | Verified |
| `POST /v1/oauth/token` | pending, slow-down, denial, expiry, wrong client/grant, transient retry behavior, concurrent one-winner exchange, consumed-code rejection | Verified |
| `POST /v1/installation/classifier/provision` | local/managed material rules, encrypted credential lifecycle, restore drill decryption | Verified |
| `POST /v1/installation/classifier/classify` | text bounds; forged-token rejection; server-held provider authorization; installation/provider credential non-disclosure; provider success/failure/timeout | Verified with loopback provider |
| `POST /v1/installation/classifier/classify-batch` | item and byte bounds, partial retry/parser/provider tests | Covered with loopback provider |
| `GET/POST /v1/org/members` | role authorization, tenant listings, member/invitation flows | Verified |
| `PATCH/DELETE /v1/org/members/{user_id}` | foreign-org rejection, last-admin protection, removal revokes installations | Verified |
| `POST /v1/org/members/{user_id}/password-reset` | admin-only, organization-scoped, SMTP-required account-owner delivery, no-mailer refusal without token creation, and cross-tenant rejection | Verified except real SMTP delivery |
| `GET/POST /v1/org/invitations` | lifecycle, masking, manual `201`/`delivery: "manual"`/fragment `acceptUrl` without a mailer, SMTP behavior, role authorization | Verified |
| `POST /v1/org/invitations/{id}/resend` | lifecycle authorization, token rotation, manual accept-link response without a mailer, and external-mail failure behavior | Covered; real delivery not executed |
| `DELETE /v1/org/invitations/{id}` | revoked token indistinguishability and authorization | Verified |
| `GET/POST /v1/org/teams` | lifecycle, validation, audit effects, browser creation | Verified |
| `PATCH/DELETE /v1/org/teams/{id}` | rename/delete lifecycle and cross-tenant no-side-effect regression | Verified |
| `GET /v1/org/installations` | tenant-only listing, persisted client version telemetry, and web admin rendering | Verified |
| `PATCH /v1/org/installations/{id}` | assignment lifecycle and foreign-org rejection | Verified |
| `GET/PATCH /v1/org/settings` | persistence, 1–3650 day bounds, tenant scope | Verified |
| `GET/PATCH /v1/org/classifier` | local/managed settings, endpoint policy, credential linkage, browser rendering | Verified |
| `POST /v1/org/classifier/test` | provider mock success/fallback/repair/failure/timeout behavior | Covered; no paid external call |
| `GET/POST /v1/org/credentials` | encrypt, redact, rotate, version, provision, audit | Verified |
| `DELETE /v1/org/credentials/{credential_id}` | revoke and provisioning denial | Verified |
| `POST /v1/org/vault/recovery` | local password confirmation, recent OIDC-session confirmation, stale-session rejection, per-organization key separation, restore drill | Verified |
| `GET/POST /v1/org/prices` | default and organization catalog, validation, service-token restriction | Verified |
| `PATCH/DELETE /v1/org/prices/{id}` | version/update/retire lifecycle and tenant scope | Verified |
| `GET /v1/me/installations` | ownership-only listing, client version telemetry, and profile browser rendering | Verified |
| `DELETE /v1/me/installations/{id}` | owner success and foreign-owner denial | Verified |
| `POST /v1/me/enrollment-codes` | legacy automation boundary, rate limit, and concurrent one-winner enrollment | Verified |
| `POST /v1/ingest/sessions` | live ClickHouse insert, typed schema/client-floor 426 rejection, version persistence, raw-ID rejection, retryable partial batch, idempotent replay, revision replacement, revoked token, real CLI E2E | Verified |
| `GET /v1/analytics/overview` | live tenant-only aggregate, filters, restore drill | Verified |
| `GET /v1/analytics/timeseries` | live analytics tests and overview/browser rendering | Verified |
| `GET /v1/analytics/breakdowns` | all browser dimensions and live scoped-filter tests | Verified |
| `GET /v1/analytics/category-model` | live analytics queries and Models browser page | Verified |
| `GET /v1/analytics/workflow-model` | turn attribution queries and Models browser page | Verified |
| `GET /v1/analytics/classification-overhead` | separate classifier usage query and Models browser page | Verified |
| `GET /v1/analytics/sessions` | tenant scope, facets, filters, sorting/pagination bounds, viewer restriction | Verified |
| `GET /v1/analytics/sessions/{session_key}` | access control and unavailable-session browser boundary | Verified |
| `GET /v1/analytics/facets` | tenant-scoped facet integration test and browser filter rendering | Verified |
| `GET /v1/me/usage` | caller-owned installations only and profile browser rendering | Verified |
| `GET /v1/me/sessions` | caller-owned installation filters and Sessions browser rendering | Verified |

All protected paths were also exercised for missing, malformed, invented,
expired, revoked, disabled-account, wrong-role, wrong-organization, and
service-token credentials. HTTP middleware tests cover request-ID propagation,
404 versus 405, gzip decompression, malformed JSON, and the 10 MiB body limit.
Rate-limit tests cover exact boundaries, independent keys/scopes, disabled
budgets, reopened windows, successful-login reset, and trusted-proxy handling.

## Browser and Next proxy coverage

Fourteen user pages exist:

- `/`, `/usage` (all eight dimensions), `/models`, `/sessions`,
  `/sessions/[sessionKey]`, `/profile`, `/organizations`, `/admin`, and
  `/admin/pricing` were rendered against the real API.
- `/login`, `/forgot-password`, `/reset-password`, and `/accept-invite` were
  exercised for success or safe invalid/missing-credential states.
- The isolated SSO browser stack follows the real provider redirects, PKCE
  callback and host-only cookie, verifies password UI/recovery are absent,
  renders enforcement status, and approves a native client.
- `/device` was exercised for signed-in inspection, matching-code display,
  explicit approval, issued installation visibility, and login/workspace
  continuation behavior.
- Team create/rename/delete, device-enrollment command preparation, logout,
  protected redirect, and absence of client-side page exceptions were
  exercised.
- Server/client timezone differences were exercised in the production build;
  displayed dates now hydrate deterministically and timestamps identify UTC.
- API failures now render an unavailable state instead of placeholder
  organization data. Anonymous page requests receive a `307` to `/login`, and
  anonymous `/api/*` requests receive `401` JSON, so no response carries
  organization data without a session.
- Administration and pricing pages fail closed for missing or insufficient
  roles. Session drilldown and export are organization-wide for an analyst or
  admin and scoped to the caller's own sessions otherwise. Exports use
  `metrune-sessions.csv` for the organization view and
  `metrune-my-sessions.csv` for the personal view; they preserve filters,
  return explicit errors when live data is unavailable, set `no-store`, and
  neutralize spreadsheet formula prefixes.
- Login, SSO, and workspace continuation paths are checked by the shared
  same-origin-relative navigation validator; profile download URLs are
  normalized and restricted to HTTP(S).

All `web/app/api/**/route.ts` proxy routes compile in the production build.
Their shared cookie forwarding and error behavior is exercised through login,
logout, recovery, organization selection, teams, enrollment, analytics,
pricing reads, and profile flows. Mutation semantics behind the less frequently
used organization-control-plane and authorization routes are covered by the
SQL-backed integration suite and targeted concurrency tests.

## Background and persistence coverage

| Process or state | Verification | Status |
|---|---|---|
| Hourly identity-record reaper | Extracted reaper operation deletes only sessions, invitations, resets, and device grants beyond their retention windows | Verified operation; hour-long scheduler wait not executed |
| CLI watch/daemon loop | Command compatibility, scan/classify/queue/upload primitives, and server-profile refresh selection | Covered; sustained process timing/signals not executed |
| PostgreSQL startup migrations | Fresh Compose startup and repeat integration setup | Verified |
| ClickHouse schema compatibility, deduplicated revisions and TTL retention stamps | Live integration tests and restore drill | Verified; multi-day TTL merge timing not executed |
| Default price import/repricing | Startup and live price queries | Verified |
| Legacy vault credential rewrap | success, undecryptable-row preservation, idempotent rerun | Verified |
| SQLite outbox/cache/checkpoints/update gate | file-backed tests across reopen, acknowledgement, and 24-hour notice gating | Verified |
| Backup and restore | PostgreSQL custom dump, ClickHouse Native export, vault key, volume destruction and full restore | Verified |

## Integrations and configuration

| Integration/configuration | Verification | Status |
|---|---|---|
| PostgreSQL 17 | all migrations and live control-plane tests | Verified |
| ClickHouse 24.8 | live ingestion/analytics and destructive restore | Verified |
| Development Compose | clean build/start/readiness/web/CLI/browser E2E | Verified in the dated Linux run |
| Production Compose | rendered invariants, four-service topology, loopback binds, secrets and non-root checks | Verified |
| SMTP STARTTLS/TLS | complete/partial/invalid config, fail-closed production behavior, generic public failures | Covered; no relay credentials, so delivery not executed |
| OpenID Connect | real HTTP discovery/authorization/JWKS/token exchange, RSA verification, browser redirect/cookie E2E, device approval and upload | Verified against deterministic providers; operator IdP federation remains external |
| OpenAI-compatible classifier/OpenRouter | loopback HTTP success, fallback, repair, retry, 503 and timeout | Covered; no paid/live provider request |
| OpenRouter pricing catalog | parser and catalog precedence | Covered; live catalog sync not executed |
| Desktop keyring | private fallback file behavior; native round-trip release gate | Fallback covered; native secret-service/keychain execution is a release-workflow gate |
| GitHub releases | signed manifest/checksum/update contracts and release workflows; remote tag read | Covered; remote had no tags, local `gh` credential was invalid, and connector access could not inspect secrets/variables |
| HTTPS reverse proxy/DNS | production configuration validation | Not executed; no production hostname/certificate |
| Linux x86_64 client/server | release build and Compose runtime | Verified |
| Windows/macOS clients | workflow/action syntax and target selection; macOS E2E checkout-build path | Not executed in the dated run; Windows runners and a macOS release E2E gate remain unavailable |

Production configuration rejects insecure bootstrap credentials, non-HTTPS
public URLs, incomplete/plaintext SMTP, insecure remote classifier endpoints,
and an absent/unusable vault key when encrypted credentials exist. Development
defaults, host-port overrides, client mirror paths, trusted proxy headers,
rate-limit budgets, TTLs, classifier mode/provider/endpoint/model/credential,
bootstrap identity, database connections, and download paths were inspected.

## Tests added in this verification

- Compatibility tests cover semantic-version prereleases, server information,
  below-floor and unsupported-schema 426 bodies, terminal CLI instructions,
  request version headers, update notice precedence/opt-out, a persistent
  24-hour gate, migration 017, and version telemetry in both installation APIs.
- Four device-authorization integration tests covering success, denial, expiry,
  invalid inputs, active-workspace authorization, cross-tenant teams, hashed
  persistence, polling pace, cache policy, and concurrent one-time exchange.
- Three device-code generation/normalization/URL unit tests and two CLI parsing
  and OAuth-error regressions.
- Five loopback classifier tests for structured fallback, repair, partial
  batches, upstream failure, and timeout.
- Two fallback credential-store persistence/permission/fail-closed tests.
- Targeted regressions cover viewer session scope, manual invitation and
  SMTP-less password-reset refusal, `classifier configure`, `scan --force`,
  and nested Claude usage; the ignored native-keyring round-trip test is a
  separate release gate.
- Protected installation-credential scoping and transparent legacy-config
  migration tests.
- OIDC configuration tests for partial setup, production secret policy,
  hostname/cookie topology, bounds, and safe continuations.
- Seven live OIDC integration scenarios covering cryptographic validation,
  replay/concurrency, PKCE/state expiry, key rotation, provider failures and
  timeouts, identity/provisioning, invitation/reset/recovery policy, device
  approval, and installation upload.
- A Playwright enterprise-SSO scenario backed by an isolated signed OIDC
  provider and real API/web/database processes.
- Invitation, password-reset, SMTP-unavailable, concurrency, and reaper
  lifecycle tests.
- Five team/installation, credential/classifier, pricing, retention, and
  concurrent enrollment control-plane tests.
- Three HTTP boundary tests for request IDs/routing, gzip, JSON, and body size.
- Four rate-limit/proxy-trust boundary tests.
- Distribution tests for partial mirrors and malformed/oversized manifests.
- Mail configuration and email-normalization tests.
- A cross-tenant team-delete no-side-effect regression assertion.
- Three Playwright scenarios covering public identity, authentication,
  dashboard pages, administration, browser device approval, and logout.
- Stable pending-batch identity and retryable partial-ingest regressions.
- A managed-routing integration test proving that the installation
  authenticates to Metrune while only the server authenticates to the provider.
- Atomic updater replacement and server-profile watch-refresh regressions.
- A real CLI lifecycle in the Compose E2E: server artifact download, device
  authorization and signed-in approval, private fixture scan, non-empty upload,
  unavailable-server retry, revision replacement, analytics visibility, and
  revocation.

## Failures found and fixed

1. A fresh Compose database ran SQL migrations twice: once through
   `/docker-entrypoint-initdb.d` and once through SQLx. Migration 014 then
   failed on a duplicate constraint. The API is now the sole migration owner,
   and the production-Compose checker rejects reintroducing the mount.
2. Deleting another organization's team returned 404 but first cleared that
   team's installation assignments. The handler now locks and validates the
   organization-owned team in a transaction before any scoped mutation.
3. The SMTP-unavailable test counted all reset tokens globally and raced
   parallel tests. It now scopes its assertion to its unique identity.
4. Deterministic identity fixture tokens collided across repeated live runs.
   Fixtures retain the required token shape but are unique.
5. Playwright required an unnecessary ffmpeg binary because video was enabled.
   Video is disabled; traces and failure screenshots remain.
6. Next's route announcer made broad ARIA selectors ambiguous. Assertions now
   target the intended visible message and scoped table.
7. E2E and restore scripts retained local images and temporary backup
   directories. Both now remove their own images, volumes, and temporary data.
8. Dependabot had no update cooldown. Cargo, npm, and Actions updates now wait
   seven days and are capped at one grouped pull request per ecosystem;
   CI/security push runs are limited to `main`, and releases are dispatch-only,
   so publishing a generated release tag does not duplicate the full matrices.
   Current actionlint and offline zizmor report no findings.
9. The web runtime used the full, end-of-life Node 20 image. Trivy found
   hundreds of fixed high/critical OS and package-manager findings. Build,
   runtime, CI, and documented prerequisites now use Node 24; the final runtime
   is slim and removes unused npm/Corepack/Yarn. The rebuilt image has zero
   high/critical Trivy findings.
10. The CLI generated a random upload batch ID on every read of the same
    pending outbox. A lost response therefore defeated server idempotency.
    Batch IDs are now a deterministic digest of the exact ordered snapshots and
    change only when the pending payload changes.
11. The API recorded a partially rejected batch as complete. Retrying the same
    stable ID then returned duplicates for the accepted and rejected rows and
    could cause the CLI to acknowledge rejected data. Only fully accepted
    batches are now recorded as complete; partial batches remain retryable.
12. `watch` inferred whether a classifier was server-provisioned from its
    provider ID, so organization-managed custom providers were not refreshed.
    It now uses the profile's client/server configuration-version origin and
    covers custom providers in both execution modes.
13. Production-rendered installation dates used the server timezone while
    React hydrated them in the browser timezone, causing visible hydration
    errors. Shared formatters now use deterministic UTC output.
14. Native enrollment required manually copying a bearer-like one-time code
    from the profile and had no OAuth authorization grant. Enrollment now uses
    a browser-approved device grant and returns only an installation credential
    to the CLI; the legacy token path remains for controlled automation.
15. The first browser regression used an unscoped exact-text selector after an
    approved client correctly appeared in both the filter and client table.
    The assertion now targets the client table, and the complete E2E was rerun.
16. SSO was documented but not implemented. The API now performs OIDC
    discovery/code flow and verified identity binding; the web app exposes only
    the active authentication method, and the existing device grant inherits
    the resulting session.
17. A password session minted before enabling SSO would otherwise remain valid
    for its original lifetime. Authorization now requires the deployment's
    current session method on every request, and startup revokes sessions from
    the previous mode.
18. Installation credentials were serialized in ordinary client config.
    Enrollment now stores them in the OS keyring or a private fallback store,
    and existing configs migrate without losing access.
19. The new host-run browser SSO harness initially started ClickHouse without
    its database/schema. It now applies the same checked-in migrations as the
    product Compose entrypoint before starting the API.
20. The OIDC/device/upload integration scenario tried to prove service-token
    continuity through a nonexistent `/v1/admin/settings` route. It now calls
    the real `/v1/org/settings` contract; the focused scenario and complete
    live suite pass.
21. The SSO browser harness passed `multiquery=1` to ClickHouse's HTTP API,
    which ClickHouse 24.8 rejects as an unknown setting. It now applies every
    migration through `clickhouse-client --multiquery`, reports each filename,
    and passes both focused and combined E2E gates.
22. The RustSec workflow assumed `rsa` was never compiled. OIDC correctly adds
    it for public-key ID-token verification, making that assertion stale.
    The exception now fails unless the only reverse dependency is
    `rsa -> openidconnect -> metrune-api` and production OIDC code remains free
    of private-key APIs.

## Remaining risks and explicitly unexecuted behavior

- No real SMTP message was delivered. The no-mailer invitation response is
  covered; a controlled relay account is still required to verify DNS,
  authentication, TLS policy, spam handling, and inbox links.
- No real OpenRouter/OpenAI-compatible paid endpoint was called. Deterministic
  loopback tests cover its protocol and failure contract without leaking text
  or credentials.
- No canonical signed release was published or self-installed, and the dated
  run did not execute the macOS E2E path or Windows runners. The remote had no
  tags, so the manually dispatched workflow had not yet run for this repository.
- The OIDC protocol path is verified with deterministic signed providers, not a
  real Entra ID, Okta, Keycloak, or customer federation policy. Redirect URI,
  claims, conditional access, administrator recovery, and key rotation must be
  validated with each supported operator IdP. Logout revokes the Metrune
  session but does not initiate provider logout. Per-organization providers,
  group mapping, SCIM, and native SAML are not implemented.
- SSO-only administrators have no local password. Disabling OIDC restores local
  mode but does not create one; an automated host-controlled break-glass setter
  remains future hardening.
- The installation credential is revocable, distinct from user OAuth tokens,
  and protected by the OS keyring or mode-`0600` fallback, but remains
  long-lived. Automatic expiry and rotation remain future hardening. A real
  desktop keyring service was unavailable on this host; its API path is
  compile-covered and fallback behavior was executed.
- Managed classification is implemented but is not the default; database and
  development configuration still default to local/private execution.
- Update notices are best-effort and intentionally never install anything.
  Operators must explicitly set the server floor after inspecting fleet
  telemetry. The API source image's unsigned `0.0.0-source` Linux manifest is
  suitable for development but is rejected by clients that pin a release key.
- The watch daemon was not left running for hours, and ClickHouse TTL deletion
  was not observed across multi-day retention/merge intervals.
- The restore drill does not cover a managed backup provider, external vault
  retrieval, multi-partition ClickHouse history, DNS/TLS cutover, or an
  organization-specific recovery-time objective.
- Concurrency tests target the security-critical one-time token path. They are
  not a load, soak, or distributed multi-node test; the supported beta topology
  remains one host.
- Zizmor ran its complete offline rule set. Online audits that query GitHub
  were not available without a repository token.
- `npm audit --audit-level=high` and the production-only variant both report
  zero vulnerabilities. The production standalone dependency scan and both
  runtime-image scans were also clean; development tooling is not shipped.
- NOTICE generation completed against the final installed dependency tree.
- The web fail-closed, role, export, and continuation hardening added on
  2026-08-01 passed lint, TypeScript, production build, and the full browser
  matrix against freshly built password-mode and OIDC stacks.

## Exact commands executed

Core gates and inventory:

```bash
make check
cargo test --workspace -- --list
make test-integration
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test --workspace
cargo build --release --workspace
target/release/metrune --version
target/release/metrune --help
target/release/metrune <command> --help
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
git ls-remote --tags origin
```

Web and end-to-end:

```bash
cd web && npm ci
cd web && npm run lint
cd web && npm run typecheck
cd web && npm run build
cd web && npm audit --audit-level=high
cd web && npm audit --audit-level=high --omit=dev
make test-e2e
make test-sso-e2e
bash scripts/test-e2e.sh
bash scripts/test-sso-e2e.sh
```

Deployment, recovery, and scripts:

```bash
docker compose config --quiet
bash scripts/check-production-compose.sh
docker compose build api web
bash scripts/restore-drill.sh
bash -n scripts/*.sh
python3 -m py_compile scripts/*.py
python3 scripts/check-cla.py --list
python3 scripts/check-cla.py cloudant42
python3 scripts/generate-notices.py --output /tmp/metrune-NOTICE.verify
```

Rust and dependency security:

```bash
cargo deny check licenses sources bans
cargo audit
cargo tree --workspace --target all --invert rsa
```

Workflow security:

```bash
curl -fsSL -o actionlint.bash https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash
bash actionlint.bash
./actionlint -color /home/flo/Workspace/private/metrune/.github/workflows/*.yml
python3 -m venv <temporary-directory>
<temporary-directory>/bin/pip install --disable-pip-version-check zizmor
zizmor --persona regular --min-severity low .github/workflows
```

Trivy was installed only in a temporary directory by its release installer,
which selected v0.72.0. The scanner cache and both temporary image tags were
removed after these equivalent CI scans:

```bash
trivy fs --cache-dir <temporary-directory>/cache --scanners vuln,secret,misconfig --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 .
docker build -f crates/metrune-api/Dockerfile -t metrune-api:security .
docker build -f web/Dockerfile -t metrune-web:security .
trivy image --cache-dir <temporary-directory>/cache --scanners vuln,secret,misconfig --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 metrune-api:security
trivy image --cache-dir <temporary-directory>/cache --scanners vuln,secret,misconfig --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 metrune-web:security
```

Focused regressions were also rerun by package/module:

```bash
cargo test -p metrune-core classifier::tests -- --nocapture
cargo test -p metrune-core --test outbox -- --nocapture
cargo test -p metrune --bin metrune credentials::tests -- --nocapture
cargo test -p metrune updater_stages_and_atomically_replaces_the_existing_binary -- --nocapture
cargo test -p metrune watch_refreshes_server_profiles_regardless_of_provider_or_execution_mode -- --nocapture
cargo test -p metrune-api --lib
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::oidc:: -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::device_auth -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::identity_lifecycle::the_identity_reaper_deletes_only_records_past_their_retention_window -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::analytics::a_snapshot_with_raw_identifiers_is_rejected_without_failing_the_batch -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::control_plane::managed_classification_routes_bounded_text_with_a_server_held_credential -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::identity_lifecycle -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::control_plane -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::http_contract -- --nocapture
METRUNE_TEST_DATABASE_URL=<test-postgres> METRUNE_TEST_CLICKHOUSE_URL=<test-clickhouse> cargo test -p metrune-api testing::tenancy::an_admin_cannot_mutate_a_team_belonging_to_another_organization -- --nocapture
```

Generated verification assets and the reproducible dashboard dependency tree
were then removed with the exact repository paths below. `npm ci` restores
`web/node_modules`. The E2E script separately ran Compose
`down -v --rmi local --remove-orphans` for its unique project; shared Docker
build cache and unrelated development containers/images were intentionally
left alone.

```bash
make integration-down
rm -rf /home/flo/Workspace/private/metrune/target /home/flo/Workspace/private/metrune/web/.next /home/flo/Workspace/private/metrune/web/test-results /home/flo/Workspace/private/metrune/web/playwright-report /home/flo/Workspace/private/metrune/scripts/__pycache__ /home/flo/Workspace/private/metrune/.playwright-mcp
rm -rf /home/flo/Workspace/private/metrune/web/node_modules
```
