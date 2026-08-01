# Contributing to Metrune

Metrune is an early-stage self-hosted project. Small, focused pull requests
are welcome, especially when they include tests and documentation for the
operator or privacy impact.

## Development setup

Install Rust stable, Node.js 24+, and Docker Compose. From the repository root:

```bash
cargo test --workspace
cd web && npm ci && cd ..
make check
```

The local Compose stack uses development-only credentials and must not be
exposed to a network. See the local workflow in the README and the
[security and logging boundary](docs/SECURITY_AND_LOGGING.md).

### HTTP integration tests

The API's authorization rules are SQL predicates, so they are verified against
a real Postgres and ClickHouse rather than a mock:

```bash
make test-integration
```

That starts throwaway containers, points `METRUNE_TEST_DATABASE_URL` and
`METRUNE_TEST_CLICKHOUSE_URL` at them, runs the full workspace suite, and tears
them down. Plain `cargo test --workspace` still passes without Docker — the
tests that need a database report that they were skipped.

When you add a route, add it to the table in
`crates/metrune-api/src/testing/authorization.rs` so it is covered by the
unauthenticated and forged-token sweeps.

## Sign the CLA

Metrune uses an Individual Contributor License Agreement. You sign it once, and
it covers every contribution you make afterwards.

Add yourself to `signatures/cla.json` in your first pull request:

```json
{
  "githubUsername": "your-github-username",
  "name": "Your Full Name",
  "signedAt": "2026-07-29",
  "claVersion": "1.0"
}
```

That entry, in a commit authored by you, is your signature on [CLA.md](CLA.md).
It lives in this repository's history rather than with a third-party service.
CI checks it; you can check first with:

```bash
scripts/check-cla.py your-github-username
```

You will not be asked again on later pull requests.

### What you are agreeing to

You keep the copyright in your work, and you can still use it anywhere else —
the licence you grant is non-exclusive. What you grant the maintainer is the
right to distribute your contribution, including under commercial terms
alongside the open source project.

In exchange, section 7 of the CLA is a binding commitment in the other
direction: your contribution will remain available under Apache-2.0, or another
OSI-approved licence, for as long as it is distributed at all. It can be
included in a paid edition. It cannot be taken out of the open source project.

That asymmetry is real and worth understanding before you contribute. The
commitment in section 7 exists so the trade is explicit rather than implied.

## Before opening a pull request

- Keep raw prompts, source code, outputs, full filesystem paths, and provider
  credentials out of server-bound payloads and fixtures.
- Add or update Rust, web, or contract tests for behavior changes.
- Sign the CLA in your first pull request; see the CLA section above. A CI job
  checks it — there is no third-party bot involved.
- Run `make check` and `git diff --check`.
- For anything larger than a bug fix, open an issue first so we can agree on
  the approach before you spend time on it.
- When changing an endpoint's role requirement or organization scoping, update
  the matrix in [docs/AUTHORIZATION.md](docs/AUTHORIZATION.md).
- When changing backup, migration, or vault-key handling, run
  `./scripts/restore-drill.sh`.
- Update the relevant documentation, changelog, and roadmap item.
- Do not commit `.env` files, credentials, database dumps, generated builds,
  or local browser artifacts.

## Pull requests

Describe the user-visible change, affected deployment or privacy boundary,
validation performed, and any migration or rollback considerations. Keep
unrelated cleanup out of the same pull request. Maintainers may ask for a
focused follow-up when a change needs operational or security review.
