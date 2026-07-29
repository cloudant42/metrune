# Contributing to Metrune

Metrune is an early-stage self-hosted project. Small, focused pull requests
are welcome, especially when they include tests and documentation for the
operator or privacy impact.

## Development setup

Install Rust stable, Node.js 20+, and Docker Compose. From the repository root:

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

## Before opening a pull request

- Keep raw prompts, source code, outputs, full filesystem paths, and provider
  credentials out of server-bound payloads and fixtures.
- Add or update Rust, web, or contract tests for behavior changes.
- Run `make check` and `git diff --check`.
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
