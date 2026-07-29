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

## Sign your commits (DCO)

Metrune uses the [Developer Certificate of Origin](https://developercertificate.org/),
the same lightweight mechanism as the Linux kernel and Kubernetes. There is no
form to sign and no account to create: you certify the
[DCO](DCO.txt) by adding a `Signed-off-by` line to each commit.

```bash
git commit -s -m "Your message"
```

That appends a trailer built from your git identity:

```
Signed-off-by: Your Name <you@example.com>
```

By adding it you are certifying that you wrote the change, or that you have the
right to submit it under Apache-2.0. The sign-off must match the commit author,
and every commit in a pull request needs one. CI enforces this.

Forgot? Nothing is lost:

```bash
git commit --amend -s --no-edit     # the most recent commit
git rebase --signoff origin/main    # every commit on your branch
```

Then force-push the branch. To check before you open the pull request:

```bash
scripts/check-dco.sh origin/main..HEAD
```

Merge commits and commits authored by bots are exempt.

### What this does and does not mean

Your contribution is licensed under Apache-2.0, the same license as the rest of
the project — Apache-2.0 section 5 places inbound contributions under the
project's own terms, including its patent grant. The DCO transfers no
copyright, and it does not give the maintainers the right to relicense your
contribution. Metrune's core is Apache-2.0 and is intended to stay that way.

## Before opening a pull request

- Keep raw prompts, source code, outputs, full filesystem paths, and provider
  credentials out of server-bound payloads and fixtures.
- Add or update Rust, web, or contract tests for behavior changes.
- Sign off every commit (`git commit -s`); see the DCO section above.
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
