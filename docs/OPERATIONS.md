# Operations guide

This is the minimum backup, restore, retention, and upgrade procedure for the
single-host production-beta deployment. Adapt storage commands to the
operator's encrypted backup platform.

## Critical state

Back up all three of these independently:

1. PostgreSQL, which contains organizations, users, tokens, installations,
   settings, audit events, pricing, and encrypted provider credentials.
2. ClickHouse, which contains usage snapshots and their retention metadata.
3. The vault master key at `METRUNE_SECRETS_KEY_FILE` (the Compose default is
   `/var/lib/metrune/secrets/master.key`).

The PostgreSQL backup and vault key are a matched pair. Without the exact vault
key, encrypted provider credentials cannot be recovered from PostgreSQL. Store
the key in a separate access-controlled secret backup and never commit or log
it.

## PostgreSQL backup

For the development Compose stack, create a custom-format dump while the API
is not performing schema changes:

```bash
mkdir -p backups
docker compose exec -T postgres \
  pg_dump -U metrune -d metrune --format=custom \
  > backups/metrune-postgres.dump
```

For production, use the organization's managed PostgreSQL backup or equivalent
encrypted `pg_dump`/WAL procedure. Verify that the dump can be read from a
separate operator account and that its retention matches the recovery
objective.

## ClickHouse backup

Use ClickHouse-native backup or the storage provider's consistent volume
snapshot facility. A filesystem copy of a live ClickHouse data directory is
not a sufficient backup. Quiesce ingestion, record the ClickHouse server
version, create the backup, and verify that the backup contains both
`session_snapshots` and `session_snapshots_dedup`.

If using Docker volumes, identify the exact volume with `docker volume inspect`
and snapshot it with the storage platform. Do not assume that a volume name is
the same across Compose project names.

## Vault key backup

Copy the master key through an access-controlled channel and restrict the
backup to the deployment recovery operators. For Compose, the key is stored in
the `metrune-secrets` volume. The API refuses to start when encrypted
credentials exist but the key is missing; treat that as a restore signal, not
as a reason to generate a new key.

Provider credentials are not sealed with the master key directly. Each
organization gets its own key, derived from the master key with HKDF-SHA256
over the organization's id, so one tenant's key cannot open another tenant's
credentials. Derivation is deterministic: restoring the same master key
restores every organization's key.

The recovery key an admin exports from the dashboard
(`POST /v1/org/vault/recovery`) is that **organization's** derived key, not the
master key. It lets that organization decrypt its own credentials out of band.
It is not a deployment backup and cannot be used to restore the server — back
up `METRUNE_SECRETS_KEY_FILE` for that.

Credentials written before this scheme carry `key_derivation = 0` in
`provider_credentials` and stay readable under the master key. The API re-seals
them under their organization's key on the next start; a row that fails to
decrypt is logged and left untouched rather than dropped.

## Restore order

1. Restore PostgreSQL to a new or empty instance and verify the application
   role can connect.
2. Restore the ClickHouse database or volume snapshot with the compatible
   ClickHouse version.
3. Restore the exact vault master key at `METRUNE_SECRETS_KEY_FILE` with file
   permissions restricted to the API user.
4. Start one API instance so migrations and ClickHouse compatibility checks
   complete, then verify `/v1/readyz`.
5. Start the web service and validate login, analytics, ingestion, and vault
   credential resolution with a test account.
6. Keep the original backups untouched until the restored deployment passes a
   representative dashboard and client upload check.

## Retention and deletion

Usage rows carry the organization's retention value in ClickHouse. The
ClickHouse TTL removes rows after that stamped period; changing retention in
the admin area restamps existing rows through a background mutation. A
retention change is not an immediate deletion guarantee, so operators should
allow for ClickHouse mutation and merge time.

Retention does not automatically remove PostgreSQL users, installations,
tokens, audit events, pricing, or encrypted credentials. Installation
revocation, credential revocation, session expiry, and local client export are
separate controls. Full organization deletion is not yet an automated product
workflow; use a reviewed, tested database procedure and preserve audit and
legal records as required by the organization's policy.

## Upgrades and rollback

Back up PostgreSQL, ClickHouse, and the vault key before every release. The API
currently runs embedded PostgreSQL migrations during startup and applies
ClickHouse compatibility changes during startup. For the supported Compose
deployment, stop the old API, start the new API, verify readiness, and only
then recreate the web service.

Migrations may be forward-only. Do not roll back the application binary across
an unapplied or partially applied schema change unless the release notes
explicitly document compatibility. If a migration fails, preserve logs and the
database backup, fix the migration or restore to a new instance, and do not
delete the migration history table.

## Recovery drill

Before a production release, perform a restore in an isolated environment and
record the elapsed time, missing prerequisites, restored row counts, dashboard
checks, client upload check, and vault credential check. A backup is not
considered operationally useful until this drill succeeds.

### Automated drill

`scripts/restore-drill.sh` runs the full loop against Compose and fails loudly
if any part of it does not survive:

```bash
./scripts/restore-drill.sh
```

The script uses its own Compose project, its own volumes, and its own host port
(`METRUNE_DRILL_API_PORT`, default `18080`), so it can run beside a development
deployment without touching it. It:

1. Starts a clean deployment and seeds the state a backup must protect: an
   organization, a provider credential encrypted with the vault key, a
   classifier configuration pointing at that credential, an enrolled
   installation, and an ingested usage snapshot.
2. Takes the three backups described above — a custom-format `pg_dump`, a
   ClickHouse `Native` export of `session_snapshots_dedup`, and the vault
   master key.
3. Destroys the deployment **including every volume**, so nothing but the
   backups remains.
4. Restores in the documented order: PostgreSQL into an empty database, the
   vault master key at mode `600` before the API starts, then the API, then
   ClickHouse history.
5. Verifies the restore end to end: dashboard login works, analytics reports
   the restored session, the pre-existing installation token still
   authenticates, and — the check that actually proves the key pairing —
   classifier provisioning returns the *decrypted* provider secret.

Pass `METRUNE_DRILL_KEEP=1` to leave the restored deployment and its backups in
place for manual inspection. `METRUNE_DRILL_BACKUP_DIR` selects where backups
are written; it defaults to a temporary directory.

The script models a single-node Compose deployment. For managed PostgreSQL or
ClickHouse, keep the same sequence and the same verification steps, but
substitute the platform's backup and restore commands.

### What the drill does not cover

Record these manually as part of a production drill: multi-partition ClickHouse
history and merge/mutation backlog, external backup retrieval of the vault key,
DNS and TLS cutover, SMTP delivery, and the elapsed wall-clock time against the
recovery-time objective.
