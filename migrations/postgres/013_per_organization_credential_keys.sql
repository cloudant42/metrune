-- Provider credentials move from a single deployment-wide vault key to a key
-- derived per organization, so exporting one organization's recovery key can
-- no longer decrypt a co-tenant's secrets.
--
-- Existing rows stay readable: they keep key_derivation = 0 (sealed under the
-- master key) until the API re-wraps them under their organization's key on
-- the next start.

ALTER TABLE provider_credentials
    ADD COLUMN IF NOT EXISTS key_derivation SMALLINT NOT NULL DEFAULT 0;

-- Recovery exports are per organization and are now scoped to the active
-- organization rather than the exporting user's legacy home organization.
ALTER TABLE vault_recovery_exports
    ADD COLUMN IF NOT EXISTS key_derivation SMALLINT NOT NULL DEFAULT 0;
