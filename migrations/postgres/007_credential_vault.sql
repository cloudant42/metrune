CREATE TABLE IF NOT EXISTS provider_credentials (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    grace_until TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (organization_id, credential_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS provider_credentials_one_active
    ON provider_credentials(organization_id, credential_id)
    WHERE revoked_at IS NULL AND grace_until IS NULL;

CREATE TABLE IF NOT EXISTS vault_recovery_exports (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    exported_by UUID REFERENCES users(id) ON DELETE SET NULL,
    exported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE installations
    ADD COLUMN IF NOT EXISTS classifier_credential_id TEXT,
    ADD COLUMN IF NOT EXISTS classifier_credential_version INTEGER;
