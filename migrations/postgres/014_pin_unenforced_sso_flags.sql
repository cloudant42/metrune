-- Pin the SSO flags to their defaults until enforcement exists.
--
-- `organizations.sso_enforced` and `organizations.local_login_enabled` were
-- added in 004_identity.sql for OIDC sign-in. The dashboard reads them and
-- renders "SSO enforcement: enforced" and "Local password sign-in: disabled",
-- but `login` never consults either column, and no code path writes them.
--
-- Setting them directly in the database therefore produces an interface that
-- claims a protection the API does not apply. This constraint makes that state
-- unrepresentable: an attempt to enable SSO enforcement fails loudly instead of
-- succeeding silently and misleadingly.
--
-- docs/sso-design.md is the agreed design. The migration that implements
-- enforcement drops this constraint.

-- No code writes these columns, so any non-default value was set by hand and
-- never took effect. Normalising first keeps the constraint addition from
-- failing on such a row.
UPDATE organizations
   SET sso_enforced = FALSE,
       local_login_enabled = TRUE
 WHERE sso_enforced IS DISTINCT FROM FALSE
    OR local_login_enabled IS DISTINCT FROM TRUE;

ALTER TABLE organizations
  ADD CONSTRAINT organizations_sso_flags_unenforced
  CHECK (sso_enforced = FALSE AND local_login_enabled = TRUE);
