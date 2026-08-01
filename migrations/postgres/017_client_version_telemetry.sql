ALTER TABLE installations
  ADD COLUMN IF NOT EXISTS last_client_version TEXT;
