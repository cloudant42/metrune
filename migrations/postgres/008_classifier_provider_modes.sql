ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS classifier_protocol TEXT NOT NULL DEFAULT 'openai_chat',
    ADD COLUMN IF NOT EXISTS classifier_response_mode TEXT NOT NULL DEFAULT 'auto';
