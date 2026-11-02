-- +goose Up
ALTER TABLE api_token
    ADD CONSTRAINT api_token_scope_check CHECK (api_token_scope IN ('read', 'write')),
    ALTER COLUMN api_token_expires_at SET NOT NULL;

CREATE UNIQUE INDEX api_token_active_name_index
    ON api_token (api_token_account_id, api_token_name) WHERE api_token_revoked_at IS NULL;
CREATE INDEX api_token_expires_at_index ON api_token (api_token_expires_at);

-- +goose Down
DROP INDEX api_token_expires_at_index;
DROP INDEX api_token_active_name_index;

ALTER TABLE api_token
    ALTER COLUMN api_token_expires_at DROP NOT NULL,
    DROP CONSTRAINT api_token_scope_check;
