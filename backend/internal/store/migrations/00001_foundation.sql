-- +goose Up
CREATE TABLE account (
    account_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_name text NOT NULL UNIQUE CHECK (account_name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    account_role text NOT NULL DEFAULT 'admin' CHECK (account_role IN ('admin', 'read_only')),
    account_preference jsonb NOT NULL DEFAULT '{}',
    account_created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credential (
    credential_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    credential_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    credential_kind text NOT NULL CHECK (credential_kind IN ('password')),
    credential_secret_hash text NOT NULL,
    credential_created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX credential_one_password_per_account
    ON credential (credential_account_id) WHERE credential_kind = 'password';

CREATE TABLE session (
    session_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_token_hash bytea NOT NULL UNIQUE,
    session_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    session_created_at timestamptz NOT NULL DEFAULT now(),
    session_expires_at timestamptz NOT NULL
);

CREATE INDEX session_expires_at_index ON session (session_expires_at);

CREATE TABLE setting (
    setting_key text PRIMARY KEY,
    setting_value jsonb NOT NULL
);

CREATE TABLE audit_event (
    audit_event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    audit_event_account_id bigint REFERENCES account (account_id) ON DELETE SET NULL,
    audit_event_action text NOT NULL,
    audit_event_target text,
    audit_event_client_ip text,
    audit_event_created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_token (
    api_token_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    api_token_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    api_token_name text NOT NULL,
    api_token_hash bytea NOT NULL UNIQUE,
    api_token_scope text NOT NULL,
    api_token_created_at timestamptz NOT NULL DEFAULT now(),
    api_token_expires_at timestamptz,
    api_token_revoked_at timestamptz
);

-- +goose Down
DROP TABLE api_token;
DROP TABLE audit_event;
DROP TABLE setting;
DROP TABLE session;
DROP TABLE credential;
DROP TABLE account;
