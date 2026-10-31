-- +goose Up
ALTER TABLE credential DROP CONSTRAINT credential_credential_kind_check;
ALTER TABLE credential ALTER COLUMN credential_secret_hash DROP NOT NULL;
ALTER TABLE credential
    ADD COLUMN credential_secret_ciphertext bytea,
    ADD COLUMN credential_key_id text,
    ADD COLUMN credential_totp_last_step bigint,
    ADD COLUMN credential_webauthn_id bytea UNIQUE,
    ADD COLUMN credential_webauthn_data jsonb,
    ADD COLUMN credential_last_used_at timestamptz;
ALTER TABLE credential
    ADD CONSTRAINT credential_kind_check CHECK (credential_kind IN ('password', 'totp', 'webauthn')),
    ADD CONSTRAINT credential_payload_check CHECK (
        (credential_kind = 'password' AND credential_secret_hash IS NOT NULL)
        OR (credential_kind = 'totp' AND credential_secret_ciphertext IS NOT NULL AND credential_key_id IS NOT NULL)
        OR (credential_kind = 'webauthn' AND credential_webauthn_id IS NOT NULL AND credential_webauthn_data IS NOT NULL)
    );

CREATE UNIQUE INDEX credential_one_totp_per_account
    ON credential (credential_account_id) WHERE credential_kind = 'totp';
CREATE INDEX credential_account_id_index ON credential (credential_account_id);

ALTER TABLE account
    ADD COLUMN account_webauthn_user_handle bytea UNIQUE,
    ADD COLUMN account_failed_second_factor_count integer NOT NULL DEFAULT 0 CHECK (account_failed_second_factor_count >= 0),
    ADD COLUMN account_locked_until timestamptz,
    ADD COLUMN account_second_factor_setup_until timestamptz;

UPDATE account SET account_second_factor_setup_until = 'infinity';

CREATE TABLE recovery_code (
    recovery_code_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recovery_code_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    recovery_code_hash bytea NOT NULL,
    recovery_code_used_at timestamptz,
    recovery_code_created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (recovery_code_account_id, recovery_code_hash)
);

CREATE TABLE access_rule (
    access_rule_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    access_rule_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    access_rule_kind text NOT NULL CHECK (access_rule_kind IN ('ip', 'country')),
    access_rule_value text NOT NULL,
    access_rule_created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (access_rule_kind <> 'country' OR access_rule_value ~ '^[A-Z]{2}$'),
    UNIQUE (access_rule_account_id, access_rule_kind, access_rule_value)
);

CREATE INDEX session_account_id_index ON session (session_account_id);
CREATE INDEX api_token_account_id_index ON api_token (api_token_account_id);
CREATE INDEX audit_event_account_id_index ON audit_event (audit_event_account_id);
CREATE INDEX audit_event_created_at_index ON audit_event (audit_event_created_at);

-- +goose Down
DROP INDEX audit_event_created_at_index;
DROP INDEX audit_event_account_id_index;
DROP INDEX api_token_account_id_index;
DROP INDEX session_account_id_index;

DROP TABLE access_rule;
DROP TABLE recovery_code;

ALTER TABLE account
    DROP COLUMN account_second_factor_setup_until,
    DROP COLUMN account_locked_until,
    DROP COLUMN account_failed_second_factor_count,
    DROP COLUMN account_webauthn_user_handle;

DELETE FROM credential WHERE credential_kind <> 'password';

DROP INDEX credential_account_id_index;
DROP INDEX credential_one_totp_per_account;
ALTER TABLE credential
    DROP CONSTRAINT credential_payload_check,
    DROP CONSTRAINT credential_kind_check;
ALTER TABLE credential
    DROP COLUMN credential_last_used_at,
    DROP COLUMN credential_webauthn_data,
    DROP COLUMN credential_webauthn_id,
    DROP COLUMN credential_totp_last_step,
    DROP COLUMN credential_key_id,
    DROP COLUMN credential_secret_ciphertext;
ALTER TABLE credential ALTER COLUMN credential_secret_hash SET NOT NULL;
ALTER TABLE credential
    ADD CONSTRAINT credential_credential_kind_check CHECK (credential_kind IN ('password'));
