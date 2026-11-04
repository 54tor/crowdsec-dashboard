-- +goose Up
CREATE TABLE account (
    account_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_name text NOT NULL UNIQUE CHECK (account_name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    account_role text NOT NULL DEFAULT 'admin' CHECK (account_role IN ('admin', 'read_only')),
    account_preference jsonb NOT NULL DEFAULT '{}',
    account_created_at timestamptz NOT NULL DEFAULT now(),
    account_webauthn_user_handle bytea UNIQUE,
    account_failed_second_factor_count integer NOT NULL DEFAULT 0 CHECK (account_failed_second_factor_count >= 0),
    account_locked_until timestamptz,
    account_second_factor_setup_until timestamptz
);

CREATE TABLE credential (
    credential_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    credential_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    credential_kind text NOT NULL,
    credential_secret_hash text,
    credential_created_at timestamptz NOT NULL DEFAULT now(),
    credential_secret_ciphertext bytea,
    credential_key_id text,
    credential_totp_last_step bigint,
    credential_webauthn_id bytea UNIQUE,
    credential_webauthn_data jsonb,
    credential_last_used_at timestamptz,
    CONSTRAINT credential_kind_check CHECK (credential_kind IN ('password', 'totp', 'webauthn')),
    CONSTRAINT credential_payload_check CHECK (
        (credential_kind = 'password' AND credential_secret_hash IS NOT NULL)
        OR (credential_kind = 'totp' AND credential_secret_ciphertext IS NOT NULL AND credential_key_id IS NOT NULL)
        OR (credential_kind = 'webauthn' AND credential_webauthn_id IS NOT NULL AND credential_webauthn_data IS NOT NULL)
    )
);

CREATE UNIQUE INDEX credential_one_password_per_account
    ON credential (credential_account_id) WHERE credential_kind = 'password';
CREATE UNIQUE INDEX credential_one_totp_per_account
    ON credential (credential_account_id) WHERE credential_kind = 'totp';
CREATE INDEX credential_account_id_index ON credential (credential_account_id);

CREATE TABLE session (
    session_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_token_hash bytea NOT NULL UNIQUE,
    session_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    session_created_at timestamptz NOT NULL DEFAULT now(),
    session_expires_at timestamptz NOT NULL
);

CREATE INDEX session_expires_at_index ON session (session_expires_at);
CREATE INDEX session_account_id_index ON session (session_account_id);

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

CREATE INDEX audit_event_account_id_index ON audit_event (audit_event_account_id);
CREATE INDEX audit_event_created_at_index ON audit_event (audit_event_created_at);

CREATE TABLE api_token (
    api_token_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    api_token_account_id bigint NOT NULL REFERENCES account (account_id) ON DELETE CASCADE,
    api_token_name text NOT NULL,
    api_token_hash bytea NOT NULL UNIQUE,
    api_token_scope text NOT NULL,
    api_token_created_at timestamptz NOT NULL DEFAULT now(),
    api_token_expires_at timestamptz NOT NULL,
    api_token_revoked_at timestamptz,
    CONSTRAINT api_token_scope_check CHECK (api_token_scope IN ('read', 'write'))
);

CREATE INDEX api_token_account_id_index ON api_token (api_token_account_id);
CREATE UNIQUE INDEX api_token_active_name_index
    ON api_token (api_token_account_id, api_token_name) WHERE api_token_revoked_at IS NULL;
CREATE INDEX api_token_expires_at_index ON api_token (api_token_expires_at);

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

CREATE TABLE engine (
    engine_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    engine_name text NOT NULL UNIQUE CHECK (engine_name ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    engine_is_local boolean NOT NULL DEFAULT false,
    engine_lapi_url text NOT NULL,
    engine_machine_id text NOT NULL,
    engine_machine_password_sealed bytea,
    engine_machine_password_key_id text,
    engine_proxy_kind text CHECK (engine_proxy_kind IN ('socks5', 'http')),
    engine_proxy_url text,
    engine_proxy_credential_sealed bytea,
    engine_proxy_credential_key_id text,
    engine_allow_insecure_http boolean NOT NULL DEFAULT false,
    engine_public_address_list jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(engine_public_address_list) = 'array'),
    engine_enabled boolean NOT NULL DEFAULT true,
    engine_sync_enabled boolean NOT NULL DEFAULT false,
    engine_collection_cursor bigint NOT NULL DEFAULT 0 CHECK (engine_collection_cursor >= 0),
    engine_last_collected_at timestamptz,
    engine_last_collection_error text,
    engine_created_at timestamptz NOT NULL DEFAULT now(),
    engine_updated_at timestamptz NOT NULL DEFAULT now(),
    engine_history_incomplete boolean NOT NULL DEFAULT false,
    engine_deleting_at timestamptz,
    CONSTRAINT engine_password_required_unless_local_check CHECK (
        engine_is_local OR (engine_machine_password_sealed IS NOT NULL AND engine_machine_password_key_id IS NOT NULL)
    ),
    CONSTRAINT engine_machine_password_pair_check CHECK (
        (engine_machine_password_sealed IS NULL) = (engine_machine_password_key_id IS NULL)
    ),
    CONSTRAINT engine_proxy_credential_pair_check CHECK (
        (engine_proxy_credential_sealed IS NULL) = (engine_proxy_credential_key_id IS NULL)
    ),
    CONSTRAINT engine_proxy_pair_check CHECK ((engine_proxy_kind IS NULL) = (engine_proxy_url IS NULL)),
    CONSTRAINT engine_proxy_credential_requires_proxy_check CHECK (
        engine_proxy_kind IS NOT NULL
        OR (engine_proxy_credential_sealed IS NULL AND engine_proxy_credential_key_id IS NULL)
    )
);

CREATE UNIQUE INDEX engine_one_local_index ON engine (engine_is_local) WHERE engine_is_local;

CREATE TABLE alert (
    alert_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_engine_id bigint NOT NULL REFERENCES engine (engine_id) ON DELETE CASCADE,
    alert_upstream_id bigint NOT NULL CHECK (alert_upstream_id > 0),
    alert_upstream_uuid text NOT NULL,
    alert_scenario_name text NOT NULL,
    alert_scenario_version text,
    alert_message text,
    alert_machine_id text,
    alert_source_scope text,
    alert_source_value text,
    alert_source_country_code text,
    alert_source_autonomous_system_number text,
    alert_source_autonomous_system_name text,
    alert_events_count integer,
    alert_events_truncated boolean NOT NULL DEFAULT false,
    alert_simulated boolean NOT NULL DEFAULT false,
    alert_started_at timestamptz,
    alert_stopped_at timestamptz,
    alert_created_at timestamptz,
    alert_collected_at timestamptz NOT NULL DEFAULT now(),
    alert_source_kind text NOT NULL DEFAULT 'log' CHECK (alert_source_kind IN ('log', 'appsec')),
    UNIQUE (alert_engine_id, alert_upstream_id, alert_upstream_uuid)
);

CREATE INDEX alert_created_at_nulls_last_index ON alert (alert_created_at DESC NULLS LAST, alert_id DESC);
CREATE INDEX alert_engine_id_created_at_nulls_last_index ON alert (alert_engine_id, alert_created_at DESC NULLS LAST, alert_id DESC);
CREATE INDEX alert_source_kind_created_at_index ON alert (alert_source_kind, alert_created_at DESC NULLS LAST, alert_id DESC);
CREATE INDEX alert_collected_at_index ON alert (alert_collected_at);
CREATE INDEX alert_source_value_index ON alert (alert_source_value);
CREATE INDEX alert_scenario_name_index ON alert (alert_scenario_name);

CREATE TABLE event (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_alert_id bigint NOT NULL REFERENCES alert (alert_id) ON DELETE CASCADE,
    event_timestamp timestamptz,
    event_meta jsonb NOT NULL DEFAULT '{}',
    CONSTRAINT event_meta_bounded_object_check CHECK (
        jsonb_typeof(event_meta) = 'object' AND octet_length(event_meta::text) <= 65536
    )
);

CREATE INDEX event_alert_id_index ON event (event_alert_id);

CREATE TABLE decision (
    decision_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decision_alert_id bigint NOT NULL REFERENCES alert (alert_id) ON DELETE CASCADE,
    decision_upstream_id bigint NOT NULL,
    decision_type text NOT NULL,
    decision_origin text NOT NULL,
    decision_scope text NOT NULL,
    decision_value text NOT NULL,
    decision_scenario text,
    decision_simulated boolean NOT NULL DEFAULT false,
    decision_until timestamptz,
    UNIQUE (decision_alert_id, decision_upstream_id)
);

CREATE INDEX decision_value_index ON decision (decision_value);
CREATE INDEX decision_until_index ON decision (decision_until);

-- +goose Down
DROP TABLE decision;
DROP TABLE event;
DROP TABLE alert;
DROP TABLE engine;
DROP TABLE access_rule;
DROP TABLE recovery_code;
DROP TABLE api_token;
DROP TABLE audit_event;
DROP TABLE setting;
DROP TABLE session;
DROP TABLE credential;
DROP TABLE account;
