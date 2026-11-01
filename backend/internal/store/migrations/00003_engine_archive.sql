-- +goose Up
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
    UNIQUE (alert_engine_id, alert_upstream_id, alert_upstream_uuid)
);

CREATE INDEX alert_created_at_index ON alert (alert_created_at DESC);
CREATE INDEX alert_engine_id_created_at_index ON alert (alert_engine_id, alert_created_at DESC);
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
