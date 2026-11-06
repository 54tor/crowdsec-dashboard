-- +goose Up
CREATE TABLE config_file_backup (
    config_file_backup_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    config_file_backup_engine_name text NOT NULL,
    config_file_backup_file_name text NOT NULL,
    config_file_backup_content text NOT NULL CHECK (octet_length(config_file_backup_content) <= 262144),
    config_file_backup_digest text NOT NULL DEFAULT '',
    config_file_backup_account_name text,
    config_file_backup_created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX config_file_backup_file_index
    ON config_file_backup (config_file_backup_engine_name, config_file_backup_file_name, config_file_backup_created_at DESC, config_file_backup_id DESC);

-- +goose Down
DROP TABLE config_file_backup;
