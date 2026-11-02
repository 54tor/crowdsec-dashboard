-- +goose Up
ALTER TABLE engine ADD COLUMN engine_history_incomplete boolean NOT NULL DEFAULT false;

CREATE INDEX alert_created_at_nulls_last_index ON alert (alert_created_at DESC NULLS LAST, alert_id DESC);
CREATE INDEX alert_engine_id_created_at_nulls_last_index ON alert (alert_engine_id, alert_created_at DESC NULLS LAST, alert_id DESC);
DROP INDEX alert_created_at_index;
DROP INDEX alert_engine_id_created_at_index;

-- +goose Down
CREATE INDEX alert_engine_id_created_at_index ON alert (alert_engine_id, alert_created_at DESC);
CREATE INDEX alert_created_at_index ON alert (alert_created_at DESC);
DROP INDEX alert_engine_id_created_at_nulls_last_index;
DROP INDEX alert_created_at_nulls_last_index;

ALTER TABLE engine DROP COLUMN engine_history_incomplete;
