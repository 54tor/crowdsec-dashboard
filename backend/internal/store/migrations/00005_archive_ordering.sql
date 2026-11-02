-- +goose Up
ALTER TABLE engine ADD COLUMN engine_history_incomplete boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE engine DROP COLUMN engine_history_incomplete;
