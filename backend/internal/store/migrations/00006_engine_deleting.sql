-- +goose Up
ALTER TABLE engine ADD COLUMN engine_deleting_at timestamptz;

-- +goose Down
ALTER TABLE engine DROP COLUMN engine_deleting_at;
