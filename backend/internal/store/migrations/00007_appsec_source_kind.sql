-- +goose Up
ALTER TABLE alert ADD COLUMN alert_source_kind text NOT NULL DEFAULT 'log'
    CHECK (alert_source_kind IN ('log', 'appsec'));

UPDATE alert SET alert_source_kind = 'appsec'
WHERE EXISTS (
    SELECT 1 FROM event
    WHERE event_alert_id = alert_id
      AND (
          event_meta->>'service' = 'appsec'
          OR event_meta->>'log_type' LIKE 'appsec-%'
          OR (event_meta ? 'matched_zones' AND event_meta ? 'target_fqdn')
      )
);

CREATE INDEX alert_source_kind_created_at_index ON alert (alert_source_kind, alert_created_at DESC NULLS LAST, alert_id DESC);

-- +goose Down
DROP INDEX alert_source_kind_created_at_index;
ALTER TABLE alert DROP COLUMN alert_source_kind;
