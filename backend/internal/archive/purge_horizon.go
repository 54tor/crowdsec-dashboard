package archive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

const eventPurgeHorizonKey = "archive_event_purge_horizon"

func readEventPurgeHorizon(ctx context.Context, database bun.IDB) (*time.Time, error) {
	var storedValue []byte
	readError := database.NewRaw(`SELECT setting_value FROM setting WHERE setting_key = ?`, eventPurgeHorizonKey).Scan(ctx, &storedValue)
	if errors.Is(readError, sql.ErrNoRows) {
		return nil, nil
	}
	if readError != nil {
		return nil, readError
	}
	var storedHorizon time.Time
	if decodeError := json.Unmarshal(storedValue, &storedHorizon); decodeError != nil {
		return nil, decodeError
	}
	return &storedHorizon, nil
}

func writeEventPurgeHorizon(ctx context.Context, database bun.IDB, horizon time.Time) error {
	encodedHorizon, encodeError := json.Marshal(horizon.UTC())
	if encodeError != nil {
		return encodeError
	}
	_, writeError := database.NewRaw(
		`INSERT INTO setting (setting_key, setting_value) VALUES (?, ?::jsonb)
		 ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`,
		eventPurgeHorizonKey, string(encodedHorizon),
	).Exec(ctx)
	return writeError
}
