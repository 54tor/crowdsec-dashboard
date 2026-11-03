package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

const lastMigrationBeforeSourceKind = 6

// insertAlertWithEventMetas archives one alert of the engine carrying one event
// per given JSON meta object, straight in SQL, as the pre-00007 writer did.
func insertAlertWithEventMetas(testContext *testing.T, database *bun.DB, engineIdentifier int64, upstreamIdentifier int64, eventMetas ...string) {
	testContext.Helper()
	alertIdentifier, alertError := insertTestAlert(testContext, database, engineIdentifier, upstreamIdentifier, fmt.Sprintf("uuid-%d", upstreamIdentifier))
	if alertError != nil {
		testContext.Fatalf("alert %d: %v", upstreamIdentifier, alertError)
	}
	for _, eventMeta := range eventMetas {
		if _, eventError := database.ExecContext(context.Background(),
			"INSERT INTO event (event_alert_id, event_meta) VALUES (?, ?::jsonb)", alertIdentifier, eventMeta); eventError != nil {
			testContext.Fatalf("event of alert %d: %v", upstreamIdentifier, eventError)
		}
	}
}

func sourceKindsByUpstreamID(testContext *testing.T, database *bun.DB) map[int64]string {
	testContext.Helper()
	var storedRows []struct {
		UpstreamID int64  `bun:"alert_upstream_id"`
		SourceKind string `bun:"alert_source_kind"`
	}
	if queryError := database.NewRaw("SELECT alert_upstream_id, alert_source_kind FROM alert").Scan(context.Background(), &storedRows); queryError != nil {
		testContext.Fatalf("read source kinds: %v", queryError)
	}
	kindsByUpstreamID := map[int64]string{}
	for _, storedRow := range storedRows {
		kindsByUpstreamID[storedRow.UpstreamID] = storedRow.SourceKind
	}
	return kindsByUpstreamID
}

// The events mirror the real engine capture (deploy/dev/fixtures/appsec-alert.json):
// the aggregate alert carries service/log_type, the per-rule alerts only carry
// matched_zones and target_fqdn among the keys the predicate looks at.
func TestMigrationBackfillsAppSecFromEvents(testContext *testing.T) {
	database := storetest.NewUnmigrated(testContext)
	ctx := context.Background()
	provider := newMigrationProvider(testContext, database)
	if _, upToError := provider.UpTo(ctx, lastMigrationBeforeSourceKind); upToError != nil {
		testContext.Fatalf("up to %d: %v", lastMigrationBeforeSourceKind, upToError)
	}
	engineIdentifier := insertTestEngine(testContext, database, "remote")
	insertAlertWithEventMetas(testContext, database, engineIdentifier, 1, `{"source_ip":"203.0.113.1","service":"appsec","log_type":"appsec-block"}`)
	insertAlertWithEventMetas(testContext, database, engineIdentifier, 2, `{"log_type":"appsec-info"}`)
	insertAlertWithEventMetas(testContext, database, engineIdentifier, 3,
		`{"source_ip":"203.0.113.3"}`,
		`{"rule_name":"crowdsecurity/vpatch-env-access","matched_zones":"REQUEST_FILENAME","target_fqdn":"www.example.com"}`)
	insertAlertWithEventMetas(testContext, database, engineIdentifier, 4, `{"service":"ssh","log_type":"ssh_failed-auth"}`)
	insertAlertWithEventMetas(testContext, database, engineIdentifier, 5, `{"matched_zones":"URI"}`, `{"target_fqdn":"www.example.com"}`)
	insertAlertWithEventMetas(testContext, database, engineIdentifier, 6)

	if _, upError := provider.Up(ctx); upError != nil {
		testContext.Fatalf("up: %v", upError)
	}

	expectedKinds := map[int64]string{1: "appsec", 2: "appsec", 3: "appsec", 4: "log", 5: "log", 6: "log"}
	if obtainedKinds := sourceKindsByUpstreamID(testContext, database); fmt.Sprint(obtainedKinds) != fmt.Sprint(expectedKinds) {
		testContext.Errorf("expected %v, got %v", expectedKinds, obtainedKinds)
	}
	_, invalidKindError := database.ExecContext(ctx, "UPDATE alert SET alert_source_kind = 'other' WHERE alert_upstream_id = 1")
	requireSQLState(testContext, invalidKindError, "23514", "alert_source_kind")
	if _, indexed := alertIndexDefinitions(testContext, database)["alert_source_kind_created_at_index"]; !indexed {
		testContext.Errorf("the source kind filter needs its index")
	}
}

func TestSourceKindMigrationDownRemovesColumnAndIndex(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	provider := newMigrationProvider(testContext, database)

	if _, downError := provider.DownTo(ctx, lastMigrationBeforeSourceKind); downError != nil {
		testContext.Fatalf("down to %d: %v", lastMigrationBeforeSourceKind, downError)
	}
	var remainingColumns int
	countError := database.NewRaw(
		"SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'alert' AND column_name = 'alert_source_kind'",
	).Scan(ctx, &remainingColumns)
	if countError != nil || remainingColumns != 0 {
		testContext.Errorf("down must drop alert_source_kind, %d left (error %v)", remainingColumns, countError)
	}
	if _, stillIndexed := alertIndexDefinitions(testContext, database)["alert_source_kind_created_at_index"]; stillIndexed {
		testContext.Errorf("down must drop the source kind index")
	}

	if _, upError := provider.Up(ctx); upError != nil {
		testContext.Fatalf("up again: %v", upError)
	}
}
