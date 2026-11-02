package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

// alertIndexDefinitions maps each index of the alert table to its definition,
// as PostgreSQL renders it, so a test can check the sort order it stores.
func alertIndexDefinitions(testContext *testing.T, database *bun.DB) map[string]string {
	testContext.Helper()
	var indexRows []struct {
		IndexName       string `bun:"indexname"`
		IndexDefinition string `bun:"indexdef"`
	}
	queryError := database.NewRaw(
		"SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename = 'alert'",
	).Scan(context.Background(), &indexRows)
	if queryError != nil {
		testContext.Fatalf("list alert indexes: %v", queryError)
	}
	definitionsByName := map[string]string{}
	for _, indexRow := range indexRows {
		definitionsByName[indexRow.IndexName] = indexRow.IndexDefinition
	}
	return definitionsByName
}

// The archive lists alerts by created_at DESC NULLS LAST then alert_id DESC; the
// indexes serving that order (with and without the engine filter) must store the
// same order, and the DESC NULLS FIRST indexes of 00003 they replace are gone.
func TestArchiveOrderingIndexesSortNullsLast(testContext *testing.T) {
	database := storetest.New(testContext)

	definitionsByName := alertIndexDefinitions(testContext, database)

	expectedDefinitions := map[string]string{
		"alert_created_at_nulls_last_index":           "(alert_created_at DESC NULLS LAST, alert_id DESC)",
		"alert_engine_id_created_at_nulls_last_index": "(alert_engine_id, alert_created_at DESC NULLS LAST, alert_id DESC)",
	}
	for indexName, expectedColumns := range expectedDefinitions {
		if !strings.HasSuffix(definitionsByName[indexName], expectedColumns) {
			testContext.Errorf("index %s = %q, want columns %s", indexName, definitionsByName[indexName], expectedColumns)
		}
	}
	for _, replacedIndexName := range []string{"alert_created_at_index", "alert_engine_id_created_at_index"} {
		if replacedDefinition, stillPresent := definitionsByName[replacedIndexName]; stillPresent {
			testContext.Errorf("index %s must be replaced, still %q", replacedIndexName, replacedDefinition)
		}
	}
}

func TestArchiveOrderingMigrationDownRestoresThe00003Indexes(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	provider := newMigrationProvider(testContext, database)

	if _, downError := provider.DownTo(ctx, 4); downError != nil {
		testContext.Fatalf("down to 4: %v", downError)
	}
	definitionsAfterDown := alertIndexDefinitions(testContext, database)
	for _, restoredIndexName := range []string{"alert_created_at_index", "alert_engine_id_created_at_index"} {
		if _, restored := definitionsAfterDown[restoredIndexName]; !restored {
			testContext.Errorf("down must restore %s, got %v", restoredIndexName, definitionsAfterDown)
		}
	}
	if _, stillPresent := definitionsAfterDown["alert_created_at_nulls_last_index"]; stillPresent {
		testContext.Errorf("down must drop the NULLS LAST index")
	}

	if _, upError := provider.Up(ctx); upError != nil {
		testContext.Fatalf("up again: %v", upError)
	}
	if _, recreated := alertIndexDefinitions(testContext, database)["alert_created_at_nulls_last_index"]; !recreated {
		testContext.Errorf("up must recreate the NULLS LAST index")
	}
}
