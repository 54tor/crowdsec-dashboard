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
// indexes serving that order (unfiltered, by engine and by source kind) must store
// the same order, and no DESC NULLS FIRST index on alert_created_at may exist.
func TestArchiveOrderingIndexesSortNullsLast(testContext *testing.T) {
	database := storetest.New(testContext)

	definitionsByName := alertIndexDefinitions(testContext, database)

	expectedDefinitions := map[string]string{
		"alert_created_at_nulls_last_index":           "(alert_created_at DESC NULLS LAST, alert_id DESC)",
		"alert_engine_id_created_at_nulls_last_index": "(alert_engine_id, alert_created_at DESC NULLS LAST, alert_id DESC)",
		"alert_source_kind_created_at_index":          "(alert_source_kind, alert_created_at DESC NULLS LAST, alert_id DESC)",
	}
	for indexName, expectedColumns := range expectedDefinitions {
		if !strings.HasSuffix(definitionsByName[indexName], expectedColumns) {
			testContext.Errorf("index %s = %q, want columns %s", indexName, definitionsByName[indexName], expectedColumns)
		}
	}
	for _, forbiddenIndexName := range []string{"alert_created_at_index", "alert_engine_id_created_at_index"} {
		if forbiddenDefinition, stillPresent := definitionsByName[forbiddenIndexName]; stillPresent {
			testContext.Errorf("index %s must not exist, found %q", forbiddenIndexName, forbiddenDefinition)
		}
	}
}
