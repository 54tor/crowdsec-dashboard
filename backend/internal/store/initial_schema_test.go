package store_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

// columnNamesOf returns the set of columns of a table of the test schema, so a
// test can check that the single initial migration creates every column the
// engine registry and the archive rely on.
func columnNamesOf(testContext *testing.T, database *bun.DB, tableName string) map[string]bool {
	testContext.Helper()
	var columnNames []string
	queryError := database.NewRaw(
		"SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ?", tableName,
	).Scan(context.Background(), &columnNames)
	if queryError != nil {
		testContext.Fatalf("list columns of %s: %v", tableName, queryError)
	}
	presentColumns := map[string]bool{}
	for _, columnName := range columnNames {
		presentColumns[columnName] = true
	}
	return presentColumns
}

func publicTableNames(testContext *testing.T, database *bun.DB) []string {
	testContext.Helper()
	var tableNames []string
	queryError := database.NewRaw(
		"SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name <> 'goose_db_version'",
	).Scan(context.Background(), &tableNames)
	if queryError != nil {
		testContext.Fatalf("list tables: %v", queryError)
	}
	sort.Strings(tableNames)
	return tableNames
}

func TestInitialSchemaCreatesTheEngineRegistryColumns(testContext *testing.T) {
	database := storetest.New(testContext)

	engineColumns := columnNamesOf(testContext, database, "engine")

	expectedEngineColumns := []string{
		"engine_name", "engine_is_local", "engine_lapi_url", "engine_machine_id",
		"engine_machine_password_sealed", "engine_machine_password_key_id",
		"engine_proxy_kind", "engine_proxy_url", "engine_proxy_credential_sealed", "engine_proxy_credential_key_id",
		"engine_allow_insecure_http", "engine_public_address_list", "engine_enabled", "engine_sync_enabled",
		"engine_collection_cursor", "engine_last_collected_at", "engine_last_collection_error",
		"engine_history_incomplete", "engine_deleting_at",
	}
	for _, expectedColumn := range expectedEngineColumns {
		if !engineColumns[expectedColumn] {
			testContext.Errorf("engine must have column %s", expectedColumn)
		}
	}
}

func TestAlertSourceKindDefaultsToLogAndRefusesUnknownKinds(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	engineIdentifier := insertTestEngine(testContext, database, "remote")
	alertIdentifier, alertError := insertTestAlert(testContext, database, engineIdentifier, 1, "uuid-a")
	if alertError != nil {
		testContext.Fatalf("alert: %v", alertError)
	}

	var obtainedSourceKind string
	if readError := database.NewRaw("SELECT alert_source_kind FROM alert WHERE alert_id = ?", alertIdentifier).Scan(ctx, &obtainedSourceKind); readError != nil {
		testContext.Fatalf("read source kind: %v", readError)
	}
	if obtainedSourceKind != "log" {
		testContext.Errorf("source kind = %q, want log", obtainedSourceKind)
	}

	if _, appSecError := database.ExecContext(ctx, "UPDATE alert SET alert_source_kind = 'appsec' WHERE alert_id = ?", alertIdentifier); appSecError != nil {
		testContext.Errorf("appsec source kind: %v", appSecError)
	}
	_, unknownKindError := database.ExecContext(ctx, "UPDATE alert SET alert_source_kind = 'other' WHERE alert_id = ?", alertIdentifier)
	requireSQLState(testContext, unknownKindError, "23514", "alert_alert_source_kind_check")
}

// Rolling the single initial migration back must leave no table behind, and
// applying it again must give back a usable schema.
func TestMigrationDownThenUpRestoresTheWholeSchema(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	provider := newMigrationProvider(testContext, database)
	tablesBeforeDown := publicTableNames(testContext, database)

	if _, downError := provider.DownTo(ctx, 0); downError != nil {
		testContext.Fatalf("down to 0: %v", downError)
	}
	if tablesAfterDown := publicTableNames(testContext, database); len(tablesAfterDown) != 0 {
		testContext.Fatalf("tables after down = %v, want none", tablesAfterDown)
	}

	if _, upError := provider.Up(ctx); upError != nil {
		testContext.Fatalf("up again: %v", upError)
	}
	if tablesAfterUp := publicTableNames(testContext, database); strings.Join(tablesAfterUp, ",") != strings.Join(tablesBeforeDown, ",") {
		testContext.Errorf("tables after up = %v, want %v", tablesAfterUp, tablesBeforeDown)
	}
	accountIdentifier := insertTestAccount(testContext, database, "alice")
	_, totpError := database.ExecContext(ctx,
		"INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', '\\x01', 'key1')", accountIdentifier)
	if totpError != nil {
		testContext.Errorf("totp after up: %v", totpError)
	}
	insertTestEngine(testContext, database, "remote")
}

// The search feature relies on pg_trgm GIN indexes; the existing btree indexes
// must stay beside them because equality filters and sorting still use them.
func TestInitialSchemaCreatesTheTrigramSearchIndexes(testContext *testing.T) {
	database := storetest.New(testContext)

	var schemaIndexes []struct {
		IndexName       string `bun:"indexname"`
		IndexDefinition string `bun:"indexdef"`
	}
	queryError := database.NewRaw(
		"SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema()",
	).Scan(context.Background(), &schemaIndexes)
	if queryError != nil {
		testContext.Fatalf("list indexes: %v", queryError)
	}
	definitionByIndexName := map[string]string{}
	for _, schemaIndex := range schemaIndexes {
		definitionByIndexName[schemaIndex.IndexName] = schemaIndex.IndexDefinition
	}

	expectedTrigramIndexes := []string{
		"alert_source_value_trigram_index", "alert_scenario_name_trigram_index",
		"alert_message_trigram_index", "alert_machine_id_trigram_index",
		"decision_value_trigram_index", "decision_scenario_trigram_index",
		"decision_type_trigram_index", "decision_origin_trigram_index",
		"engine_name_trigram_index", "audit_event_action_trigram_index",
		"audit_event_target_trigram_index", "account_name_trigram_index",
	}
	for _, expectedIndexName := range expectedTrigramIndexes {
		indexDefinition, isPresent := definitionByIndexName[expectedIndexName]
		if !isPresent {
			testContext.Errorf("missing trigram index %s", expectedIndexName)
			continue
		}
		isTrigramGinIndex := strings.Contains(indexDefinition, "USING gin") && strings.Contains(indexDefinition, "gin_trgm_ops")
		if !isTrigramGinIndex {
			testContext.Errorf("index %s = %q, want a gin gin_trgm_ops index", expectedIndexName, indexDefinition)
		}
	}

	expectedBtreeIndexes := []string{"alert_source_value_index", "alert_scenario_name_index", "decision_value_index"}
	for _, expectedIndexName := range expectedBtreeIndexes {
		if _, isPresent := definitionByIndexName[expectedIndexName]; !isPresent {
			testContext.Errorf("missing btree index %s", expectedIndexName)
		}
	}
}
