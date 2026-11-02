package engines

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

const testPurgeBatchSize = 3

func insertArchivedAlerts(testContext *testing.T, fixture testFixture, engineID int64, alertCount int) {
	testContext.Helper()
	for alertNumber := 1; alertNumber <= alertCount; alertNumber++ {
		_, insertError := fixture.database.ExecContext(context.Background(),
			`INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name)
			 VALUES (?, ?, ?, 'test/scenario')`, engineID, alertNumber, fmt.Sprintf("uuid-%d", alertNumber))
		if insertError != nil {
			testContext.Fatalf("insert alert: %v", insertError)
		}
	}
}

func markDeleting(testContext *testing.T, fixture testFixture, name string) {
	testContext.Helper()
	_, markError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_deleting_at = now() WHERE engine_name = ?`, name)
	if markError != nil {
		testContext.Fatalf("mark deleting: %v", markError)
	}
}

func countRows(testContext *testing.T, fixture testFixture, query string, arguments ...any) int {
	testContext.Helper()
	var rowCount int
	if scanError := fixture.database.NewRaw(query, arguments...).Scan(context.Background(), &rowCount); scanError != nil {
		testContext.Fatalf("count: %v", scanError)
	}
	return rowCount
}

func newDeletableEngine(testContext *testing.T, fixture testFixture, name string, alertCount int) Engine {
	testContext.Helper()
	fixture.repository.SetPurgeBatchSize(testPurgeBatchSize)
	createdEngine := mustCreate(testContext, fixture, insecureInput(name, "http://"+name+".example.com"))
	insertArchivedAlerts(testContext, fixture, createdEngine.ID, alertCount)
	return createdEngine
}

func TestDeleteLargeArchiveReturns202AndCompletes(testContext *testing.T) {
	fixture := newFixture(testContext)
	deletedEngine := newDeletableEngine(testContext, fixture, "edge-big", 8)

	if deleteError := fixture.repository.Delete(context.Background(), "edge-big"); deleteError != nil {
		testContext.Fatalf("delete: %v", deleteError)
	}
	fixture.repository.WaitPurges()

	if remaining := countRows(testContext, fixture, `SELECT count(*) FROM alert WHERE alert_engine_id = ?`, deletedEngine.ID); remaining != 0 {
		testContext.Errorf("%d alerts left", remaining)
	}
	if remaining := countRows(testContext, fixture, `SELECT count(*) FROM engine WHERE engine_id = ?`, deletedEngine.ID); remaining != 0 {
		testContext.Errorf("engine row left")
	}
}

func TestDeleteSurvivesRequestCancellation(testContext *testing.T) {
	fixture := newFixture(testContext)
	deletedEngine := newDeletableEngine(testContext, fixture, "edge-cancel", 7)
	requestContext, cancelRequest := context.WithCancel(context.Background())

	deleteError := fixture.repository.Delete(requestContext, "edge-cancel")
	cancelRequest()
	fixture.repository.WaitPurges()

	if deleteError != nil {
		testContext.Fatalf("delete: %v", deleteError)
	}
	if remaining := countRows(testContext, fixture, `SELECT count(*) FROM engine WHERE engine_id = ?`, deletedEngine.ID); remaining != 0 {
		testContext.Error("a cancelled request must not stop the purge")
	}
}

func TestDeletingEngineIsHiddenAndNotCollected(testContext *testing.T) {
	fixture := newFixture(testContext)
	server, _ := startTrackedEngine(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-hidden", server.URL))
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)
	if _, found := registry.Client("edge-hidden"); !found {
		testContext.Fatal("precondition: the engine must be registered")
	}

	markDeleting(testContext, fixture, "edge-hidden")
	mustReload(testContext, registry)

	engineList, listError := fixture.repository.List(context.Background())
	if listError != nil {
		testContext.Fatalf("list: %v", listError)
	}
	for _, listedEngine := range engineList {
		if listedEngine.Name == "edge-hidden" {
			testContext.Error("a deleting engine must not be listed")
		}
	}
	if _, found := registry.Client("edge-hidden"); found {
		testContext.Error("a deleting engine must leave the registry")
	}
	if _, getError := fixture.repository.Get(context.Background(), "edge-hidden"); !errors.Is(getError, ErrEngineNotFound) {
		testContext.Errorf("get: %v", getError)
	}
}

func TestDeletingEngineResumesAtStartup(testContext *testing.T) {
	fixture := newFixture(testContext)
	deletedEngine := newDeletableEngine(testContext, fixture, "edge-resume", 8)
	markDeleting(testContext, fixture, "edge-resume")

	fixture.repository.ResumeDeletions(context.Background())
	fixture.repository.WaitPurges()

	if remaining := countRows(testContext, fixture, `SELECT count(*) FROM engine WHERE engine_id = ?`, deletedEngine.ID); remaining != 0 {
		testContext.Error("a deleting engine left by a restart must be purged")
	}
	if remaining := countRows(testContext, fixture, `SELECT count(*) FROM alert WHERE alert_engine_id = ?`, deletedEngine.ID); remaining != 0 {
		testContext.Errorf("%d alerts left", remaining)
	}
}

func TestDeletingEngineRefusesUpdateAndTest(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-frozen", "http://edge-frozen.example.com"))
	markDeleting(testContext, fixture, "edge-frozen")
	registry := newTestRegistry(testContext, fixture, nil)

	_, updateError := fixture.repository.Update(context.Background(), "edge-frozen", Input{Enabled: boolPointer(false)})
	_, probeError := registry.Probe(context.Background(), "edge-frozen")
	deleteError := fixture.repository.Delete(context.Background(), "edge-frozen")

	for operation, operationError := range map[string]error{"update": updateError, "probe": probeError, "delete": deleteError} {
		if !errors.Is(operationError, ErrEngineNotFound) {
			testContext.Errorf("%s: %v", operation, operationError)
		}
	}
}

func TestNameReuseWhileDeletingIsRefusedUntilPurged(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-reuse", "http://edge-reuse.example.com"))
	markDeleting(testContext, fixture, "edge-reuse")

	_, refusedError := fixture.repository.Create(context.Background(), insecureInput("edge-reuse", "http://other.example.com"))
	fixture.repository.ResumeDeletions(context.Background())
	fixture.repository.WaitPurges()
	_, allowedError := fixture.repository.Create(context.Background(), insecureInput("edge-reuse", "http://other.example.com"))

	if !errors.Is(refusedError, ErrEngineExists) {
		testContext.Errorf("reuse while deleting: %v", refusedError)
	}
	if allowedError != nil {
		testContext.Errorf("reuse after purge: %v", allowedError)
	}
}
