package secrets

import (
	"context"
	"testing"
)

func markEngineDeletingLikeTheRepository(testContext *testing.T, fixture rotationFixture, engineID int64) {
	testContext.Helper()
	_, markError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_deleting_at = now(), engine_machine_password_sealed = '\x'::bytea,
		 engine_machine_password_key_id = 'deleted', engine_proxy_credential_sealed = NULL,
		 engine_proxy_credential_key_id = NULL WHERE engine_id = ?`, engineID)
	if markError != nil {
		testContext.Fatalf("mark deleting: %v", markError)
	}
}

func TestDeletingEngineDoesNotBreakKeyCheckNorRotation(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	engineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "edge-deleting", destinationPasswordAssociatedData, destinationCredentialAssociatedData)
	markEngineDeletingLikeTheRepository(testContext, fixture, engineID)

	checkError := CheckKeysAvailable(context.Background(), fixture.database, fixture.rotatingKeyring)
	dryRunReport, dryRunError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, true, 10)
	rotateReport, rotateError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, 10)

	if checkError != nil {
		testContext.Errorf("a deleting engine must not make the key check fail: %v", checkError)
	}
	if dryRunError != nil || rotateError != nil {
		testContext.Fatalf("rotate: %v / %v", dryRunError, rotateError)
	}
	for _, report := range []RotationReport{dryRunReport, rotateReport} {
		for _, columnReport := range report.Columns {
			if len(columnReport.UnreadableIDs) != 0 {
				testContext.Errorf("a deleting engine must not be reported unreadable: %+v", columnReport)
			}
		}
	}
}
