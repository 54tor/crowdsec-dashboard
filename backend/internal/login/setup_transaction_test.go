package login

import (
	"context"
	"errors"
	"testing"
	"time"

	"crowdsec-dashboard/internal/accounts"
)

// countRows reads one count(*) so the assertions below compare plain numbers.
func (fixture *loginFixture) countRows(testContext *testing.T, query string, arguments ...any) int {
	testContext.Helper()
	var rowCount int
	if queryError := fixture.database.NewRaw(query, arguments...).Scan(context.Background(), &rowCount); queryError != nil {
		testContext.Fatal(queryError)
	}
	return rowCount
}

const (
	secondFactorCountQuery = `SELECT count(*) FROM credential WHERE credential_account_id = ? AND credential_kind IN ('totp', 'webauthn')`
	sessionCountQuery      = `SELECT count(*) FROM session WHERE session_account_id = ?`
)

// TestCloseSecondFactorSetupRacesWithExpiry starts a setup inside the window
// and completes it after the deadline: the SQL recheck of the deadline must
// refuse the enrolment even though the pending login was granted in time.
func TestCloseSecondFactorSetupRacesWithExpiry(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	accountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, accountID, fixture.clock.Now().Add(time.Minute).Format(time.RFC3339Nano))
	beginResult := fixture.beginOrFail(testContext, "alice")
	prepareTOTPSetup(testContext, fixture, beginResult.PendingID)
	fixture.clock.Advance(2 * time.Minute)

	_, completeError := fixture.service.CompleteSetup(context.Background(), beginResult.PendingID, clientAddress)

	if !errors.Is(completeError, accounts.ErrSecondFactorSetupClosed) {
		testContext.Errorf("a setup completed after the deadline must be refused, got %v", completeError)
	}
	if factorCount := fixture.countRows(testContext, secondFactorCountQuery, accountID); factorCount != 0 {
		testContext.Errorf("no factor may be written after the deadline, found %d", factorCount)
	}
}

// TestEnrolmentRevokesSessionsInSameTransaction makes the session revocation
// fail: if it ran after the commit, the factors would already be stored.
func TestEnrolmentRevokesSessionsInSameTransaction(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	accountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, accountID, "infinity")
	if _, sessionError := fixture.sessions.Create(context.Background(), accountID); sessionError != nil {
		testContext.Fatal(sessionError)
	}
	beginResult := fixture.beginOrFail(testContext, "alice")
	prepareTOTPSetup(testContext, fixture, beginResult.PendingID)
	// The schema is this test's own (storetest.New): the trigger only exists here.
	if _, triggerError := fixture.database.ExecContext(context.Background(), `
		CREATE FUNCTION refuse_session_delete() RETURNS trigger LANGUAGE plpgsql AS
		  $$ BEGIN RAISE EXCEPTION 'session delete refused by test'; END $$;
		CREATE TRIGGER refuse_session_delete BEFORE DELETE ON session
		  FOR EACH ROW EXECUTE FUNCTION refuse_session_delete();`); triggerError != nil {
		testContext.Fatal(triggerError)
	}

	_, completeError := fixture.service.CompleteSetup(context.Background(), beginResult.PendingID, clientAddress)

	if completeError == nil {
		testContext.Fatal("CompleteSetup must fail when the sessions cannot be revoked")
	}
	if factorCount := fixture.countRows(testContext, secondFactorCountQuery, accountID); factorCount != 0 {
		testContext.Errorf("the factors must roll back with the failed revocation, found %d", factorCount)
	}
	if isAllowed, _ := fixture.accounts.SecondFactorSetupAllowed(context.Background(), accountID, fixture.clock.Now()); !isAllowed {
		testContext.Error("the setup window must stay open after the rollback")
	}
}

// TestRollbackKeepsSessionsAndFactorsConsistent fails the last write of the
// enrolment (recovery codes): the sessions revoked earlier in the same
// transaction must come back, and no factor may remain.
func TestRollbackKeepsSessionsAndFactorsConsistent(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	accountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, accountID, "infinity")
	if _, sessionError := fixture.sessions.Create(context.Background(), accountID); sessionError != nil {
		testContext.Fatal(sessionError)
	}
	beginResult := fixture.beginOrFail(testContext, "alice")
	prepareTOTPSetup(testContext, fixture, beginResult.PendingID)
	if _, alterError := fixture.database.ExecContext(context.Background(),
		`ALTER TABLE recovery_code ADD CONSTRAINT always_fail CHECK (false) NOT VALID`); alterError != nil {
		testContext.Fatal(alterError)
	}

	_, completeError := fixture.service.CompleteSetup(context.Background(), beginResult.PendingID, clientAddress)

	if completeError == nil {
		testContext.Fatal("CompleteSetup must fail when the recovery codes cannot be saved")
	}
	if sessionCount := fixture.countRows(testContext, sessionCountQuery, accountID); sessionCount != 1 {
		testContext.Errorf("the session must survive the rollback, found %d", sessionCount)
	}
	if factorCount := fixture.countRows(testContext, secondFactorCountQuery, accountID); factorCount != 0 {
		testContext.Errorf("no factor may survive the rollback, found %d", factorCount)
	}
}
