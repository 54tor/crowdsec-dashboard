package accounts

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	secondAdminName = "bob"
	readOnlyName    = "carol"
	unknownName     = "nobody"
)

// createOrFail creates an account through the management entry point, so every
// test account starts like a real one: password set, setup window open.
func createOrFail(testContext *testing.T, repository *Repository, accountName, role string) int64 {
	testContext.Helper()
	accountID, createError := repository.CreateAccount(context.Background(), accountName, validPassword, role, SecondFactorSetupWindow)
	if createError != nil {
		testContext.Fatalf("create %s: %v", accountName, createError)
	}
	return accountID
}

func execOrFail(testContext *testing.T, repository *Repository, query string, arguments ...any) {
	testContext.Helper()
	if _, execError := repository.database.ExecContext(context.Background(), query, arguments...); execError != nil {
		testContext.Fatal(execError)
	}
}

func countOrFail(testContext *testing.T, repository *Repository, query string, arguments ...any) int {
	testContext.Helper()
	var rowCount int
	if queryError := repository.database.NewRaw(query, arguments...).Scan(context.Background(), &rowCount); queryError != nil {
		testContext.Fatal(queryError)
	}
	return rowCount
}

func randomBytes(testContext *testing.T) []byte {
	testContext.Helper()
	generatedBytes := make([]byte, 32)
	if _, readError := rand.Read(generatedBytes); readError != nil {
		testContext.Fatal(readError)
	}
	return generatedBytes
}

// seedSecondFactorAndAccess gives an account what a reset or a deletion must
// remove: a TOTP and a passkey credential with its user handle, two recovery
// codes, one session, one active API token and one already revoked token.
func seedSecondFactorAndAccess(testContext *testing.T, repository *Repository, accountID int64) {
	testContext.Helper()
	execOrFail(testContext, repository,
		`INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', ?, 'key-1')`,
		accountID, randomBytes(testContext))
	execOrFail(testContext, repository,
		`INSERT INTO credential (credential_account_id, credential_kind, credential_webauthn_id, credential_webauthn_data) VALUES (?, 'webauthn', ?, '{}'::jsonb)`,
		accountID, randomBytes(testContext))
	execOrFail(testContext, repository, `UPDATE account SET account_webauthn_user_handle = ? WHERE account_id = ?`, randomBytes(testContext), accountID)
	for recoveryCodeNumber := 0; recoveryCodeNumber < 2; recoveryCodeNumber++ {
		execOrFail(testContext, repository,
			`INSERT INTO recovery_code (recovery_code_account_id, recovery_code_hash) VALUES (?, ?)`, accountID, randomBytes(testContext))
	}
	execOrFail(testContext, repository,
		`INSERT INTO session (session_token_hash, session_account_id, session_expires_at) VALUES (?, ?, now() + interval '1 hour')`,
		randomBytes(testContext), accountID)
	execOrFail(testContext, repository,
		`INSERT INTO api_token (api_token_account_id, api_token_name, api_token_hash, api_token_scope, api_token_expires_at)
		 VALUES (?, 'active', ?, 'read', now() + interval '30 days')`, accountID, randomBytes(testContext))
	execOrFail(testContext, repository,
		`INSERT INTO api_token (api_token_account_id, api_token_name, api_token_hash, api_token_scope, api_token_expires_at, api_token_revoked_at)
		 VALUES (?, 'old', ?, 'read', now() + interval '30 days', '2026-01-01T00:00:00Z')`, accountID, randomBytes(testContext))
}

const (
	secondFactorCountQuery = `SELECT count(*) FROM credential WHERE credential_account_id = ? AND credential_kind IN ('totp', 'webauthn')`
	recoveryCodeCountQuery = `SELECT count(*) FROM recovery_code WHERE recovery_code_account_id = ?`
	sessionCountQuery      = `SELECT count(*) FROM session WHERE session_account_id = ?`
	activeTokenCountQuery  = `SELECT count(*) FROM api_token WHERE api_token_account_id = ? AND api_token_revoked_at IS NULL`
	adminCountQuery        = `SELECT count(*) FROM account WHERE account_role = 'admin'`
)

func roleOf(testContext *testing.T, repository *Repository, accountName string) string {
	testContext.Helper()
	var accountRole string
	if queryError := repository.database.NewRaw(`SELECT account_role FROM account WHERE account_name = ?`, accountName).
		Scan(context.Background(), &accountRole); queryError != nil {
		testContext.Fatal(queryError)
	}
	return accountRole
}

func TestCreateAccountWithReadOnlyRole(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)

	accountID := createOrFail(testContext, repository, readOnlyName, auth.RoleReadOnly)

	if accountID == 0 || roleOf(testContext, repository, readOnlyName) != auth.RoleReadOnly {
		testContext.Errorf("expected a read_only account, got id %d role %s", accountID, roleOf(testContext, repository, readOnlyName))
	}
	if _, authenticateError := repository.Authenticate(context.Background(), readOnlyName, validPassword); authenticateError != nil {
		testContext.Errorf("the initial password must authenticate, got %v", authenticateError)
	}
}

func TestCreateAccountRefusesUnknownRole(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)

	_, createError := repository.CreateAccount(context.Background(), readOnlyName, validPassword, "superuser", SecondFactorSetupWindow)

	if !errors.Is(createError, ErrInvalidRole) {
		testContext.Errorf("expected ErrInvalidRole, got %v", createError)
	}
	if accountCount := countOrFail(testContext, repository, `SELECT count(*) FROM account`); accountCount != 0 {
		testContext.Errorf("no account may be created, found %d", accountCount)
	}
}

func TestCreateAccountAlwaysStartsInSecondFactorSetup(testContext *testing.T) {
	repository, clock := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, readOnlyName, auth.RoleReadOnly)
	ctx := context.Background()

	var setupUntil time.Time
	if queryError := repository.database.NewRaw(`SELECT account_second_factor_setup_until FROM account WHERE account_id = ?`, accountID).
		Scan(ctx, &setupUntil); queryError != nil {
		testContext.Fatal(queryError)
	}
	expectedDeadline := clock.Now().Add(72 * time.Hour)
	if !setupUntil.Equal(expectedDeadline) {
		testContext.Errorf("the setup window must end 72 h after creation (%v), got %v", expectedDeadline, setupUntil)
	}
	if factorCount := countOrFail(testContext, repository, secondFactorCountQuery, accountID); factorCount != 0 {
		testContext.Errorf("a created account has no second factor yet, found %d", factorCount)
	}
}

func TestChangeRoleRefusesDemotingLastAdmin(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	createOrFail(testContext, repository, readOnlyName, auth.RoleReadOnly)

	_, demoteError := repository.ChangeRole(context.Background(), validAccountName, auth.RoleReadOnly)

	if !errors.Is(demoteError, ErrLastAdmin) {
		testContext.Errorf("expected ErrLastAdmin, got %v", demoteError)
	}
	if accountRole := roleOf(testContext, repository, validAccountName); accountRole != auth.RoleAdmin {
		testContext.Errorf("the last admin must stay admin, got %s", accountRole)
	}
	if previousRole, promoteError := repository.ChangeRole(context.Background(), readOnlyName, auth.RoleAdmin); promoteError != nil || previousRole != auth.RoleReadOnly {
		testContext.Fatalf("promoting a read_only account must succeed and report read_only, got %q %v", previousRole, promoteError)
	}
	if _, demoteAfterPromotionError := repository.ChangeRole(context.Background(), validAccountName, auth.RoleReadOnly); demoteAfterPromotionError != nil {
		testContext.Errorf("with another admin the demotion must succeed, got %v", demoteAfterPromotionError)
	}
	if _, invalidRoleError := repository.ChangeRole(context.Background(), readOnlyName, "owner"); !errors.Is(invalidRoleError, ErrInvalidRole) {
		testContext.Errorf("expected ErrInvalidRole, got %v", invalidRoleError)
	}
}

func TestDeleteRefusesLastAdmin(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	createOrFail(testContext, repository, readOnlyName, auth.RoleReadOnly)

	deleteError := repository.Delete(context.Background(), validAccountName)

	if !errors.Is(deleteError, ErrLastAdmin) {
		testContext.Errorf("expected ErrLastAdmin, got %v", deleteError)
	}
	if adminCount := countOrFail(testContext, repository, adminCountQuery); adminCount != 1 {
		testContext.Errorf("the last admin must remain, found %d admins", adminCount)
	}
	if deleteReadOnlyError := repository.Delete(context.Background(), readOnlyName); deleteReadOnlyError != nil {
		testContext.Errorf("deleting a read_only account must succeed, got %v", deleteReadOnlyError)
	}
}

// TestConcurrentMutualDemotionKeepsOneAdmin starts both demotions at the same
// instant on real PostgreSQL connections: only the advisory lock serialises
// the two "count the other admins" checks.
func TestConcurrentMutualDemotionKeepsOneAdmin(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	createOrFail(testContext, repository, secondAdminName, auth.RoleAdmin)
	targetNames := []string{validAccountName, secondAdminName}
	demotionErrors := make([]error, len(targetNames))
	var waitGroup sync.WaitGroup
	startSignal := make(chan struct{})

	for targetIndex, targetName := range targetNames {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-startSignal
			_, demotionErrors[targetIndex] = repository.ChangeRole(context.Background(), targetName, auth.RoleReadOnly)
		}()
	}
	close(startSignal)
	waitGroup.Wait()

	successCount, lastAdminCount := 0, 0
	for _, demotionError := range demotionErrors {
		switch {
		case demotionError == nil:
			successCount++
		case errors.Is(demotionError, ErrLastAdmin):
			lastAdminCount++
		}
	}
	if successCount != 1 || lastAdminCount != 1 {
		testContext.Errorf("expected one demotion and one ErrLastAdmin, got %v", demotionErrors)
	}
	if adminCount := countOrFail(testContext, repository, adminCountQuery); adminCount != 1 {
		testContext.Errorf("exactly one admin must remain, found %d", adminCount)
	}
}

func TestDeleteCascadesSessionsAndTokens(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	readOnlyID := createOrFail(testContext, repository, readOnlyName, auth.RoleReadOnly)
	seedSecondFactorAndAccess(testContext, repository, readOnlyID)

	if deleteError := repository.Delete(context.Background(), readOnlyName); deleteError != nil {
		testContext.Fatal(deleteError)
	}

	for _, ownedRowsQuery := range []string{
		`SELECT count(*) FROM account WHERE account_id = ?`,
		`SELECT count(*) FROM credential WHERE credential_account_id = ?`,
		recoveryCodeCountQuery,
		sessionCountQuery,
		`SELECT count(*) FROM api_token WHERE api_token_account_id = ?`,
	} {
		if rowCount := countOrFail(testContext, repository, ownedRowsQuery, readOnlyID); rowCount != 0 {
			testContext.Errorf("%s: expected no row after deletion, found %d", ownedRowsQuery, rowCount)
		}
	}
}

func TestResetSecondFactorRemovesFactorsRecoveryCodesAndSessions(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	seedSecondFactorAndAccess(testContext, repository, accountID)

	if resetError := repository.ResetSecondFactor(context.Background(), validAccountName); resetError != nil {
		testContext.Fatal(resetError)
	}

	for _, removedRowsQuery := range []string{secondFactorCountQuery, recoveryCodeCountQuery, sessionCountQuery} {
		if rowCount := countOrFail(testContext, repository, removedRowsQuery, accountID); rowCount != 0 {
			testContext.Errorf("%s: expected no row after the reset, found %d", removedRowsQuery, rowCount)
		}
	}
	if _, authenticateError := repository.Authenticate(context.Background(), validAccountName, validPassword); authenticateError != nil {
		testContext.Errorf("the password must stay valid after the reset, got %v", authenticateError)
	}
}

func TestResetSecondFactorRevokesTokens(testContext *testing.T) {
	repository, clock := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	seedSecondFactorAndAccess(testContext, repository, accountID)

	if resetError := repository.ResetSecondFactor(context.Background(), validAccountName); resetError != nil {
		testContext.Fatal(resetError)
	}

	if activeTokenCount := countOrFail(testContext, repository, activeTokenCountQuery, accountID); activeTokenCount != 0 {
		testContext.Errorf("every token must be revoked, %d still active", activeTokenCount)
	}
	if revokedNowCount := countOrFail(testContext, repository,
		`SELECT count(*) FROM api_token WHERE api_token_account_id = ? AND api_token_revoked_at = ?`, accountID, clock.Now()); revokedNowCount != 1 {
		testContext.Errorf("only the active token is stamped with the reset time, got %d", revokedNowCount)
	}
}

func TestResetSecondFactorOpensSetupWindow(testContext *testing.T) {
	repository, clock := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	seedSecondFactorAndAccess(testContext, repository, accountID)
	execOrFail(testContext, repository, `UPDATE account SET account_second_factor_setup_until = NULL WHERE account_id = ?`, accountID)
	clock.Advance(time.Hour)

	if resetError := repository.ResetSecondFactor(context.Background(), validAccountName); resetError != nil {
		testContext.Fatal(resetError)
	}

	ctx := context.Background()
	deadline := clock.Now().Add(SecondFactorSetupWindow)
	beforeDeadline, beforeError := repository.SecondFactorSetupAllowed(ctx, accountID, deadline.Add(-time.Second))
	atDeadline, atError := repository.SecondFactorSetupAllowed(ctx, accountID, deadline)
	if beforeError != nil || atError != nil || !beforeDeadline || atDeadline {
		testContext.Errorf("the window must be open until reset time + 72 h, got %v/%v (%v, %v)", beforeDeadline, atDeadline, beforeError, atError)
	}
}

func TestResetSecondFactorClearsWebAuthnUserHandle(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	seedSecondFactorAndAccess(testContext, repository, accountID)

	if resetError := repository.ResetSecondFactor(context.Background(), validAccountName); resetError != nil {
		testContext.Fatal(resetError)
	}

	if handleCount := countOrFail(testContext, repository,
		`SELECT count(*) FROM account WHERE account_id = ? AND account_webauthn_user_handle IS NOT NULL`, accountID); handleCount != 0 {
		testContext.Error("the passkey user handle must be cleared so a new passkey can be enrolled")
	}
}

// documentedResetProcedure is the SQL of docs/operations.md, "Resetting a lost
// factor", verbatim except for the account name placeholder.
var documentedResetProcedure = []string{
	`DELETE FROM credential WHERE credential_kind IN ('totp', 'webauthn')
	   AND credential_account_id = (SELECT account_id FROM account WHERE account_name = ?)`,
	`DELETE FROM recovery_code WHERE recovery_code_account_id =
	  (SELECT account_id FROM account WHERE account_name = ?)`,
	`UPDATE account SET account_webauthn_user_handle = NULL WHERE account_name = ?`,
	`UPDATE account SET account_second_factor_setup_until = now() + interval '1 day'
	 WHERE account_name = ?`,
}

type secondFactorState struct {
	CredentialKinds    string `bun:"credential_kinds"`
	RecoveryCodeCount  int    `bun:"recovery_code_count"`
	HasUserHandle      bool   `bun:"has_user_handle"`
	HasSetupWindow     bool   `bun:"has_setup_window"`
	FailedFactorCount  int    `bun:"failed_factor_count"`
	HasLock            bool   `bun:"has_lock"`
	PasswordCredential int    `bun:"password_credential"`
}

func secondFactorStateOf(testContext *testing.T, repository *Repository, accountID int64) secondFactorState {
	testContext.Helper()
	var state secondFactorState
	queryError := repository.database.NewRaw(`
		SELECT
		  COALESCE((SELECT string_agg(credential_kind, ',' ORDER BY credential_kind) FROM credential WHERE credential_account_id = account_id), '') AS credential_kinds,
		  (SELECT count(*) FROM recovery_code WHERE recovery_code_account_id = account_id) AS recovery_code_count,
		  account_webauthn_user_handle IS NOT NULL AS has_user_handle,
		  account_second_factor_setup_until IS NOT NULL AS has_setup_window,
		  account_failed_second_factor_count AS failed_factor_count,
		  account_locked_until IS NOT NULL AS has_lock,
		  (SELECT count(*) FROM credential WHERE credential_account_id = account_id AND credential_kind = 'password') AS password_credential
		FROM account WHERE account_id = ?`, accountID).Scan(context.Background(), &state)
	if queryError != nil {
		testContext.Fatal(queryError)
	}
	return state
}

// TestResetSecondFactorMatchesDocumentedSQLProcedure resets one account with
// the documented SQL and an identical one with ResetSecondFactor: the factor
// rows, recovery codes, handle, window and lockout must end up alike. The code
// additionally revokes sessions and tokens, checked by the tests above.
func TestResetSecondFactorMatchesDocumentedSQLProcedure(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	documentedAccountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	codedAccountID := createOrFail(testContext, repository, secondAdminName, auth.RoleAdmin)
	for _, accountID := range []int64{documentedAccountID, codedAccountID} {
		seedSecondFactorAndAccess(testContext, repository, accountID)
		execOrFail(testContext, repository,
			`UPDATE account SET account_failed_second_factor_count = 3, account_locked_until = '2026-10-31T13:00:00Z' WHERE account_id = ?`, accountID)
	}

	for _, documentedStatement := range documentedResetProcedure {
		execOrFail(testContext, repository, documentedStatement, validAccountName)
	}
	if resetError := repository.ResetSecondFactor(context.Background(), secondAdminName); resetError != nil {
		testContext.Fatal(resetError)
	}

	documentedState := secondFactorStateOf(testContext, repository, documentedAccountID)
	codedState := secondFactorStateOf(testContext, repository, codedAccountID)
	if documentedState != codedState {
		testContext.Errorf("the reset must match the documented procedure:\n documented %+v\n code       %+v", documentedState, codedState)
	}
}

// TestResetSecondFactorRevokesSessionsAtomically makes the last statement of
// the reset (token revocation) fail: nothing done before it may stay applied.
func TestResetSecondFactorRevokesSessionsAtomically(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	seedSecondFactorAndAccess(testContext, repository, accountID)
	stateBefore := secondFactorStateOf(testContext, repository, accountID)
	// The schema is this test's own (storetest.New): the trigger only exists here.
	execOrFail(testContext, repository, `
		CREATE FUNCTION refuse_token_update() RETURNS trigger LANGUAGE plpgsql AS
		  $$ BEGIN RAISE EXCEPTION 'token update refused by test'; END $$;
		CREATE TRIGGER refuse_token_update BEFORE UPDATE ON api_token
		  FOR EACH ROW EXECUTE FUNCTION refuse_token_update();`)

	resetError := repository.ResetSecondFactor(context.Background(), validAccountName)

	if resetError == nil {
		testContext.Fatal("the reset must fail when the tokens cannot be revoked")
	}
	if stateAfter := secondFactorStateOf(testContext, repository, accountID); stateAfter != stateBefore {
		testContext.Errorf("the failed reset must roll back, before %+v after %+v", stateBefore, stateAfter)
	}
	if sessionCount := countOrFail(testContext, repository, sessionCountQuery, accountID); sessionCount != 1 {
		testContext.Errorf("the session must survive the rollback, found %d", sessionCount)
	}
}

func TestRevokeSessionsRevokesTokens(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	seedSecondFactorAndAccess(testContext, repository, accountID)

	if revokeError := repository.RevokeSessionsAndTokens(context.Background(), validAccountName); revokeError != nil {
		testContext.Fatal(revokeError)
	}

	if sessionCount := countOrFail(testContext, repository, sessionCountQuery, accountID); sessionCount != 0 {
		testContext.Errorf("every session must be removed, found %d", sessionCount)
	}
	if activeTokenCount := countOrFail(testContext, repository, activeTokenCountQuery, accountID); activeTokenCount != 0 {
		testContext.Errorf("every token must be revoked, %d still active", activeTokenCount)
	}
	if factorCount := countOrFail(testContext, repository, secondFactorCountQuery, accountID); factorCount != 2 {
		testContext.Errorf("revoking sessions must keep the factors, found %d", factorCount)
	}
}

func TestListReportsLockedAndSecondFactorState(testContext *testing.T) {
	repository, clock := newRepositoryWithClock(testContext)
	enrolledID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	lockedID := createOrFail(testContext, repository, secondAdminName, auth.RoleAdmin)
	createOrFail(testContext, repository, readOnlyName, auth.RoleReadOnly)
	seedSecondFactorAndAccess(testContext, repository, enrolledID)
	execOrFail(testContext, repository, `UPDATE account SET account_locked_until = ? WHERE account_id = ?`, clock.Now().Add(time.Minute), lockedID)
	execOrFail(testContext, repository, `UPDATE account SET account_locked_until = ? WHERE account_id = ?`, clock.Now().Add(-time.Minute), enrolledID)
	factors := secondfactor.NewRepository(repository.database, nil)

	summaries, listError := repository.List(context.Background())

	if listError != nil || len(summaries) != 3 {
		testContext.Fatalf("expected three accounts, got %+v (%v)", summaries, listError)
	}
	expectedLocked := map[string]bool{validAccountName: false, secondAdminName: true, readOnlyName: false}
	for _, summary := range summaries {
		enrolledMethods, methodsError := factors.Methods(context.Background(), summary.AccountID)
		if methodsError != nil {
			testContext.Fatal(methodsError)
		}
		if summary.SecondFactorEnrolled != (len(enrolledMethods) > 0) {
			testContext.Errorf("%s: SecondFactorEnrolled %v disagrees with Methods %v", summary.AccountName, summary.SecondFactorEnrolled, enrolledMethods)
		}
		if summary.Locked != expectedLocked[summary.AccountName] {
			testContext.Errorf("%s: expected Locked %v, got %v", summary.AccountName, expectedLocked[summary.AccountName], summary.Locked)
		}
		if summary.CreatedAt.IsZero() || summary.AccountRole == "" {
			testContext.Errorf("%s: incomplete summary %+v", summary.AccountName, summary)
		}
	}
	if summaries[0].AccountName != validAccountName || summaries[2].AccountName != readOnlyName {
		testContext.Errorf("accounts must be listed by name, got %+v", summaries)
	}
}

func TestUnlockClearsCounterAndLock(testContext *testing.T) {
	repository, clock := newRepositoryWithClock(testContext)
	accountID := createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	execOrFail(testContext, repository,
		`UPDATE account SET account_failed_second_factor_count = 5, account_locked_until = ? WHERE account_id = ?`, clock.Now().Add(time.Hour), accountID)

	if unlockError := repository.Unlock(context.Background(), validAccountName); unlockError != nil {
		testContext.Fatal(unlockError)
	}

	state := secondFactorStateOf(testContext, repository, accountID)
	if state.FailedFactorCount != 0 || state.HasLock {
		testContext.Errorf("expected the counter at 0 and no lock, got %+v", state)
	}
}

func TestUnknownAccountReturnsErrAccountNotFound(testContext *testing.T) {
	repository, _ := newRepositoryWithClock(testContext)
	createOrFail(testContext, repository, validAccountName, auth.RoleAdmin)
	ctx := context.Background()
	_, accountIDError := repository.AccountID(ctx, unknownName)

	_, changeToAdminError := repository.ChangeRole(ctx, unknownName, auth.RoleAdmin)
	_, changeToReadOnlyError := repository.ChangeRole(ctx, unknownName, auth.RoleReadOnly)
	operationErrors := map[string]error{
		"ChangeRole":              changeToAdminError,
		"ChangeRole to read_only": changeToReadOnlyError,
		"Delete":                  repository.Delete(ctx, unknownName),
		"ResetSecondFactor":       repository.ResetSecondFactor(ctx, unknownName),
		"RevokeSessionsAndTokens": repository.RevokeSessionsAndTokens(ctx, unknownName),
		"Unlock":                  repository.Unlock(ctx, unknownName),
		"AccountID":               accountIDError,
	}

	for operationName, operationError := range operationErrors {
		if !errors.Is(operationError, ErrAccountNotFound) {
			testContext.Errorf("%s: expected ErrAccountNotFound, got %v", operationName, operationError)
		}
	}
	if knownAccountID, knownError := repository.AccountID(ctx, validAccountName); knownError != nil || knownAccountID == 0 {
		testContext.Errorf("AccountID of a known account: got %d (%v)", knownAccountID, knownError)
	}
}
