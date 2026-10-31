package accounts

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"crowdsec-dashboard/internal/secondfactor"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store/storetest"
)

const (
	enrollmentAccountName = "first-admin"
	enrollmentPassword    = "a long enough password"
)

// confirmedEnrollment is what the operator saw while enrolling the second factor:
// the TOTP secret, the code that confirmed it, and the recovery codes shown once.
type confirmedEnrollment struct {
	secret        string
	confirmedCode string
	confirmedAt   time.Time
	recoveryCodes []string
}

func factorRepositoryFor(testContext *testing.T, repository *Repository) *secondfactor.Repository {
	testContext.Helper()
	keyring, keyringError := secrets.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if keyringError != nil {
		testContext.Fatal(keyringError)
	}
	return secondfactor.NewRepository(repository.database, keyring)
}

func newEnrollmentFor(testContext *testing.T, repository *Repository) *Enrollment {
	testContext.Helper()
	return NewEnrollment(repository, factorRepositoryFor(testContext, repository))
}

func newEnrollment(testContext *testing.T) (*Enrollment, *Repository) {
	testContext.Helper()
	repository := NewRepository(storetest.New(testContext))
	return newEnrollmentFor(testContext, repository), repository
}

func openToken(testContext *testing.T, enrollment *Enrollment) string {
	testContext.Helper()
	token, opened, openError := enrollment.Open(context.Background())
	if openError != nil || !opened || token == "" {
		testContext.Fatalf("expected an opened enrollment, got opened=%v error=%v", opened, openError)
	}
	return token
}

func countAccounts(testContext *testing.T, repository *Repository) int {
	testContext.Helper()
	accountCount, countError := repository.Count(context.Background())
	if countError != nil {
		testContext.Fatal(countError)
	}
	return accountCount
}

// confirmTOTPOnPendingState drives the factor steps of an already started
// enrollment: begin TOTP, confirm it with the current code, generate recovery codes.
func confirmTOTPOnPendingState(testContext *testing.T, enrollment *Enrollment, token string) confirmedEnrollment {
	testContext.Helper()
	setup, accountName, setupError := enrollment.Setup(token)
	if setupError != nil {
		testContext.Fatalf("setup: %v", setupError)
	}
	totpEnrollment, beginError := setup.BeginTOTP(accountName)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	confirmedAt := time.Now()
	confirmedCode, codeError := totp.GenerateCode(totpEnrollment.Secret, confirmedAt)
	if codeError != nil {
		testContext.Fatal(codeError)
	}
	if confirmError := setup.ConfirmTOTP(confirmedCode, confirmedAt); confirmError != nil {
		testContext.Fatalf("confirm totp: %v", confirmError)
	}
	recoveryCodes, codesError := setup.RecoveryCodes()
	if codesError != nil {
		testContext.Fatal(codesError)
	}
	return confirmedEnrollment{secret: totpEnrollment.Secret, confirmedCode: confirmedCode, confirmedAt: confirmedAt, recoveryCodes: recoveryCodes}
}

// startWithConfirmedTOTP replaces the lot 1 single-call Complete: the account step,
// then a confirmed TOTP factor and generated recovery codes, ready for Complete.
func startWithConfirmedTOTP(testContext *testing.T, enrollment *Enrollment, token, accountName string) confirmedEnrollment {
	testContext.Helper()
	if startError := enrollment.Start(context.Background(), token, accountName, enrollmentPassword); startError != nil {
		testContext.Fatalf("start: %v", startError)
	}
	return confirmTOTPOnPendingState(testContext, enrollment, token)
}

func TestOpenReturnsTokenOnEmptyDatabase(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)

	token := openToken(testContext, enrollment)

	if len(token) != 43 {
		testContext.Errorf("expected a 43 character base64url token, got %d characters", len(token))
	}
	isRequired, requiredError := enrollment.Required(context.Background())
	if requiredError != nil || !isRequired {
		testContext.Errorf("expected enrollment required, got %v %v", isRequired, requiredError)
	}
}

func TestOpenReturnsNoTokenWhenAccountExists(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	enrollment := newEnrollmentFor(testContext, repository)

	token, opened, openError := enrollment.Open(context.Background())

	if openError != nil || opened || token != "" {
		testContext.Errorf("expected no token, got %q opened=%v error=%v", token, opened, openError)
	}
	isRequired, _ := enrollment.Required(context.Background())
	if isRequired {
		testContext.Error("enrollment must not be required when an account exists")
	}
}

func TestCompleteCreatesAdminAndAuthenticates(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)

	createdIdentity, completeError := enrollment.Complete(context.Background(), token)

	if completeError != nil {
		testContext.Fatal(completeError)
	}
	if createdIdentity.AccountName != enrollmentAccountName || createdIdentity.AccountRole != roleAdmin {
		testContext.Errorf("unexpected identity %+v", createdIdentity)
	}
	authenticatedIdentity, authenticateError := repository.Authenticate(context.Background(), enrollmentAccountName, enrollmentPassword)
	if authenticateError != nil || authenticatedIdentity.AccountID != createdIdentity.AccountID {
		testContext.Errorf("authenticate failed: %+v %v", authenticatedIdentity, authenticateError)
	}
	secondStartError := enrollment.Start(context.Background(), token, "second-admin", enrollmentPassword)
	if !errors.Is(secondStartError, ErrEnrollmentClosed) {
		testContext.Errorf("token must be erased after success, got %v", secondStartError)
	}
	if _, secondCompleteError := enrollment.Complete(context.Background(), token); !errors.Is(secondCompleteError, ErrEnrollmentClosed) {
		testContext.Errorf("complete must be closed after success, got %v", secondCompleteError)
	}
}

func TestStartRejectsWrongToken(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	openToken(testContext, enrollment)

	startError := enrollment.Start(context.Background(), "not-the-token", enrollmentAccountName, enrollmentPassword)

	if !errors.Is(startError, ErrEnrollmentToken) {
		testContext.Errorf("expected ErrEnrollmentToken, got %v", startError)
	}
	if accountCount := countAccounts(testContext, repository); accountCount != 0 {
		testContext.Errorf("expected no account, got %d", accountCount)
	}
}

func TestCompleteRejectsWrongToken(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)

	_, completeError := enrollment.Complete(context.Background(), "not-the-token")

	if !errors.Is(completeError, ErrEnrollmentToken) {
		testContext.Errorf("expected ErrEnrollmentToken, got %v", completeError)
	}
	if accountCount := countAccounts(testContext, repository); accountCount != 0 {
		testContext.Errorf("expected no account, got %d", accountCount)
	}
	if _, _, setupError := enrollment.Setup("not-the-token"); !errors.Is(setupError, ErrEnrollmentToken) {
		testContext.Errorf("setup with a wrong token: expected ErrEnrollmentToken, got %v", setupError)
	}
}

func TestStartWithoutOpenIsClosed(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)

	startError := enrollment.Start(context.Background(), "anything", enrollmentAccountName, enrollmentPassword)

	if !errors.Is(startError, ErrEnrollmentClosed) {
		testContext.Errorf("expected ErrEnrollmentClosed, got %v", startError)
	}
	if _, _, setupError := enrollment.Setup("anything"); !errors.Is(setupError, ErrEnrollmentClosed) {
		testContext.Errorf("setup without open: expected ErrEnrollmentClosed, got %v", setupError)
	}
}

func TestCompleteIsClosedAfterFirstAccount(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)
	passwordHash, hashError := HashPassword(validPassword)
	if hashError != nil {
		testContext.Fatal(hashError)
	}
	if _, createError := repository.CreateWithPasswordHash(context.Background(), validAccountName, passwordHash, roleAdmin); createError != nil {
		testContext.Fatal(createError)
	}

	_, completeError := enrollment.Complete(context.Background(), token)

	if !errors.Is(completeError, ErrEnrollmentClosed) {
		testContext.Errorf("expected ErrEnrollmentClosed, got %v", completeError)
	}
	if accountCount := countAccounts(testContext, repository); accountCount != 1 {
		testContext.Errorf("expected one account, got %d", accountCount)
	}
}

func TestCompleteTwiceConcurrentlyCreatesOneAccount(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)

	const concurrentCompletions = 2
	completionErrors := make([]error, concurrentCompletions)
	var waitGroup sync.WaitGroup
	startSignal := make(chan struct{})
	for completionIndex := 0; completionIndex < concurrentCompletions; completionIndex++ {
		waitGroup.Add(1)
		go func(completionIndex int) {
			defer waitGroup.Done()
			<-startSignal
			_, completionErrors[completionIndex] = enrollment.Complete(context.Background(), token)
		}(completionIndex)
	}
	close(startSignal)
	waitGroup.Wait()

	successCount, closedCount := 0, 0
	for _, completionError := range completionErrors {
		switch {
		case completionError == nil:
			successCount++
		case errors.Is(completionError, ErrEnrollmentClosed):
			closedCount++
		default:
			testContext.Errorf("unexpected error %v", completionError)
		}
	}
	if successCount != 1 || closedCount != 1 {
		testContext.Errorf("expected one success and one closed, got %d and %d", successCount, closedCount)
	}
	if accountCount := countAccounts(testContext, repository); accountCount != 1 {
		testContext.Errorf("expected one account, got %d", accountCount)
	}
}

func TestConcurrentCompletionsWithSeparateInstancesCreateOneAccount(testContext *testing.T) {
	repository := NewRepository(storetest.New(testContext))
	firstEnrollment := newEnrollmentFor(testContext, repository)
	secondEnrollment := newEnrollmentFor(testContext, repository)
	firstToken := openToken(testContext, firstEnrollment)
	secondToken := openToken(testContext, secondEnrollment)
	startWithConfirmedTOTP(testContext, firstEnrollment, firstToken, "first-admin")
	startWithConfirmedTOTP(testContext, secondEnrollment, secondToken, "second-admin")

	var waitGroup sync.WaitGroup
	completionErrors := make([]error, 2)
	startSignal := make(chan struct{})
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-startSignal
		_, completionErrors[0] = firstEnrollment.Complete(context.Background(), firstToken)
	}()
	go func() {
		defer waitGroup.Done()
		<-startSignal
		_, completionErrors[1] = secondEnrollment.Complete(context.Background(), secondToken)
	}()
	close(startSignal)
	waitGroup.Wait()

	if accountCount := countAccounts(testContext, repository); accountCount != 1 {
		testContext.Errorf("expected one account, got %d (%v)", accountCount, completionErrors)
	}
	closedCount := 0
	for _, completionError := range completionErrors {
		if errors.Is(completionError, ErrEnrollmentClosed) {
			closedCount++
		}
	}
	if closedCount != 1 {
		testContext.Errorf("expected exactly one ErrEnrollmentClosed, got %v", completionErrors)
	}
}

func TestReopenAfterRestartInvalidatesPreviousToken(testContext *testing.T) {
	repository := NewRepository(storetest.New(testContext))
	firstEnrollment := newEnrollmentFor(testContext, repository)
	previousToken := openToken(testContext, firstEnrollment)
	secondEnrollment := newEnrollmentFor(testContext, repository)
	newToken := openToken(testContext, secondEnrollment)

	if newToken == previousToken {
		testContext.Fatal("a reopened enrollment must generate a different token")
	}
	previousTokenError := secondEnrollment.Start(context.Background(), previousToken, enrollmentAccountName, enrollmentPassword)
	if !errors.Is(previousTokenError, ErrEnrollmentToken) {
		testContext.Errorf("expected ErrEnrollmentToken for the previous token, got %v", previousTokenError)
	}
	startWithConfirmedTOTP(testContext, secondEnrollment, newToken, enrollmentAccountName)
	if _, newTokenError := secondEnrollment.Complete(context.Background(), newToken); newTokenError != nil {
		testContext.Errorf("new token must work, got %v", newTokenError)
	}
}

func TestReopeningTheSameInstanceInvalidatesItsPreviousToken(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)
	previousToken := openToken(testContext, enrollment)
	openToken(testContext, enrollment)

	startError := enrollment.Start(context.Background(), previousToken, enrollmentAccountName, enrollmentPassword)

	if !errors.Is(startError, ErrEnrollmentToken) {
		testContext.Errorf("expected ErrEnrollmentToken, got %v", startError)
	}
}

func TestReopeningDropsThePendingState(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)
	previousToken := openToken(testContext, enrollment)
	startWithConfirmedTOTP(testContext, enrollment, previousToken, enrollmentAccountName)
	newToken := openToken(testContext, enrollment)

	if _, _, setupError := enrollment.Setup(newToken); !errors.Is(setupError, ErrEnrollmentNotStarted) {
		testContext.Errorf("a new token must not inherit the previous pending state, got %v", setupError)
	}
}

func TestStartRejectsInvalidAccountNameAndPassword(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)

	nameError := enrollment.Start(context.Background(), token, "Bad Name!", enrollmentPassword)
	passwordError := enrollment.Start(context.Background(), token, enrollmentAccountName, "short")

	if !errors.Is(nameError, ErrInvalidAccountName) {
		testContext.Errorf("expected ErrInvalidAccountName, got %v", nameError)
	}
	if !errors.Is(passwordError, ErrPasswordLength) {
		testContext.Errorf("expected ErrPasswordLength, got %v", passwordError)
	}
	if _, _, setupError := enrollment.Setup(token); !errors.Is(setupError, ErrEnrollmentNotStarted) {
		testContext.Errorf("a rejected start must not create a pending state, got %v", setupError)
	}
	if accountCount := countAccounts(testContext, repository); accountCount != 0 {
		testContext.Errorf("expected no account, got %d", accountCount)
	}
	startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)
	if _, retryError := enrollment.Complete(context.Background(), token); retryError != nil {
		testContext.Errorf("token must survive validation failures, got %v", retryError)
	}
}

func TestErrorsNeverContainTokenOrPassword(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)
	token := openToken(testContext, enrollment)

	wrongTokenError := enrollment.Start(context.Background(), "wrong-token-value", enrollmentAccountName, enrollmentPassword)
	shortPasswordError := enrollment.Start(context.Background(), token, enrollmentAccountName, "short")
	_, notStartedError := enrollment.Complete(context.Background(), token)
	_, wrongCompleteTokenError := enrollment.Complete(context.Background(), "wrong-token-value")
	if startError := enrollment.Start(context.Background(), token, enrollmentAccountName, enrollmentPassword); startError != nil {
		testContext.Fatal(startError)
	}
	_, incompleteError := enrollment.Complete(context.Background(), token)

	for _, observedError := range []error{wrongTokenError, shortPasswordError, notStartedError, wrongCompleteTokenError, incompleteError} {
		if observedError == nil {
			testContext.Fatal("every call above must fail")
		}
		message := observedError.Error()
		for _, secret := range []string{token, "wrong-token-value", enrollmentPassword} {
			if strings.Contains(message, secret) {
				testContext.Errorf("error %q contains a secret", message)
			}
		}
	}
}

func TestRequiredAnswersFromMemoryAndFollowsTheTokenLifecycle(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)

	requiredBeforeOpen, _ := enrollment.Required(context.Background())
	if requiredBeforeOpen {
		testContext.Error("enrollment must not be required before Open, even on an empty database")
	}
	token := openToken(testContext, enrollment)
	requiredAfterOpen, _ := enrollment.Required(context.Background())
	if !requiredAfterOpen {
		testContext.Error("enrollment must be required while a token is open")
	}
	startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)
	requiredAfterStart, _ := enrollment.Required(context.Background())
	if !requiredAfterStart {
		testContext.Error("enrollment must stay required until Complete")
	}
	if _, completeError := enrollment.Complete(context.Background(), token); completeError != nil {
		testContext.Fatal(completeError)
	}
	requiredAfterComplete, requiredError := enrollment.Required(context.Background())
	if requiredError != nil || requiredAfterComplete {
		testContext.Errorf("enrollment must be closed after Complete, got %v %v", requiredAfterComplete, requiredError)
	}
}

func TestStartDoesNotCreateAccount(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)

	if startError := enrollment.Start(context.Background(), token, enrollmentAccountName, enrollmentPassword); startError != nil {
		testContext.Fatal(startError)
	}

	if accountCount := countAccounts(testContext, repository); accountCount != 0 {
		testContext.Errorf("the account step must not create the account, got %d", accountCount)
	}
	isRequired, _ := enrollment.Required(context.Background())
	if !isRequired {
		testContext.Error("enrollment must stay required after Start")
	}
	_, accountName, setupError := enrollment.Setup(token)
	if setupError != nil || accountName != enrollmentAccountName {
		testContext.Errorf("expected the pending account name, got %q %v", accountName, setupError)
	}
}

func TestCompleteRefusesWithoutConfirmedFactor(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)

	_, notStartedError := enrollment.Complete(context.Background(), token)
	if !errors.Is(notStartedError, ErrEnrollmentNotStarted) {
		testContext.Errorf("expected ErrEnrollmentNotStarted, got %v", notStartedError)
	}
	if startError := enrollment.Start(context.Background(), token, enrollmentAccountName, enrollmentPassword); startError != nil {
		testContext.Fatal(startError)
	}
	setup, accountName, _ := enrollment.Setup(token)
	if _, beginError := setup.BeginTOTP(accountName); beginError != nil {
		testContext.Fatal(beginError)
	}

	_, unconfirmedError := enrollment.Complete(context.Background(), token)

	if !errors.Is(unconfirmedError, ErrSecondFactorIncomplete) {
		testContext.Errorf("expected ErrSecondFactorIncomplete before confirmation, got %v", unconfirmedError)
	}
	confirmTOTPOnPendingState(testContext, enrollment, token)
	if accountCount := countAccounts(testContext, repository); accountCount != 0 {
		testContext.Errorf("expected no account before Complete, got %d", accountCount)
	}
	if _, completeError := enrollment.Complete(context.Background(), token); completeError != nil {
		testContext.Errorf("the window must stay open after a refused Complete, got %v", completeError)
	}
}

func TestCompleteRefusesConfirmedFactorWithoutRecoveryCodes(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	if startError := enrollment.Start(context.Background(), token, enrollmentAccountName, enrollmentPassword); startError != nil {
		testContext.Fatal(startError)
	}
	setup, accountName, _ := enrollment.Setup(token)
	totpEnrollment, _ := setup.BeginTOTP(accountName)
	confirmedCode, _ := totp.GenerateCode(totpEnrollment.Secret, time.Now())
	if confirmError := setup.ConfirmTOTP(confirmedCode, time.Now()); confirmError != nil {
		testContext.Fatal(confirmError)
	}

	_, completeError := enrollment.Complete(context.Background(), token)

	if !errors.Is(completeError, ErrSecondFactorIncomplete) {
		testContext.Errorf("recovery codes must be shown before Complete, got %v", completeError)
	}
}

func TestCompleteCreatesAccountWithPasswordTOTPAndRecoveryCodes(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	factors := factorRepositoryFor(testContext, repository)
	token := openToken(testContext, enrollment)
	confirmed := startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)

	createdIdentity, completeError := enrollment.Complete(context.Background(), token)
	if completeError != nil {
		testContext.Fatal(completeError)
	}

	methods, methodsError := factors.Methods(context.Background(), createdIdentity.AccountID)
	if methodsError != nil || len(methods) != 1 || methods[0] != "totp" {
		testContext.Errorf("expected [totp], got %v %v", methods, methodsError)
	}
	var storedRecoveryCodes int
	if countError := repository.database.NewRaw(
		"SELECT count(*) FROM recovery_code WHERE recovery_code_account_id = ?", createdIdentity.AccountID,
	).Scan(context.Background(), &storedRecoveryCodes); countError != nil || storedRecoveryCodes != 10 {
		testContext.Errorf("expected 10 recovery codes, got %d %v", storedRecoveryCodes, countError)
	}
	replayError := factors.VerifyTOTP(context.Background(), createdIdentity.AccountID, confirmed.confirmedCode, confirmed.confirmedAt)
	if !errors.Is(replayError, secondfactor.ErrInvalidCode) {
		testContext.Errorf("the code accepted during enrollment must not be reusable, got %v", replayError)
	}
	if consumeError := factors.ConsumeRecoveryCode(context.Background(), createdIdentity.AccountID, confirmed.recoveryCodes[0]); consumeError != nil {
		testContext.Errorf("a shown recovery code must be stored, got %v", consumeError)
	}
	if _, _, setupError := enrollment.Setup(token); !errors.Is(setupError, ErrEnrollmentClosed) {
		testContext.Errorf("the pending state must be forgotten after Complete, got %v", setupError)
	}
}

func TestStartAgainReplacesPendingState(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	startWithConfirmedTOTP(testContext, enrollment, token, "abandoned-admin")

	if restartError := enrollment.Start(context.Background(), token, enrollmentAccountName, enrollmentPassword); restartError != nil {
		testContext.Fatal(restartError)
	}
	_, unconfirmedError := enrollment.Complete(context.Background(), token)
	if !errors.Is(unconfirmedError, ErrSecondFactorIncomplete) {
		testContext.Errorf("a new account step must drop the confirmed factor, got %v", unconfirmedError)
	}
	confirmTOTPOnPendingState(testContext, enrollment, token)

	createdIdentity, completeError := enrollment.Complete(context.Background(), token)

	if completeError != nil || createdIdentity.AccountName != enrollmentAccountName {
		testContext.Fatalf("expected the replacing account, got %+v %v", createdIdentity, completeError)
	}
	if _, abandonedError := repository.Authenticate(context.Background(), "abandoned-admin", enrollmentPassword); abandonedError == nil {
		testContext.Error("the abandoned account name must not exist")
	}
}

// failRecoveryCodeInserts adds a constraint that no row can satisfy, so the
// last write of SaveSetup fails after the account and its TOTP credential were
// inserted in the same transaction. NOT VALID skips the check of existing rows.
// The schema is the test's own (storetest.New), so other tests are unaffected.
func failRecoveryCodeInserts(testContext *testing.T, repository *Repository) {
	testContext.Helper()
	if _, alterError := repository.database.ExecContext(context.Background(),
		"ALTER TABLE recovery_code ADD CONSTRAINT always_fail CHECK (false) NOT VALID"); alterError != nil {
		testContext.Fatal(alterError)
	}
}

func allowRecoveryCodeInserts(testContext *testing.T, repository *Repository) {
	testContext.Helper()
	if _, alterError := repository.database.ExecContext(context.Background(),
		"ALTER TABLE recovery_code DROP CONSTRAINT always_fail"); alterError != nil {
		testContext.Fatal(alterError)
	}
}

func countRows(testContext *testing.T, repository *Repository, countQuery string) int {
	testContext.Helper()
	var rowCount int
	if countError := repository.database.NewRaw(countQuery).Scan(context.Background(), &rowCount); countError != nil {
		testContext.Fatal(countError)
	}
	return rowCount
}

func TestCompleteCreatesNoAccountWhenRecoveryCodesCannotBeSaved(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	startWithConfirmedTOTP(testContext, enrollment, token, enrollmentAccountName)
	failRecoveryCodeInserts(testContext, repository)

	_, failedCompleteError := enrollment.Complete(context.Background(), token)

	if failedCompleteError == nil {
		testContext.Fatal("Complete must fail when the recovery codes cannot be saved")
	}
	if accountCount := countRows(testContext, repository, "SELECT count(*) FROM account"); accountCount != 0 {
		testContext.Errorf("no account may exist without its factor, got %d accounts", accountCount)
	}
	if credentialCount := countRows(testContext, repository, "SELECT count(*) FROM credential"); credentialCount != 0 {
		testContext.Errorf("no credential may survive the rollback, got %d rows", credentialCount)
	}

	allowRecoveryCodeInserts(testContext, repository)
	createdIdentity, retriedCompleteError := enrollment.Complete(context.Background(), token)

	if retriedCompleteError != nil || createdIdentity.AccountName != enrollmentAccountName {
		testContext.Errorf("the token and pending state must stay usable after the failure, got %+v / %v", createdIdentity, retriedCompleteError)
	}
	if recoveryCodeCount := countRows(testContext, repository, "SELECT count(*) FROM recovery_code"); recoveryCodeCount != 10 {
		testContext.Errorf("expected the 10 recovery codes after the retry, got %d", recoveryCodeCount)
	}
}
