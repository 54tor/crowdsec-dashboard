package accounts

import (
	"context"
	"errors"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/store/storetest"
)

const (
	enrollmentAccountName = "first-admin"
	enrollmentPassword    = "a long enough password"
)

func newEnrollment(testContext *testing.T) (*Enrollment, *Repository) {
	testContext.Helper()
	repository := NewRepository(storetest.New(testContext))
	return NewEnrollment(repository), repository
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
	enrollment := NewEnrollment(repository)

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

	createdIdentity, completeError := enrollment.Complete(context.Background(), token, enrollmentAccountName, enrollmentPassword)

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
	_, secondCompleteError := enrollment.Complete(context.Background(), token, "second-admin", enrollmentPassword)
	if !errors.Is(secondCompleteError, ErrEnrollmentClosed) {
		testContext.Errorf("token must be erased after success, got %v", secondCompleteError)
	}
}

func TestCompleteRejectsWrongToken(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	openToken(testContext, enrollment)

	_, completeError := enrollment.Complete(context.Background(), "not-the-token", enrollmentAccountName, enrollmentPassword)

	if !errors.Is(completeError, ErrEnrollmentToken) {
		testContext.Errorf("expected ErrEnrollmentToken, got %v", completeError)
	}
	if accountCount := countAccounts(testContext, repository); accountCount != 0 {
		testContext.Errorf("expected no account, got %d", accountCount)
	}
}

func TestCompleteWithoutOpenIsClosed(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)

	_, completeError := enrollment.Complete(context.Background(), "anything", enrollmentAccountName, enrollmentPassword)

	if !errors.Is(completeError, ErrEnrollmentClosed) {
		testContext.Errorf("expected ErrEnrollmentClosed, got %v", completeError)
	}
}

func TestCompleteIsClosedAfterFirstAccount(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)
	passwordHash, hashError := HashPassword(validPassword)
	if hashError != nil {
		testContext.Fatal(hashError)
	}
	if _, createError := repository.CreateWithPasswordHash(context.Background(), validAccountName, passwordHash, roleAdmin); createError != nil {
		testContext.Fatal(createError)
	}

	_, completeError := enrollment.Complete(context.Background(), token, enrollmentAccountName, enrollmentPassword)

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

	const concurrentCompletions = 2
	completionErrors := make([]error, concurrentCompletions)
	var waitGroup sync.WaitGroup
	startSignal := make(chan struct{})
	for completionIndex := 0; completionIndex < concurrentCompletions; completionIndex++ {
		waitGroup.Add(1)
		go func(completionIndex int) {
			defer waitGroup.Done()
			<-startSignal
			_, completionErrors[completionIndex] = enrollment.Complete(context.Background(), token, enrollmentAccountName, enrollmentPassword)
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
	firstEnrollment := NewEnrollment(repository)
	secondEnrollment := NewEnrollment(repository)
	firstToken := openToken(testContext, firstEnrollment)
	secondToken := openToken(testContext, secondEnrollment)

	var waitGroup sync.WaitGroup
	completionErrors := make([]error, 2)
	startSignal := make(chan struct{})
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-startSignal
		_, completionErrors[0] = firstEnrollment.Complete(context.Background(), firstToken, "first-admin", enrollmentPassword)
	}()
	go func() {
		defer waitGroup.Done()
		<-startSignal
		_, completionErrors[1] = secondEnrollment.Complete(context.Background(), secondToken, "second-admin", enrollmentPassword)
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
	firstEnrollment := NewEnrollment(repository)
	previousToken := openToken(testContext, firstEnrollment)
	secondEnrollment := NewEnrollment(repository)
	newToken := openToken(testContext, secondEnrollment)

	if newToken == previousToken {
		testContext.Fatal("a reopened enrollment must generate a different token")
	}
	_, previousTokenError := secondEnrollment.Complete(context.Background(), previousToken, enrollmentAccountName, enrollmentPassword)
	if !errors.Is(previousTokenError, ErrEnrollmentToken) {
		testContext.Errorf("expected ErrEnrollmentToken for the previous token, got %v", previousTokenError)
	}
	_, newTokenError := secondEnrollment.Complete(context.Background(), newToken, enrollmentAccountName, enrollmentPassword)
	if newTokenError != nil {
		testContext.Errorf("new token must work, got %v", newTokenError)
	}
}

func TestReopeningTheSameInstanceInvalidatesItsPreviousToken(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)
	previousToken := openToken(testContext, enrollment)
	openToken(testContext, enrollment)

	_, completeError := enrollment.Complete(context.Background(), previousToken, enrollmentAccountName, enrollmentPassword)

	if !errors.Is(completeError, ErrEnrollmentToken) {
		testContext.Errorf("expected ErrEnrollmentToken, got %v", completeError)
	}
}

func TestCompleteRejectsInvalidAccountNameAndPassword(testContext *testing.T) {
	enrollment, repository := newEnrollment(testContext)
	token := openToken(testContext, enrollment)

	_, nameError := enrollment.Complete(context.Background(), token, "Bad Name!", enrollmentPassword)
	_, passwordError := enrollment.Complete(context.Background(), token, enrollmentAccountName, "short")

	if !errors.Is(nameError, ErrInvalidAccountName) {
		testContext.Errorf("expected ErrInvalidAccountName, got %v", nameError)
	}
	if !errors.Is(passwordError, ErrPasswordLength) {
		testContext.Errorf("expected ErrPasswordLength, got %v", passwordError)
	}
	if accountCount := countAccounts(testContext, repository); accountCount != 0 {
		testContext.Errorf("expected no account, got %d", accountCount)
	}
	_, retryError := enrollment.Complete(context.Background(), token, enrollmentAccountName, enrollmentPassword)
	if retryError != nil {
		testContext.Errorf("token must survive validation failures, got %v", retryError)
	}
}

func TestErrorsNeverContainTokenOrPassword(testContext *testing.T) {
	enrollment, _ := newEnrollment(testContext)
	token := openToken(testContext, enrollment)

	_, wrongTokenError := enrollment.Complete(context.Background(), "wrong-token-value", enrollmentAccountName, enrollmentPassword)
	_, shortPasswordError := enrollment.Complete(context.Background(), token, enrollmentAccountName, "short")

	for _, observedError := range []error{wrongTokenError, shortPasswordError} {
		message := observedError.Error()
		for _, secret := range []string{token, "wrong-token-value", enrollmentPassword, "short"} {
			if message == secret {
				testContext.Errorf("error %q equals a secret", message)
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
	if _, completeError := enrollment.Complete(context.Background(), token, enrollmentAccountName, enrollmentPassword); completeError != nil {
		testContext.Fatal(completeError)
	}
	requiredAfterComplete, requiredError := enrollment.Required(context.Background())
	if requiredError != nil || requiredAfterComplete {
		testContext.Errorf("enrollment must be closed after Complete, got %v %v", requiredAfterComplete, requiredError)
	}
}
