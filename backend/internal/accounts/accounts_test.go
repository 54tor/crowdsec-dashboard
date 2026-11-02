package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/store/storetest"
)

const (
	validAccountName   = "alice"
	validPassword      = "correct horse battery"
	roleAdmin          = "admin"
	timingTolerance    = 3.0
	firstCallTolerance = 1.6
)

func newRepositoryWithAccount(testContext *testing.T) *Repository {
	testContext.Helper()
	repository := NewRepository(storetest.New(testContext))
	if _, createError := repository.CreateAccount(context.Background(), validAccountName, validPassword, roleAdmin, SecondFactorSetupWindow); createError != nil {
		testContext.Fatal(createError)
	}
	return repository
}

func TestFirstUnknownAccountAuthenticateCostsLikeAWrongPassword(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	measureAuthenticate(testContext, repository, validAccountName)

	wrongPasswordDuration := measureAuthenticate(testContext, repository, validAccountName)
	unknownAccountDuration := measureAuthenticate(testContext, repository, "nobody")

	ratio := float64(unknownAccountDuration) / float64(wrongPasswordDuration)
	if ratio < 1/timingTolerance || ratio > timingTolerance {
		testContext.Errorf("unknown account took %v, wrong password %v", unknownAccountDuration, wrongPasswordDuration)
	}
	secondUnknownAccountDuration := measureAuthenticate(testContext, repository, "nobody")
	firstCallOverhead := float64(unknownAccountDuration) / float64(secondUnknownAccountDuration)
	if firstCallOverhead > firstCallTolerance {
		testContext.Errorf("first unknown call took %v, second %v", unknownAccountDuration, secondUnknownAccountDuration)
	}
}

func measureAuthenticate(testContext *testing.T, repository *Repository, accountName string) time.Duration {
	testContext.Helper()
	startTime := time.Now()
	_, authenticateError := repository.Authenticate(context.Background(), accountName, "wrong password value")
	elapsedDuration := time.Since(startTime)
	if !errors.Is(authenticateError, auth.ErrInvalidCredentials) {
		testContext.Fatalf("expected ErrInvalidCredentials, got %v", authenticateError)
	}
	return elapsedDuration
}

func TestAuthenticateReturnsIdentityForValidPassword(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)

	identityObtained, authenticateError := repository.Authenticate(context.Background(), validAccountName, validPassword)

	if authenticateError != nil {
		testContext.Fatal(authenticateError)
	}
	if identityObtained.AccountName != validAccountName || identityObtained.AccountRole != roleAdmin || identityObtained.AccountID == 0 {
		testContext.Errorf("unexpected identity: %+v", identityObtained)
	}
}

func TestAuthenticateRejectsWrongPassword(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)

	_, authenticateError := repository.Authenticate(context.Background(), validAccountName, "wrong password value")

	if !errors.Is(authenticateError, auth.ErrInvalidCredentials) {
		testContext.Errorf("expected ErrInvalidCredentials, got %v", authenticateError)
	}
}

func TestAuthenticateRejectsUnknownAccountWithErrInvalidCredentials(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)

	_, authenticateError := repository.Authenticate(context.Background(), "nobody", validPassword)

	if !errors.Is(authenticateError, auth.ErrInvalidCredentials) {
		testContext.Errorf("expected ErrInvalidCredentials, got %v", authenticateError)
	}
}

func TestAuthenticateReturnsDistinctErrorWhenDatabaseIsClosed(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := NewRepository(database)
	database.Close()

	_, authenticateError := repository.Authenticate(context.Background(), validAccountName, validPassword)

	if authenticateError == nil || errors.Is(authenticateError, auth.ErrInvalidCredentials) {
		testContext.Errorf("expected infrastructure error, got %v", authenticateError)
	}
}

func TestCreateRefusesDuplicateName(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)

	_, createError := repository.CreateAccount(context.Background(), validAccountName, validPassword, roleAdmin, SecondFactorSetupWindow)

	if !errors.Is(createError, ErrAccountExists) {
		testContext.Errorf("expected ErrAccountExists, got %v", createError)
	}
}

func TestCreateRefusesInvalidName(testContext *testing.T) {
	repository := NewRepository(storetest.New(testContext))

	for _, invalidName := range []string{"", "Alice", "-bad", "has space", strings.Repeat("a", 65)} {
		_, createError := repository.CreateAccount(context.Background(), invalidName, validPassword, roleAdmin, SecondFactorSetupWindow)
		if !errors.Is(createError, ErrInvalidAccountName) {
			testContext.Errorf("name %q: expected ErrInvalidAccountName, got %v", invalidName, createError)
		}
	}
}

func TestCountReturnsNumberOfAccounts(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)

	accountCount, countError := repository.Count(context.Background())

	if countError != nil || accountCount != 1 {
		testContext.Errorf("expected 1, got %d (%v)", accountCount, countError)
	}
}

func TestHashPasswordRefusesTooShortAndTooLong(testContext *testing.T) {
	for _, invalidPassword := range []string{"short", strings.Repeat("a", 11), strings.Repeat("a", 129)} {
		if _, hashError := HashPassword(invalidPassword); !errors.Is(hashError, ErrPasswordLength) {
			testContext.Errorf("length %d: expected ErrPasswordLength, got %v", len(invalidPassword), hashError)
		}
	}
	for _, validLengthPassword := range []string{strings.Repeat("a", 12), strings.Repeat("a", 128)} {
		if _, hashError := HashPassword(validLengthPassword); hashError != nil {
			testContext.Errorf("length %d: %v", len(validLengthPassword), hashError)
		}
	}
}
