package secondfactor

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store/storetest"
)

type enrolledFixture struct {
	database      *bun.DB
	repository    *Repository
	accountID     int64
	secret        string
	recoveryCodes []string
}

func newKeyring(testContext *testing.T) *secrets.Keyring {
	testContext.Helper()
	keyring, keyringError := secrets.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if keyringError != nil {
		testContext.Fatal(keyringError)
	}
	return keyring
}

func enrollAccount(testContext *testing.T, database *bun.DB, repository *Repository, accountName string) (int64, string, []string) {
	testContext.Helper()
	ctx := context.Background()
	accountID, createError := accounts.NewRepository(database).CreateWithPasswordHash(ctx, accountName, "hash", "admin")
	if createError != nil {
		testContext.Fatal(createError)
	}
	setup := &Setup{}
	enrollment, beginError := setup.BeginTOTP(accountName)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	if confirmError := setup.ConfirmTOTP(codeAt(testContext, enrollment.Secret, referenceInstant), referenceInstant); confirmError != nil {
		testContext.Fatal(confirmError)
	}
	recoveryCodes, codesError := setup.RecoveryCodes()
	if codesError != nil {
		testContext.Fatal(codesError)
	}
	if saveError := repository.SaveSetup(ctx, database, accountID, setup); saveError != nil {
		testContext.Fatalf("save setup: %v", saveError)
	}
	return accountID, enrollment.Secret, recoveryCodes
}

func newEnrolledFixture(testContext *testing.T) enrolledFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	repository := NewRepository(database, newKeyring(testContext))
	accountID, secret, recoveryCodes := enrollAccount(testContext, database, repository, "alice")
	return enrolledFixture{database, repository, accountID, secret, recoveryCodes}
}

func TestStoredTOTPSecretIsNotPlaintext(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)
	var storedCiphertext []byte
	queryError := fixture.database.NewRaw(`SELECT credential_secret_ciphertext FROM credential WHERE credential_account_id = ? AND credential_kind = 'totp'`, fixture.accountID).
		Scan(context.Background(), &storedCiphertext)
	if queryError != nil {
		testContext.Fatal(queryError)
	}
	decodedSecret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(fixture.secret)

	if bytes.Contains(storedCiphertext, []byte(fixture.secret)) || bytes.Contains(storedCiphertext, decodedSecret) {
		testContext.Fatal("stored ciphertext leaks the secret")
	}
}

func TestVerifyTOTPAcceptsValidCode(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)

	verifyError := fixture.repository.VerifyTOTP(context.Background(), fixture.accountID, codeAt(testContext, fixture.secret, referenceInstant.Add(30*time.Second)), referenceInstant.Add(30*time.Second))

	if verifyError != nil {
		testContext.Fatalf("expected success, got %v", verifyError)
	}
}

func TestVerifyTOTPRejectsWrongCode(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)

	verifyError := fixture.repository.VerifyTOTP(context.Background(), fixture.accountID, "000000", referenceInstant.Add(30*time.Second))

	if !errors.Is(verifyError, ErrInvalidCode) {
		testContext.Fatalf("expected ErrInvalidCode, got %v", verifyError)
	}
}

func TestVerifyTOTPRejectsReplayedStep(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)
	ctx := context.Background()
	laterInstant := referenceInstant.Add(60 * time.Second)
	nextStepInstant := laterInstant.Add(30 * time.Second)

	if firstError := fixture.repository.VerifyTOTP(ctx, fixture.accountID, codeAt(testContext, fixture.secret, laterInstant), laterInstant); firstError != nil {
		testContext.Fatalf("first use: %v", firstError)
	}
	if replayError := fixture.repository.VerifyTOTP(ctx, fixture.accountID, codeAt(testContext, fixture.secret, laterInstant), laterInstant); !errors.Is(replayError, ErrInvalidCode) {
		testContext.Errorf("same code twice: expected ErrInvalidCode, got %v", replayError)
	}
	if advanceError := fixture.repository.VerifyTOTP(ctx, fixture.accountID, codeAt(testContext, fixture.secret, nextStepInstant), nextStepInstant); advanceError != nil {
		testContext.Fatalf("next step: %v", advanceError)
	}
	if olderError := fixture.repository.VerifyTOTP(ctx, fixture.accountID, codeAt(testContext, fixture.secret, laterInstant), nextStepInstant); !errors.Is(olderError, ErrInvalidCode) {
		testContext.Errorf("older step after newer: expected ErrInvalidCode, got %v", olderError)
	}
}

func TestVerifyTOTPFailsWhenCiphertextCopiedToOtherAccount(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)
	ctx := context.Background()
	otherAccountID, createError := accounts.NewRepository(fixture.database).CreateWithPasswordHash(ctx, "bob", "hash", "admin")
	if createError != nil {
		testContext.Fatal(createError)
	}
	_, copyError := fixture.database.ExecContext(ctx, `
		INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id)
		SELECT ?, 'totp', credential_secret_ciphertext, credential_key_id FROM credential
		WHERE credential_account_id = ? AND credential_kind = 'totp'`, otherAccountID, fixture.accountID)
	if copyError != nil {
		testContext.Fatal(copyError)
	}

	verifyError := fixture.repository.VerifyTOTP(ctx, otherAccountID, codeAt(testContext, fixture.secret, referenceInstant), referenceInstant)

	if verifyError == nil {
		testContext.Fatal("a ciphertext copied to another account must not verify")
	}
}

func TestConsumeRecoveryCodeIsSingleUseUnderConcurrency(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)
	const attemptCount = 10
	attemptResults := make([]error, attemptCount)
	var waitGroup sync.WaitGroup
	for attemptIndex := 0; attemptIndex < attemptCount; attemptIndex++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			attemptResults[attemptIndex] = fixture.repository.ConsumeRecoveryCode(context.Background(), fixture.accountID, strings.ToLower(fixture.recoveryCodes[0]))
		}()
	}
	waitGroup.Wait()

	successCount := 0
	for _, attemptResult := range attemptResults {
		if attemptResult == nil {
			successCount++
		} else if !errors.Is(attemptResult, ErrInvalidCode) {
			testContext.Errorf("unexpected error: %v", attemptResult)
		}
	}
	if successCount != 1 {
		testContext.Fatalf("expected exactly one success, got %d", successCount)
	}
}

func TestConsumeRecoveryCodeRejectsOtherAccountsCode(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)
	otherAccountID, _, _ := enrollAccount(testContext, fixture.database, fixture.repository, "bob")

	consumeError := fixture.repository.ConsumeRecoveryCode(context.Background(), otherAccountID, fixture.recoveryCodes[0])

	if !errors.Is(consumeError, ErrInvalidCode) {
		testContext.Fatalf("expected ErrInvalidCode, got %v", consumeError)
	}
}

func TestMethodsListsEnrolledFactors(testContext *testing.T) {
	fixture := newEnrolledFixture(testContext)
	ctx := context.Background()
	bareAccountID, createError := accounts.NewRepository(fixture.database).CreateWithPasswordHash(ctx, "carol", "hash", "admin")
	if createError != nil {
		testContext.Fatal(createError)
	}

	enrolledMethods, enrolledError := fixture.repository.Methods(ctx, fixture.accountID)
	bareMethods, bareError := fixture.repository.Methods(ctx, bareAccountID)

	if enrolledError != nil || bareError != nil {
		testContext.Fatal(enrolledError, bareError)
	}
	if len(enrolledMethods) != 1 || enrolledMethods[0] != "totp" || len(bareMethods) != 0 {
		testContext.Fatalf("enrolled=%v bare=%v", enrolledMethods, bareMethods)
	}
}
