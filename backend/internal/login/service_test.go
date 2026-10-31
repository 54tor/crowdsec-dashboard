package login

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/geo"
	"crowdsec-dashboard/internal/secondfactor"
)

func TestBeginWithWrongPasswordReturnsInvalidCredentialsAndAudits(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	fixture.createTOTPAccount(testContext, "alice")

	beginResult, beginError := fixture.service.Begin(context.Background(), "alice", wrongPassword, clientAddress)

	if !errors.Is(beginError, auth.ErrInvalidCredentials) || beginResult.PendingID != "" {
		testContext.Fatalf("expected ErrInvalidCredentials and no pending login, got %+v / %v", beginResult, beginError)
	}
	failures := fixture.recorder.eventsWithAction(audit.ActionLoginFailure)
	expectedEvent := recordedEvent{accountID: 0, action: audit.ActionLoginFailure, target: "alice", clientIP: "192.0.2.10"}
	if len(failures) != 1 || failures[0] != expectedEvent {
		testContext.Errorf("expected %+v, got %+v", expectedEvent, failures)
	}
}

func TestBeginTreatsUnknownAccountWrongPasswordAndLockedAccountAlike(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	fixture.createTOTPAccount(testContext, "alice")
	locked := fixture.createTOTPAccount(testContext, "mallory")
	for reservationNumber := 0; reservationNumber < 5; reservationNumber++ {
		if _, reserveError := fixture.accounts.ReserveSecondFactorAttempt(context.Background(), locked.accountID, fixture.clock.Now()); reserveError != nil {
			testContext.Fatal(reserveError)
		}
	}

	attemptedNames := []string{"nobody", "alice", "mallory"}
	for _, attemptedName := range attemptedNames {
		beginResult, beginError := fixture.service.Begin(context.Background(), attemptedName, wrongPassword, clientAddress)

		var lockedError AccountLockedError
		if beginError != auth.ErrInvalidCredentials || errors.As(beginError, &lockedError) || beginResult.PendingID != "" || beginResult.Methods != nil {
			testContext.Errorf("%s: expected exactly auth.ErrInvalidCredentials, got %+v / %v", attemptedName, beginResult, beginError)
		}
	}
	failures := fixture.recorder.eventsWithAction(audit.ActionLoginFailure)
	if len(failures) != len(attemptedNames) {
		testContext.Fatalf("expected one login_failure per attempt, got %+v", failures)
	}
	for failureIndex, recordedFailure := range failures {
		expectedEvent := recordedEvent{accountID: 0, action: audit.ActionLoginFailure, target: attemptedNames[failureIndex], clientIP: "192.0.2.10"}
		if recordedFailure != expectedEvent {
			testContext.Errorf("audit must not tell accounts apart: expected %+v, got %+v", expectedEvent, recordedFailure)
		}
	}
}

func TestWrongPasswordsNeverLockTheAccount(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")

	for attemptNumber := 0; attemptNumber < 20; attemptNumber++ {
		if _, beginError := fixture.service.Begin(context.Background(), "alice", wrongPassword, clientAddress); !errors.Is(beginError, auth.ErrInvalidCredentials) {
			testContext.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", attemptNumber, beginError)
		}
	}

	lockedUntil, lockedError := fixture.accounts.LockedUntil(context.Background(), alice.accountID)
	if lockedError != nil || !lockedUntil.IsZero() {
		testContext.Fatalf("wrong passwords must never lock, got %v (%v)", lockedUntil, lockedError)
	}
	beginResult := fixture.beginOrFail(testContext, "alice")
	identity, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))
	if verifyError != nil || identity.AccountID != alice.accountID {
		testContext.Errorf("expected a complete login after 20 wrong passwords, got %+v / %v", identity, verifyError)
	}
}

func TestBeginReturnsSetupStageForAccountWithoutFactor(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	legacyAccountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, legacyAccountID, "infinity")

	beginResult := fixture.beginOrFail(testContext, "alice")

	if beginResult.Stage != StageSetup || len(beginResult.Methods) != 0 || beginResult.PendingID == "" {
		testContext.Errorf("expected the setup stage without methods, got %+v", beginResult)
	}
	if _, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, "123456"); !errors.Is(verifyError, ErrWrongStage) {
		testContext.Errorf("a setup-stage pending login must not accept a second factor, got %v", verifyError)
	}
}

func TestSetupStageRefusedOutsideSetupWindow(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	fixture.createAccount(testContext, "alice")
	expiredWindowID := fixture.createAccount(testContext, "bob")
	fixture.openSetupWindow(testContext, expiredWindowID, fixture.clock.Now().Add(-time.Second).Format(time.RFC3339Nano))

	for _, accountName := range []string{"alice", "bob"} {
		beginResult, beginError := fixture.service.Begin(context.Background(), accountName, testPassword, clientAddress)

		if !errors.Is(beginError, ErrSecondFactorSetupNotAllowed) || beginResult.PendingID != "" {
			testContext.Errorf("%s: expected ErrSecondFactorSetupNotAllowed, got %+v / %v", accountName, beginResult, beginError)
		}
	}
	if _, wrongPasswordError := fixture.service.Begin(context.Background(), "alice", wrongPassword, clientAddress); !errors.Is(wrongPasswordError, auth.ErrInvalidCredentials) {
		testContext.Errorf("the setup refusal must only be revealed after a correct password, got %v", wrongPasswordError)
	}
}

func TestVerifyTOTPReturnsIdentityAndAuditsSuccess(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")

	beginResult := fixture.beginOrFail(testContext, "alice")
	identity, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if beginResult.Stage != StageSecondFactor || len(beginResult.Methods) != 1 || beginResult.Methods[0] != "totp" {
		testContext.Errorf("expected the second factor stage offering totp, got %+v", beginResult)
	}
	if verifyError != nil || identity != (auth.AccountIdentity{AccountID: alice.accountID, AccountName: "alice", AccountRole: "admin"}) {
		testContext.Fatalf("unexpected identity %+v / %v", identity, verifyError)
	}
	successes := fixture.recorder.eventsWithAction(audit.ActionLoginSuccess)
	if len(successes) != 1 || successes[0] != (recordedEvent{alice.accountID, audit.ActionLoginSuccess, "alice", "192.0.2.10"}) {
		testContext.Errorf("expected one login_success, got %+v", successes)
	}
}

func TestPendingLoginIsSingleUseAfterSuccess(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	beginResult := fixture.beginOrFail(testContext, "alice")

	_, otherAddressError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, otherAddress, fixture.totpCode(testContext, alice.secret))
	_, firstError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))
	fixture.clock.Advance(totpPeriod)
	_, replayError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if !errors.Is(otherAddressError, ErrPendingLoginInvalid) {
		testContext.Errorf("another client address must be refused, got %v", otherAddressError)
	}
	if firstError != nil {
		testContext.Fatalf("expected the first verification to succeed, got %v", firstError)
	}
	if !errors.Is(replayError, ErrPendingLoginInvalid) {
		testContext.Errorf("a used pending login must be refused, got %v", replayError)
	}
	if verifications := fixture.factors.totpVerifications.Load(); verifications != 1 {
		testContext.Errorf("only the accepted call may reach the verifier, got %d verifications", verifications)
	}
}

func TestFifthSecondFactorFailureLocksAndForgetsPendingLogin(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	beginResult := fixture.beginOrFail(testContext, "alice")

	for attemptNumber := 1; attemptNumber <= 5; attemptNumber++ {
		if _, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, neverMatchingTOTPCode); !errors.Is(verifyError, ErrSecondFactorInvalid) {
			testContext.Fatalf("attempt %d: expected ErrSecondFactorInvalid, got %v", attemptNumber, verifyError)
		}
	}
	_, forgottenError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if !errors.Is(forgottenError, ErrPendingLoginInvalid) {
		testContext.Errorf("the pending login must be forgotten after the locking failure, got %v", forgottenError)
	}
	expectedLockEnd := fixture.clock.Now().Add(15 * time.Minute)
	if lockedUntil, _ := fixture.accounts.LockedUntil(context.Background(), alice.accountID); !lockedUntil.Equal(expectedLockEnd) {
		testContext.Errorf("expected a lock until %v, got %v", expectedLockEnd, lockedUntil)
	}
	if failures := fixture.recorder.eventsWithAction(audit.ActionSecondFactorFailure); len(failures) != 5 || failures[0].target != "totp" {
		testContext.Errorf("expected 5 second_factor_failure events targeting totp, got %+v", failures)
	}
	if lockEvents := fixture.recorder.eventsWithAction(audit.ActionAccountLocked); len(lockEvents) != 1 {
		testContext.Errorf("expected one account_locked event, got %+v", lockEvents)
	}
	if verifications := fixture.factors.totpVerifications.Load(); verifications != 5 {
		testContext.Errorf("expected 5 verifications, got %d", verifications)
	}
}

func TestLockedAccountWithCorrectPasswordReturnsAccountLocked(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	beginResult := fixture.beginOrFail(testContext, "alice")
	for attemptNumber := 1; attemptNumber <= 5; attemptNumber++ {
		fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, neverMatchingTOTPCode)
	}
	expectedLockEnd := fixture.clock.Now().Add(15 * time.Minute)

	_, lockedBeginError := fixture.service.Begin(context.Background(), "alice", testPassword, clientAddress)
	fixture.clock.Advance(15 * time.Minute)
	afterLockResult := fixture.beginOrFail(testContext, "alice")
	identity, verifyError := fixture.service.VerifyTOTP(context.Background(), afterLockResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	var lockedError AccountLockedError
	if !errors.As(lockedBeginError, &lockedError) || !lockedError.Until.Equal(expectedLockEnd) {
		testContext.Errorf("expected AccountLockedError until %v, got %v", expectedLockEnd, lockedBeginError)
	}
	if verifyError != nil || identity.AccountID != alice.accountID {
		testContext.Errorf("the account must unlock after 15 minutes, got %+v / %v", identity, verifyError)
	}
	if lockedUntil, _ := fixture.accounts.LockedUntil(context.Background(), alice.accountID); !lockedUntil.IsZero() {
		testContext.Errorf("a success must clear the lock, got %v", lockedUntil)
	}
}

func TestParallelWrongCodesOnOnePendingLoginAreCappedAtFive(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	fixture.createTOTPAccount(testContext, "alice")
	beginResult := fixture.beginOrFail(testContext, "alice")

	runConcurrently(20, func() {
		fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, neverMatchingTOTPCode)
	})

	if verifications := fixture.factors.totpVerifications.Load(); verifications > 5 {
		testContext.Errorf("expected at most 5 verifications, got %d", verifications)
	}
}

func TestParallelWrongCodesAcrossPendingLoginsAreCappedPerAccount(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	pendingIDs := make(chan string, 20)
	for pendingNumber := 0; pendingNumber < 4; pendingNumber++ {
		pendingID := fixture.beginOrFail(testContext, "alice").PendingID
		for callNumber := 0; callNumber < 5; callNumber++ {
			pendingIDs <- pendingID
		}
	}
	close(pendingIDs)

	runConcurrently(20, func() {
		fixture.service.VerifyTOTP(context.Background(), <-pendingIDs, clientAddress, neverMatchingTOTPCode)
	})

	if verifications := fixture.factors.totpVerifications.Load(); verifications > 5 {
		testContext.Errorf("expected at most 5 verifications for the account, got %d", verifications)
	}
	if lockedUntil, _ := fixture.accounts.LockedUntil(context.Background(), alice.accountID); !lockedUntil.After(fixture.clock.Now()) {
		testContext.Errorf("the account must be locked, got %v", lockedUntil)
	}
}

func TestTOTPVerificationErrorCountsAsFailure(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	fixture.factors.forcedTOTPError = fmt.Errorf("open totp secret: %w", errors.New("message authentication failed"))
	beginResult := fixture.beginOrFail(testContext, "alice")

	identity, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if verifyError != ErrSecondFactorInvalid || identity != (auth.AccountIdentity{}) {
		testContext.Errorf("a verifier error must look exactly like a wrong code, got %+v / %v", identity, verifyError)
	}
	if failures := fixture.recorder.eventsWithAction(audit.ActionSecondFactorFailure); len(failures) != 1 {
		testContext.Errorf("the failure must be audited and counted, got %+v", failures)
	}
}

func TestVerifyRecoveryCodeConsumesIt(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	recoveryCode := alice.recoveryCodes[0]

	firstLogin := fixture.beginOrFail(testContext, "alice")
	identity, firstError := fixture.service.VerifyRecoveryCode(context.Background(), firstLogin.PendingID, clientAddress, recoveryCode)
	secondLogin := fixture.beginOrFail(testContext, "alice")
	_, reuseError := fixture.service.VerifyRecoveryCode(context.Background(), secondLogin.PendingID, clientAddress, recoveryCode)

	if firstError != nil || identity.AccountID != alice.accountID {
		testContext.Fatalf("expected the recovery code to log in, got %+v / %v", identity, firstError)
	}
	if !errors.Is(reuseError, ErrSecondFactorInvalid) {
		testContext.Errorf("a used recovery code must be refused, got %v", reuseError)
	}
	usedEvents := fixture.recorder.eventsWithAction(audit.ActionRecoveryCodeUsed)
	if len(usedEvents) != 1 || usedEvents[0] != (recordedEvent{alice.accountID, audit.ActionRecoveryCodeUsed, "alice", "192.0.2.10"}) {
		testContext.Errorf("expected one recovery_code_used event, got %+v", usedEvents)
	}
}

func TestWebAuthnAssertionCannotBeReplayedWithZeroCounter(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	aliceID, key := fixture.createWebAuthnAccount(testContext, "alice")
	ctx := context.Background()

	firstLogin := fixture.beginOrFail(testContext, "alice")
	capturedResponse := fixture.assertionFor(testContext, key, firstLogin.PendingID)
	_, malformedError := fixture.service.VerifyWebAuthn(ctx, firstLogin.PendingID, clientAddress, []byte(`{"id":"broken"}`))
	_, replayAfterFailureError := fixture.service.VerifyWebAuthn(ctx, firstLogin.PendingID, clientAddress, capturedResponse)
	finishCallsAfterFailure := fixture.factors.webAuthnFinishCalls.Load()

	acceptedResponse := fixture.assertionFor(testContext, key, firstLogin.PendingID)
	identity, acceptedError := fixture.service.VerifyWebAuthn(ctx, firstLogin.PendingID, clientAddress, acceptedResponse)

	secondLogin := fixture.beginOrFail(testContext, "alice")
	fixture.assertionFor(testContext, key, secondLogin.PendingID)
	_, replayOnNewLoginError := fixture.service.VerifyWebAuthn(ctx, secondLogin.PendingID, clientAddress, acceptedResponse)
	fixture.assertionFor(testContext, key, secondLogin.PendingID)
	_, oldResponseOnNewLoginError := fixture.service.VerifyWebAuthn(ctx, secondLogin.PendingID, clientAddress, capturedResponse)

	if !errors.Is(malformedError, ErrSecondFactorInvalid) || !errors.Is(replayAfterFailureError, ErrSecondFactorInvalid) {
		testContext.Errorf("expected both first attempts to fail, got %v / %v", malformedError, replayAfterFailureError)
	}
	if finishCallsAfterFailure != 1 {
		testContext.Errorf("the challenge must be consumed by the failure: the replay must not reach the verifier, got %d calls", finishCallsAfterFailure)
	}
	if acceptedError != nil || identity.AccountID != aliceID {
		testContext.Fatalf("a fresh assertion must log in, got %+v / %v", identity, acceptedError)
	}
	if !errors.Is(replayOnNewLoginError, ErrSecondFactorInvalid) || !errors.Is(oldResponseOnNewLoginError, ErrSecondFactorInvalid) {
		testContext.Errorf("a signCount 0 assertion replayed on a new pending login must be refused, got %v / %v", replayOnNewLoginError, oldResponseOnNewLoginError)
	}
}

func TestWebAuthnVerifyWithoutOptionsIsRejected(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	_, key := fixture.createWebAuthnAccount(testContext, "alice")
	withoutOptions := fixture.beginOrFail(testContext, "alice")
	otherLogin := fixture.beginOrFail(testContext, "alice")
	validElsewhere := fixture.assertionFor(testContext, key, otherLogin.PendingID)

	_, verifyError := fixture.service.VerifyWebAuthn(context.Background(), withoutOptions.PendingID, clientAddress, validElsewhere)

	if !errors.Is(verifyError, ErrSecondFactorInvalid) {
		testContext.Errorf("expected ErrSecondFactorInvalid without options, got %v", verifyError)
	}
	if finishCalls := fixture.factors.webAuthnFinishCalls.Load(); finishCalls != 0 {
		testContext.Errorf("a pending login without a challenge must not reach the verifier, got %d calls", finishCalls)
	}
}

func TestAccessRuleDeniesAfterSecondFactorAndAudits(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	fixture.addAccessRule(testContext, alice.accountID, "ip", "198.51.100.0/24")
	beginResult := fixture.beginOrFail(testContext, "alice")

	_, wrongCodeError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, neverMatchingTOTPCode)
	identity, deniedError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))
	_, afterDenialError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if !errors.Is(wrongCodeError, ErrSecondFactorInvalid) {
		testContext.Errorf("the allowlist must not be revealed before the second factor, got %v", wrongCodeError)
	}
	if !errors.Is(deniedError, ErrAccessDenied) || identity != (auth.AccountIdentity{}) {
		testContext.Errorf("expected ErrAccessDenied after a valid factor, got %+v / %v", identity, deniedError)
	}
	if !errors.Is(afterDenialError, ErrPendingLoginInvalid) {
		testContext.Errorf("the pending login must be consumed by the denial, got %v", afterDenialError)
	}
	denials := fixture.recorder.eventsWithAction(audit.ActionLoginDenied)
	if len(denials) != 1 || denials[0] != (recordedEvent{alice.accountID, audit.ActionLoginDenied, "alice", "192.0.2.10"}) {
		testContext.Errorf("expected one login_denied_access_rule event, got %+v", denials)
	}
	if successes := fixture.recorder.eventsWithAction(audit.ActionLoginSuccess); len(successes) != 0 {
		testContext.Errorf("a denied login must not be audited as a success, got %+v", successes)
	}
}

func TestIPRuleCoveringClientAllowsLogin(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	fixture.addAccessRule(testContext, alice.accountID, "ip", "192.0.2.0/24")
	beginResult := fixture.beginOrFail(testContext, "alice")

	identity, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if verifyError != nil || identity.AccountID != alice.accountID {
		testContext.Errorf("a covering rule must allow the login, got %+v / %v", identity, verifyError)
	}
}

func TestCountryRuleDeniesWhenGeolocationUnavailable(testContext *testing.T) {
	fixture := newLoginFixtureWith(testContext, fixtureOptions{geolocator: fakeGeolocator{lookupError: geo.ErrGeolocationUnavailable}})
	alice := fixture.createTOTPAccount(testContext, "alice")
	fixture.addAccessRule(testContext, alice.accountID, "country", "FR")
	beginResult := fixture.beginOrFail(testContext, "alice")

	_, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if !errors.Is(verifyError, ErrAccessDenied) {
		testContext.Errorf("a country rule without geolocation must deny, got %v", verifyError)
	}
}

func TestSetupCannotBeUsedFromSecondFactorStage(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	alice := fixture.createTOTPAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, alice.accountID, "infinity")
	beginResult := fixture.beginOrFail(testContext, "alice")

	setup, _, setupError := fixture.service.Setup(beginResult.PendingID, clientAddress)
	_, completeError := fixture.service.CompleteSetup(context.Background(), beginResult.PendingID, clientAddress)
	identity, verifyError := fixture.service.VerifyTOTP(context.Background(), beginResult.PendingID, clientAddress, fixture.totpCode(testContext, alice.secret))

	if beginResult.Stage != StageSecondFactor {
		testContext.Errorf("an account with a factor must be asked for it even with an open window, got %+v", beginResult)
	}
	if !errors.Is(setupError, ErrWrongStage) || setup != nil || !errors.Is(completeError, ErrWrongStage) {
		testContext.Errorf("expected ErrWrongStage, got %v / %v", setupError, completeError)
	}
	if verifyError != nil || identity.AccountID != alice.accountID {
		testContext.Errorf("the wrong-stage calls must leave the pending login usable, got %+v / %v", identity, verifyError)
	}
}

func completeTOTPSetup(testContext *testing.T, fixture *loginFixture, pendingID string) (auth.AccountIdentity, error) {
	testContext.Helper()
	setup, accountName, setupError := fixture.service.Setup(pendingID, clientAddress)
	if setupError != nil {
		testContext.Fatal(setupError)
	}
	fixture.confirmTOTP(testContext, setup, accountName)
	if _, codesError := setup.RecoveryCodes(); codesError != nil {
		testContext.Fatal(codesError)
	}
	return fixture.service.CompleteSetup(context.Background(), pendingID, clientAddress)
}

func TestCompleteSetupRequiresConfirmedFactor(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	legacyAccountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, legacyAccountID, "infinity")
	beginResult := fixture.beginOrFail(testContext, "alice")

	identity, completeError := fixture.service.CompleteSetup(context.Background(), beginResult.PendingID, clientAddress)

	if !errors.Is(completeError, secondfactor.ErrNoConfirmedFactor) || identity != (auth.AccountIdentity{}) {
		testContext.Errorf("the password alone must never complete the setup, got %+v / %v", identity, completeError)
	}
}

func TestCompleteSetupPersistsFactorAndReturnsIdentity(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	legacyAccountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, legacyAccountID, "infinity")
	beginResult := fixture.beginOrFail(testContext, "alice")

	identity, completeError := completeTOTPSetup(testContext, fixture, beginResult.PendingID)

	if completeError != nil || identity != (auth.AccountIdentity{AccountID: legacyAccountID, AccountName: "alice", AccountRole: "admin"}) {
		testContext.Fatalf("unexpected identity %+v / %v", identity, completeError)
	}
	methods, methodsError := fixture.factors.Methods(context.Background(), legacyAccountID)
	if methodsError != nil || len(methods) != 1 || methods[0] != "totp" {
		testContext.Errorf("expected the totp factor to be stored, got %v (%v)", methods, methodsError)
	}
	enrolledEvents := fixture.recorder.eventsWithAction(audit.ActionSecondFactorEnrolled)
	if len(enrolledEvents) != 1 || enrolledEvents[0] != (recordedEvent{legacyAccountID, audit.ActionSecondFactorEnrolled, "totp", "192.0.2.10"}) {
		testContext.Errorf("expected one second_factor_enrolled event with the client address, got %+v", enrolledEvents)
	}
	if _, replayError := fixture.service.CompleteSetup(context.Background(), beginResult.PendingID, clientAddress); !errors.Is(replayError, ErrPendingLoginInvalid) {
		testContext.Errorf("a completed setup must consume the pending login, got %v", replayError)
	}
}

func TestCompleteSetupRevokesExistingSessionsAndClearsWindow(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	legacyAccountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, legacyAccountID, "infinity")
	legacySessionToken, sessionError := fixture.sessions.Create(context.Background(), legacyAccountID)
	if sessionError != nil {
		testContext.Fatal(sessionError)
	}
	beginResult := fixture.beginOrFail(testContext, "alice")

	if _, completeError := completeTOTPSetup(testContext, fixture, beginResult.PendingID); completeError != nil {
		testContext.Fatal(completeError)
	}

	if _, isFound, lookupError := fixture.sessions.Lookup(context.Background(), legacySessionToken); isFound || lookupError != nil {
		testContext.Errorf("the sessions opened with the password alone must be revoked, got %v (%v)", isFound, lookupError)
	}
	if isAllowed, _ := fixture.accounts.SecondFactorSetupAllowed(context.Background(), legacyAccountID, fixture.clock.Now()); isAllowed {
		testContext.Error("the setup window must be closed after enrolment")
	}
	fixture.clock.Advance(totpPeriod)
	if nextLogin := fixture.beginOrFail(testContext, "alice"); nextLogin.Stage != StageSecondFactor {
		testContext.Errorf("the next login must ask for the enrolled factor, got %+v", nextLogin)
	}
}

func TestConcurrentSetupCompletionsEnrolOnce(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	legacyAccountID := fixture.createAccount(testContext, "alice")
	fixture.openSetupWindow(testContext, legacyAccountID, "infinity")
	firstLogin := fixture.beginOrFail(testContext, "alice")
	secondLogin := fixture.beginOrFail(testContext, "alice")

	_, firstError := completeTOTPSetup(testContext, fixture, firstLogin.PendingID)
	_, secondError := completeTOTPSetup(testContext, fixture, secondLogin.PendingID)

	if firstError != nil || secondError == nil {
		testContext.Errorf("only one setup may complete for a window, got %v / %v", firstError, secondError)
	}
}

func TestBeginReturnsStoreFullBeyondCapacity(testContext *testing.T) {
	fixture := newLoginFixtureWith(testContext, fixtureOptions{maxPendingLogins: 1})
	fixture.createTOTPAccount(testContext, "alice")
	fixture.beginOrFail(testContext, "alice")

	_, fullError := fixture.service.Begin(context.Background(), "alice", testPassword, netip.MustParseAddr("192.0.2.11"))

	if !errors.Is(fullError, ErrPendingStoreFull) {
		testContext.Errorf("expected ErrPendingStoreFull, got %v", fullError)
	}
}
