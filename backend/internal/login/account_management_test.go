package login

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"crowdsec-dashboard/internal/accounts"
)

func TestCreatedAccountEntersSetupStageWithinWindow(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	if _, createError := fixture.accounts.CreateAccount(context.Background(), "carol", testPassword, "read_only", accounts.SecondFactorSetupWindow); createError != nil {
		testContext.Fatal(createError)
	}

	withinWindow := fixture.beginOrFail(testContext, "carol")
	fixture.clock.Advance(accounts.SecondFactorSetupWindow + time.Second)
	afterWindow, afterWindowError := fixture.service.Begin(context.Background(), "carol", testPassword, clientAddress)

	if withinWindow.Stage != StageSetup {
		testContext.Errorf("a created account must enter the setup stage, got %+v", withinWindow)
	}
	if !errors.Is(afterWindowError, ErrSecondFactorSetupNotAllowed) || afterWindow.PendingID != "" {
		testContext.Errorf("after 72 h the setup must be refused, got %+v / %v", afterWindow, afterWindowError)
	}
}

// TestReEnrolPasskeyAfterResetSucceeds enrols a passkey, resets the factor as
// an administrator, then enrols a new passkey through the setup stage: the new
// user handle can only be stored once the old one was cleared by the reset.
func TestReEnrolPasskeyAfterResetSucceeds(testContext *testing.T) {
	fixture := newLoginFixture(testContext)
	accountID, _ := fixture.createWebAuthnAccount(testContext, "alice")
	if resetError := fixture.accounts.ResetSecondFactor(context.Background(), "alice"); resetError != nil {
		testContext.Fatal(resetError)
	}
	setupLogin := fixture.beginOrFail(testContext, "alice")
	if setupLogin.Stage != StageSetup {
		testContext.Fatalf("a reset account must enter the setup stage, got %+v", setupLogin)
	}
	setup, accountName, setupError := fixture.service.Setup(setupLogin.PendingID, clientAddress)
	if setupError != nil {
		testContext.Fatal(setupError)
	}
	creation, beginError := setup.BeginWebAuthn(fixture.relyingParty, accountName)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	if excludedCount := len(creation.Response.CredentialExcludeList); excludedCount != 0 {
		testContext.Errorf("the reset removed every passkey, none may be excluded, got %d", excludedCount)
	}
	attestationOptions, parseError := virtualwebauthn.ParseAttestationOptions(encodeJSON(testContext, creation))
	if parseError != nil {
		testContext.Fatal(parseError)
	}
	newKey := &virtualKey{authenticator: virtualwebauthn.NewAuthenticator(), credential: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(legitimateBrowser, newKey.authenticator, newKey.credential, *attestationOptions)
	if confirmError := setup.ConfirmWebAuthn(fixture.relyingParty, []byte(attestationResponse)); confirmError != nil {
		testContext.Fatal(confirmError)
	}
	if _, codesError := setup.RecoveryCodes(); codesError != nil {
		testContext.Fatal(codesError)
	}

	identity, completeError := fixture.service.CompleteSetup(context.Background(), setupLogin.PendingID, clientAddress)

	if completeError != nil || identity.AccountID != accountID {
		testContext.Fatalf("enrolling a new passkey after the reset must succeed, got %+v / %v", identity, completeError)
	}
	newKey.authenticator.AddCredential(newKey.credential)
	nextLogin := fixture.beginOrFail(testContext, "alice")
	if _, verifyError := fixture.service.VerifyWebAuthn(context.Background(), nextLogin.PendingID, clientAddress, fixture.assertionFor(testContext, newKey, nextLogin.PendingID)); verifyError != nil {
		testContext.Errorf("the new passkey must log in, got %v", verifyError)
	}
}
