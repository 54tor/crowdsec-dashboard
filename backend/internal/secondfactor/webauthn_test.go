package secondfactor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

const (
	testRelyingPartyID     = "dashboard.example.com"
	testRelyingPartyOrigin = "https://dashboard.example.com"
)

var legitimateBrowser = virtualwebauthn.RelyingParty{ID: testRelyingPartyID, Name: "CrowdSec Dashboard", Origin: testRelyingPartyOrigin}

func newTestWebAuthn(testContext *testing.T) *WebAuthn {
	testContext.Helper()
	relyingParty, relyingPartyError := NewWebAuthn(testRelyingPartyID, []string{testRelyingPartyOrigin})
	if relyingPartyError != nil {
		testContext.Fatal(relyingPartyError)
	}
	return relyingParty
}

func encodeOptions(testContext *testing.T, options any) string {
	testContext.Helper()
	encodedOptions, marshalError := json.Marshal(options)
	if marshalError != nil {
		testContext.Fatal(marshalError)
	}
	return string(encodedOptions)
}

func beginRegistration(testContext *testing.T, relyingParty *WebAuthn, setup *Setup, accountName string) *virtualwebauthn.AttestationOptions {
	testContext.Helper()
	creation, beginError := setup.BeginWebAuthn(relyingParty, accountName)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	attestationOptions, parseError := virtualwebauthn.ParseAttestationOptions(encodeOptions(testContext, creation))
	if parseError != nil {
		testContext.Fatal(parseError)
	}
	return attestationOptions
}

type virtualKey struct {
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
}

func newVirtualKey(initialCounter uint32) *virtualKey {
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	credential.Counter = initialCounter
	return &virtualKey{authenticator: virtualwebauthn.NewAuthenticator(), credential: credential}
}

func (key *virtualKey) attest(browser virtualwebauthn.RelyingParty, attestationOptions *virtualwebauthn.AttestationOptions) []byte {
	return []byte(virtualwebauthn.CreateAttestationResponse(browser, key.authenticator, key.credential, *attestationOptions))
}

func (key *virtualKey) assert(browser virtualwebauthn.RelyingParty, assertionOptions *virtualwebauthn.AssertionOptions) []byte {
	return []byte(virtualwebauthn.CreateAssertionResponse(browser, key.authenticator, key.credential, *assertionOptions))
}

func TestNewWebAuthnRejectsOriginOutsideRPID(testContext *testing.T) {
	rejectedConfigurations := [][]string{
		{"https://evil.example.net"},
		{testRelyingPartyOrigin, "https://example.com"},
		{"http://dashboard.example.com"},
		{},
	}
	for _, rejectedOrigins := range rejectedConfigurations {
		relyingParty, relyingPartyError := NewWebAuthn(testRelyingPartyID, rejectedOrigins)

		if relyingPartyError == nil || relyingParty != nil {
			testContext.Errorf("origins %v: expected a refusal, got %v", rejectedOrigins, relyingPartyError)
		}
	}
}

func TestSetupConfirmWebAuthnAcceptsVirtualAuthenticator(testContext *testing.T) {
	relyingParty := newTestWebAuthn(testContext)
	setup := &Setup{}
	attestationOptions := beginRegistration(testContext, relyingParty, setup, "alice")

	confirmError := setup.ConfirmWebAuthn(relyingParty, newVirtualKey(0).attest(legitimateBrowser, attestationOptions))

	if confirmError != nil {
		testContext.Fatalf("expected the virtual authenticator to register, got %v", confirmError)
	}
	if _, codesError := setup.RecoveryCodes(); codesError != nil {
		testContext.Fatalf("a confirmed WebAuthn credential must count as a second factor, got %v", codesError)
	}
	if !setup.Ready() {
		testContext.Error("setup must be ready once WebAuthn is confirmed and codes generated")
	}
}

func TestSetupBeginWebAuthnKeepsOneRandomUserHandle(testContext *testing.T) {
	relyingParty := newTestWebAuthn(testContext)
	setup := &Setup{}

	firstOptions := beginRegistration(testContext, relyingParty, setup, "alice")
	secondOptions := beginRegistration(testContext, relyingParty, setup, "alice")
	otherSetupOptions := beginRegistration(testContext, relyingParty, &Setup{}, "alice")

	if len(firstOptions.UserID) != 32 {
		testContext.Fatalf("expected a 32-byte user handle, got %d bytes", len(firstOptions.UserID))
	}
	if firstOptions.UserID != secondOptions.UserID {
		testContext.Error("the user handle must stay the same for one setup")
	}
	if firstOptions.UserID == otherSetupOptions.UserID || firstOptions.UserID == "alice" {
		testContext.Error("the user handle must be random, not derived from the account name")
	}
	if bytes.Equal(firstOptions.Challenge, secondOptions.Challenge) {
		testContext.Error("each BeginWebAuthn must issue a fresh challenge")
	}
}

func TestSetupConfirmWebAuthnRejectsOtherChallenge(testContext *testing.T) {
	relyingParty := newTestWebAuthn(testContext)
	setup := &Setup{}
	attestationOptions := beginRegistration(testContext, relyingParty, setup, "alice")
	forgedOptions := *attestationOptions
	forgedOptions.Challenge = bytes.Repeat([]byte{42}, len(attestationOptions.Challenge))

	confirmError := setup.ConfirmWebAuthn(relyingParty, newVirtualKey(0).attest(legitimateBrowser, &forgedOptions))

	if !errors.Is(confirmError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", confirmError)
	}
	if _, codesError := setup.RecoveryCodes(); !errors.Is(codesError, ErrNoConfirmedFactor) {
		testContext.Errorf("a failed registration must not confirm a factor, got %v", codesError)
	}
}

func TestSetupConfirmWebAuthnRejectsOtherOrigin(testContext *testing.T) {
	relyingParty := newTestWebAuthn(testContext)
	setup := &Setup{}
	attestationOptions := beginRegistration(testContext, relyingParty, setup, "alice")
	phishingBrowser := legitimateBrowser
	phishingBrowser.Origin = "https://evil.example.net"

	confirmError := setup.ConfirmWebAuthn(relyingParty, newVirtualKey(0).attest(phishingBrowser, attestationOptions))

	if !errors.Is(confirmError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", confirmError)
	}
}

func TestSetupConfirmWebAuthnWithoutBeginFails(testContext *testing.T) {
	relyingParty := newTestWebAuthn(testContext)
	attestationOptions := beginRegistration(testContext, relyingParty, &Setup{}, "alice")

	confirmError := (&Setup{}).ConfirmWebAuthn(relyingParty, newVirtualKey(0).attest(legitimateBrowser, attestationOptions))

	if !errors.Is(confirmError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", confirmError)
	}
}

func TestSetupConfirmWebAuthnConsumesRegistrationChallenge(testContext *testing.T) {
	relyingParty := newTestWebAuthn(testContext)

	confirmedSetup := &Setup{}
	validResponse := newVirtualKey(0).attest(legitimateBrowser, beginRegistration(testContext, relyingParty, confirmedSetup, "alice"))
	if firstError := confirmedSetup.ConfirmWebAuthn(relyingParty, validResponse); firstError != nil {
		testContext.Fatal(firstError)
	}
	if replayError := confirmedSetup.ConfirmWebAuthn(relyingParty, validResponse); !errors.Is(replayError, ErrWebAuthnFailed) {
		testContext.Errorf("the same registration response twice: expected ErrWebAuthnFailed, got %v", replayError)
	}

	failedSetup := &Setup{}
	attestationOptions := beginRegistration(testContext, relyingParty, failedSetup, "alice")
	key := newVirtualKey(0)
	if malformedError := failedSetup.ConfirmWebAuthn(relyingParty, []byte(`{"id":"broken"}`)); !errors.Is(malformedError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed for a malformed response, got %v", malformedError)
	}
	if retryError := failedSetup.ConfirmWebAuthn(relyingParty, key.attest(legitimateBrowser, attestationOptions)); !errors.Is(retryError, ErrWebAuthnFailed) {
		testContext.Errorf("a valid response after a failure without a new BeginWebAuthn: expected ErrWebAuthnFailed, got %v", retryError)
	}
}

type webAuthnAccount struct {
	accountID int64
	key       *virtualKey
}

type webAuthnFixture struct {
	database     *bun.DB
	repository   *Repository
	relyingParty *WebAuthn
}

func newWebAuthnFixture(testContext *testing.T) webAuthnFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	return webAuthnFixture{database, NewRepository(database, newKeyring(testContext)), newTestWebAuthn(testContext)}
}

func (fixture webAuthnFixture) enroll(testContext *testing.T, accountName string, initialCounter uint32) webAuthnAccount {
	testContext.Helper()
	ctx := context.Background()
	accountID, createError := createTestAccount(ctx, fixture.database, accountName)
	if createError != nil {
		testContext.Fatal(createError)
	}
	setup := &Setup{}
	key := newVirtualKey(initialCounter)
	if confirmError := setup.ConfirmWebAuthn(fixture.relyingParty, key.attest(legitimateBrowser, beginRegistration(testContext, fixture.relyingParty, setup, accountName))); confirmError != nil {
		testContext.Fatal(confirmError)
	}
	if _, codesError := setup.RecoveryCodes(); codesError != nil {
		testContext.Fatal(codesError)
	}
	if saveError := fixture.repository.SaveSetup(ctx, fixture.database, accountID, setup); saveError != nil {
		testContext.Fatalf("save setup: %v", saveError)
	}
	key.authenticator.AddCredential(key.credential)
	return webAuthnAccount{accountID: accountID, key: key}
}

func (fixture webAuthnFixture) beginLogin(testContext *testing.T, accountID int64) (*virtualwebauthn.AssertionOptions, webauthn.SessionData) {
	testContext.Helper()
	assertion, session, beginError := fixture.repository.BeginWebAuthnLogin(context.Background(), fixture.relyingParty, accountID)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	assertionOptions, parseError := virtualwebauthn.ParseAssertionOptions(encodeOptions(testContext, assertion))
	if parseError != nil {
		testContext.Fatal(parseError)
	}
	return assertionOptions, *session
}

func (fixture webAuthnFixture) finishLogin(accountID int64, session webauthn.SessionData, responseBody []byte) error {
	return fixture.repository.FinishWebAuthnLogin(context.Background(), fixture.relyingParty, accountID, session, responseBody)
}

func (fixture webAuthnFixture) storedSignCount(testContext *testing.T, accountID int64) int64 {
	testContext.Helper()
	var signCount int64
	queryError := fixture.database.NewRaw(
		`SELECT COALESCE((credential_webauthn_data->'authenticator'->>'signCount')::bigint, 0) FROM credential
		 WHERE credential_account_id = ? AND credential_kind = 'webauthn'`, accountID).Scan(context.Background(), &signCount)
	if queryError != nil {
		testContext.Fatal(queryError)
	}
	return signCount
}

func TestSaveSetupPersistsWebAuthnCredentialAndUserHandle(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 0)

	var userHandle []byte
	if queryError := fixture.database.NewRaw(`SELECT account_webauthn_user_handle FROM account WHERE account_id = ?`, alice.accountID).
		Scan(context.Background(), &userHandle); queryError != nil {
		testContext.Fatal(queryError)
	}
	methods, methodsError := fixture.repository.Methods(context.Background(), alice.accountID)

	if len(userHandle) != 32 {
		testContext.Errorf("expected a 32-byte user handle, got %d bytes", len(userHandle))
	}
	if methodsError != nil || len(methods) != 1 || methods[0] != "webauthn" {
		testContext.Errorf("expected [webauthn], got %v (%v)", methods, methodsError)
	}
}

func TestFinishLoginAcceptsRegisteredCredential(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 0)
	assertionOptions, session := fixture.beginLogin(testContext, alice.accountID)

	finishError := fixture.finishLogin(alice.accountID, session, alice.key.assert(legitimateBrowser, assertionOptions))

	if finishError != nil {
		testContext.Fatalf("expected the registered credential to log in, got %v", finishError)
	}
}

func TestFinishLoginRejectsOtherOrigin(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 0)
	assertionOptions, session := fixture.beginLogin(testContext, alice.accountID)
	phishingBrowser := legitimateBrowser
	phishingBrowser.Origin = "https://evil.example.net"

	finishError := fixture.finishLogin(alice.accountID, session, alice.key.assert(phishingBrowser, assertionOptions))

	if !errors.Is(finishError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", finishError)
	}
}

func TestFinishLoginRejectsOtherRPID(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 0)
	assertionOptions, session := fixture.beginLogin(testContext, alice.accountID)
	otherRelyingPartyBrowser := legitimateBrowser
	otherRelyingPartyBrowser.ID = "evil.example.net"

	finishError := fixture.finishLogin(alice.accountID, session, alice.key.assert(otherRelyingPartyBrowser, assertionOptions))

	if !errors.Is(finishError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", finishError)
	}
}

func TestFinishLoginRejectsCredentialOfOtherAccount(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 0)
	bob := fixture.enroll(testContext, "bob", 0)
	assertionOptions, session := fixture.beginLogin(testContext, alice.accountID)

	finishError := fixture.finishLogin(alice.accountID, session, bob.key.assert(legitimateBrowser, assertionOptions))

	if !errors.Is(finishError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", finishError)
	}
}

func TestFinishLoginRejectsSessionOfOtherAccount(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 0)
	bob := fixture.enroll(testContext, "bob", 0)
	bobOptions, bobSession := fixture.beginLogin(testContext, bob.accountID)

	finishError := fixture.finishLogin(alice.accountID, bobSession, bob.key.assert(legitimateBrowser, bobOptions))

	if !errors.Is(finishError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", finishError)
	}
}

func TestBeginLoginFailsForAccountWithoutWebAuthn(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	totpAccountID, _, _ := enrollAccount(testContext, fixture.database, fixture.repository, "carol")

	_, _, beginError := fixture.repository.BeginWebAuthnLogin(context.Background(), fixture.relyingParty, totpAccountID)

	if !errors.Is(beginError, ErrWebAuthnFailed) {
		testContext.Fatalf("expected ErrWebAuthnFailed, got %v", beginError)
	}
}

func TestFinishLoginRejectsNonIncreasingCounter(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 5)
	alice.key.credential.Counter = 6
	assertionOptions, session := fixture.beginLogin(testContext, alice.accountID)
	assertionResponse := alice.key.assert(legitimateBrowser, assertionOptions)

	if firstError := fixture.finishLogin(alice.accountID, session, assertionResponse); firstError != nil {
		testContext.Fatalf("expected the first assertion to pass, got %v", firstError)
	}
	if signCount := fixture.storedSignCount(testContext, alice.accountID); signCount != 6 {
		testContext.Fatalf("expected the counter 6 to be recorded, got %d", signCount)
	}
	replayError := fixture.finishLogin(alice.accountID, session, assertionResponse)

	if !errors.Is(replayError, ErrWebAuthnFailed) {
		testContext.Fatalf("a non-increasing counter must be refused as a clone, got %v", replayError)
	}
	if signCount := fixture.storedSignCount(testContext, alice.accountID); signCount != 6 {
		testContext.Errorf("a refused assertion must not change the counter, got %d", signCount)
	}
}

func TestFinishLoginLeavesZeroCounterReplayToChallengeConsumption(testContext *testing.T) {
	fixture := newWebAuthnFixture(testContext)
	alice := fixture.enroll(testContext, "alice", 0)
	assertionOptions, session := fixture.beginLogin(testContext, alice.accountID)
	assertionResponse := alice.key.assert(legitimateBrowser, assertionOptions)

	firstError := fixture.finishLogin(alice.accountID, session, assertionResponse)
	replayError := fixture.finishLogin(alice.accountID, session, assertionResponse)

	if firstError != nil || replayError != nil {
		testContext.Fatalf("a passkey keeping signCount 0 never raises CloneWarning: the repository must not be relied on for single use (login.Service consumes the session), got %v / %v", firstError, replayError)
	}
}
