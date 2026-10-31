package login

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/secondfactor"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/sessions"
	"crowdsec-dashboard/internal/store/storetest"
)

const (
	testPassword           = "correct horse battery"
	wrongPassword          = "wrong horse battery"
	neverMatchingTOTPCode  = "abcdef"
	totpPeriod             = 30 * time.Second
	testRelyingPartyID     = "dashboard.example.com"
	testRelyingPartyOrigin = "https://dashboard.example.com"
)

var legitimateBrowser = virtualwebauthn.RelyingParty{ID: testRelyingPartyID, Name: "CrowdSec Dashboard", Origin: testRelyingPartyOrigin}

type recordedEvent struct {
	accountID int64
	action    audit.Action
	target    string
	clientIP  string
}

// memoryRecorder keeps audit events in memory so tests can assert the exact
// sequence the service writes, without querying audit_event.
type memoryRecorder struct {
	mutex  sync.Mutex
	events []recordedEvent
}

func (recorder *memoryRecorder) Record(_ context.Context, accountID int64, action audit.Action, target, clientIP string) error {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.events = append(recorder.events, recordedEvent{accountID, action, target, clientIP})
	return nil
}

func (recorder *memoryRecorder) eventsWithAction(action audit.Action) []recordedEvent {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	var matchingEvents []recordedEvent
	for _, recorded := range recorder.events {
		if recorded.action == action {
			matchingEvents = append(matchingEvents, recorded)
		}
	}
	return matchingEvents
}

type fakeGeolocator struct {
	countryCode string
	lookupError error
}

func (geolocator fakeGeolocator) CountryCode(context.Context, netip.Addr) (string, error) {
	return geolocator.countryCode, geolocator.lookupError
}

// countingFactors wraps the real repository and counts the verifications that
// actually reach it: the attempt caps are proven by these counters, not by the
// error values alone. forcedTOTPError simulates a non-ErrInvalidCode failure
// (for example a secret that no longer decrypts).
type countingFactors struct {
	*secondfactor.Repository
	totpVerifications   atomic.Int64
	webAuthnFinishCalls atomic.Int64
	forcedTOTPError     error
}

func (factors *countingFactors) VerifyTOTP(ctx context.Context, accountID int64, code string, now time.Time) error {
	factors.totpVerifications.Add(1)
	if factors.forcedTOTPError != nil {
		return factors.forcedTOTPError
	}
	return factors.Repository.VerifyTOTP(ctx, accountID, code, now)
}

func (factors *countingFactors) FinishWebAuthnLogin(ctx context.Context, relyingParty *secondfactor.WebAuthn, accountID int64, session webauthn.SessionData, responseBody []byte) error {
	factors.webAuthnFinishCalls.Add(1)
	return factors.Repository.FinishWebAuthnLogin(ctx, relyingParty, accountID, session, responseBody)
}

type loginFixture struct {
	database     *bun.DB
	accounts     *accounts.Repository
	factors      *countingFactors
	sessions     *sessions.PostgresStore
	relyingParty *secondfactor.WebAuthn
	recorder     *memoryRecorder
	clock        *testClock
	service      *Service
}

type fixtureOptions struct {
	geolocator       fakeGeolocator
	maxPendingLogins int
}

func newLoginFixture(testContext *testing.T) *loginFixture {
	return newLoginFixtureWith(testContext, fixtureOptions{})
}

func newLoginFixtureWith(testContext *testing.T, options fixtureOptions) *loginFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	keyring, keyringError := secrets.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if keyringError != nil {
		testContext.Fatal(keyringError)
	}
	relyingParty, relyingPartyError := secondfactor.NewWebAuthn(testRelyingPartyID, []string{testRelyingPartyOrigin})
	if relyingPartyError != nil {
		testContext.Fatal(relyingPartyError)
	}
	clock := newTestClock()
	fixture := &loginFixture{
		database:     database,
		accounts:     accounts.NewRepository(database),
		factors:      &countingFactors{Repository: secondfactor.NewRepository(database, keyring)},
		sessions:     sessions.NewPostgresStore(database, time.Hour, clock.Now),
		relyingParty: relyingParty,
		recorder:     &memoryRecorder{},
		clock:        clock,
	}
	fixture.service = NewService(Dependencies{
		Authenticator:    fixture.accounts,
		Accounts:         fixture.accounts,
		Sessions:         fixture.sessions,
		SecondFactors:    fixture.factors,
		WebAuthn:         relyingParty,
		AccessRules:      accessrule.NewRepository(database),
		Geolocator:       options.geolocator,
		Audit:            fixture.recorder,
		Database:         database,
		Now:              clock.Now,
		MaxPendingLogins: options.maxPendingLogins,
	})
	return fixture
}

func (fixture *loginFixture) createAccount(testContext *testing.T, accountName string) int64 {
	testContext.Helper()
	passwordHash, hashError := accounts.HashPassword(testPassword)
	if hashError != nil {
		testContext.Fatal(hashError)
	}
	accountID, createError := fixture.accounts.CreateWithPasswordHash(context.Background(), accountName, passwordHash, "admin")
	if createError != nil {
		testContext.Fatal(createError)
	}
	return accountID
}

func (fixture *loginFixture) totpCode(testContext *testing.T, secret string) string {
	testContext.Helper()
	generatedCode, generateError := totp.GenerateCodeCustom(secret, fixture.clock.Now(), totp.ValidateOpts{
		Period: uint(totpPeriod / time.Second), Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if generateError != nil {
		testContext.Fatal(generateError)
	}
	return generatedCode
}

type totpAccount struct {
	accountID     int64
	secret        string
	recoveryCodes []string
}

func (fixture *loginFixture) createTOTPAccount(testContext *testing.T, accountName string) totpAccount {
	testContext.Helper()
	accountID := fixture.createAccount(testContext, accountName)
	setup := &secondfactor.Setup{}
	secret := fixture.confirmTOTP(testContext, setup, accountName)
	recoveryCodes, codesError := setup.RecoveryCodes()
	if codesError != nil {
		testContext.Fatal(codesError)
	}
	if saveError := fixture.factors.SaveSetup(context.Background(), fixture.database, accountID, setup); saveError != nil {
		testContext.Fatal(saveError)
	}
	fixture.clock.Advance(totpPeriod)
	return totpAccount{accountID: accountID, secret: secret, recoveryCodes: recoveryCodes}
}

func (fixture *loginFixture) confirmTOTP(testContext *testing.T, setup *secondfactor.Setup, accountName string) string {
	testContext.Helper()
	enrollment, beginError := setup.BeginTOTP(accountName)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	if confirmError := setup.ConfirmTOTP(fixture.totpCode(testContext, enrollment.Secret), fixture.clock.Now()); confirmError != nil {
		testContext.Fatal(confirmError)
	}
	return enrollment.Secret
}

type virtualKey struct {
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
}

func (fixture *loginFixture) createWebAuthnAccount(testContext *testing.T, accountName string) (int64, *virtualKey) {
	testContext.Helper()
	accountID := fixture.createAccount(testContext, accountName)
	setup := &secondfactor.Setup{}
	creation, beginError := setup.BeginWebAuthn(fixture.relyingParty, accountName)
	if beginError != nil {
		testContext.Fatal(beginError)
	}
	attestationOptions, parseError := virtualwebauthn.ParseAttestationOptions(encodeJSON(testContext, creation))
	if parseError != nil {
		testContext.Fatal(parseError)
	}
	key := &virtualKey{authenticator: virtualwebauthn.NewAuthenticator(), credential: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(legitimateBrowser, key.authenticator, key.credential, *attestationOptions)
	if confirmError := setup.ConfirmWebAuthn(fixture.relyingParty, []byte(attestationResponse)); confirmError != nil {
		testContext.Fatal(confirmError)
	}
	if _, codesError := setup.RecoveryCodes(); codesError != nil {
		testContext.Fatal(codesError)
	}
	if saveError := fixture.factors.SaveSetup(context.Background(), fixture.database, accountID, setup); saveError != nil {
		testContext.Fatal(saveError)
	}
	key.authenticator.AddCredential(key.credential)
	return accountID, key
}

func (fixture *loginFixture) assertionFor(testContext *testing.T, key *virtualKey, pendingID string) []byte {
	testContext.Helper()
	assertion, optionsError := fixture.service.WebAuthnOptions(context.Background(), pendingID, clientAddress)
	if optionsError != nil {
		testContext.Fatal(optionsError)
	}
	assertionOptions, parseError := virtualwebauthn.ParseAssertionOptions(encodeJSON(testContext, assertion))
	if parseError != nil {
		testContext.Fatal(parseError)
	}
	return []byte(virtualwebauthn.CreateAssertionResponse(legitimateBrowser, key.authenticator, key.credential, *assertionOptions))
}

func encodeJSON(testContext *testing.T, value any) string {
	testContext.Helper()
	encodedValue, marshalError := json.Marshal(value)
	if marshalError != nil {
		testContext.Fatal(marshalError)
	}
	return string(encodedValue)
}

func (fixture *loginFixture) beginOrFail(testContext *testing.T, accountName string) BeginResult {
	testContext.Helper()
	beginResult, beginError := fixture.service.Begin(context.Background(), accountName, testPassword, clientAddress)
	if beginError != nil {
		testContext.Fatalf("begin: %v", beginError)
	}
	return beginResult
}

func (fixture *loginFixture) addAccessRule(testContext *testing.T, accountID int64, kind, value string) {
	testContext.Helper()
	if _, insertError := fixture.database.ExecContext(context.Background(),
		`INSERT INTO access_rule (access_rule_account_id, access_rule_kind, access_rule_value) VALUES (?, ?, ?)`,
		accountID, kind, value); insertError != nil {
		testContext.Fatal(insertError)
	}
}

func (fixture *loginFixture) openSetupWindow(testContext *testing.T, accountID int64, columnValue string) {
	testContext.Helper()
	if _, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE account SET account_second_factor_setup_until = ?::timestamptz WHERE account_id = ?`, columnValue, accountID); updateError != nil {
		testContext.Fatal(updateError)
	}
}

// runConcurrently starts every call at the same instant so the attempt caps
// are exercised by real contention, not by sequential calls.
func runConcurrently(callCount int, call func()) {
	var waitGroup sync.WaitGroup
	startSignal := make(chan struct{})
	for callNumber := 0; callNumber < callCount; callNumber++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-startSignal
			call()
		}()
	}
	close(startSignal)
	waitGroup.Wait()
}
