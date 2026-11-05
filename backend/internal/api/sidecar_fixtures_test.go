package api

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/sidecarauth"
)

const (
	sidecarTestEngineName = "peer"
	sidecarTestIssuer     = "dashboard.example.com"
	sidecarTestURL        = "https://sidecar.example.com:8443"
	sidecarObservedPin    = "aa00000000000000000000000000000000000000000000000000000000000000"
	sidecarOtherPin       = "bb00000000000000000000000000000000000000000000000000000000000000"
)

// errSidecarNotFaked marks the sidecar methods of the generic engine fake: the
// tests that exercise the sidecar routes use fakeSidecarEngineService instead.
var errSidecarNotFaked = errors.New("sidecar behaviour is not faked by fakeEngineService")

func (service *fakeEngineService) ObserveSidecar(context.Context, string, string) (string, error) {
	return "", errSidecarNotFaked
}

func (service *fakeEngineService) ConfigureSidecar(context.Context, string, engines.SidecarInput) (engines.Engine, error) {
	return engines.Engine{}, errSidecarNotFaked
}

func (service *fakeEngineService) StageSidecarKey(context.Context, string) (engines.Engine, error) {
	return engines.Engine{}, errSidecarNotFaked
}

func (service *fakeEngineService) PromoteSidecarKey(context.Context, string) (engines.Engine, error) {
	return engines.Engine{}, errSidecarNotFaked
}

func (service *fakeEngineService) RemoveSidecar(context.Context, string) error {
	return errSidecarNotFaked
}

func (service *fakeEngineService) PingSidecar(context.Context, string, bool) error {
	return errSidecarNotFaked
}

// fakeSidecarEngineService records every sidecar call so a test can prove a
// refused request never reached the repository, the registry or the network.
type fakeSidecarEngineService struct {
	*fakeEngineService
	observedPin      string
	observeError     error
	observedURLs     []string
	configureInputs  []engines.SidecarInput
	configureError   error
	stageCount       int
	stageError       error
	promoteCount     int
	promoteError     error
	removedNames     []string
	removeError      error
	pingedWithNext   []bool
	pingError        error
	nextPingError    error
	enrolledEngine   engines.Engine
	currentSecretHex string
	nextSecretHex    string
}

func (service *fakeSidecarEngineService) ObserveSidecar(_ context.Context, _ string, sidecarURL string) (string, error) {
	service.observedURLs = append(service.observedURLs, sidecarURL)
	return service.observedPin, service.observeError
}

func (service *fakeSidecarEngineService) ConfigureSidecar(_ context.Context, _ string, input engines.SidecarInput) (engines.Engine, error) {
	service.configureInputs = append(service.configureInputs, input)
	return service.enrolledEngine, service.configureError
}

func (service *fakeSidecarEngineService) StageSidecarKey(context.Context, string) (engines.Engine, error) {
	service.stageCount++
	return service.enrolledEngine, service.stageError
}

func (service *fakeSidecarEngineService) PromoteSidecarKey(context.Context, string) (engines.Engine, error) {
	service.promoteCount++
	return service.enrolledEngine, service.promoteError
}

func (service *fakeSidecarEngineService) RemoveSidecar(_ context.Context, name string) error {
	service.removedNames = append(service.removedNames, name)
	return service.removeError
}

func (service *fakeSidecarEngineService) PingSidecar(_ context.Context, _ string, useNextKey bool) error {
	service.pingedWithNext = append(service.pingedWithNext, useNextKey)
	if useNextKey {
		return service.nextPingError
	}
	return service.pingError
}

func (service *fakeSidecarEngineService) sidecarCalls() int {
	return len(service.observedURLs) + len(service.configureInputs) + service.stageCount + service.promoteCount +
		len(service.removedNames) + len(service.pingedWithNext)
}

type sidecarFixture struct {
	engineFixture
	sidecarService *fakeSidecarEngineService
}

// newSidecarFixture serves the real route table with an engine "peer" enrolled
// with two freshly generated signing keys, so the tests can search every
// response for the secret halves the views must never carry.
func newSidecarFixture(testContext *testing.T, accountRole, issuer string) sidecarFixture {
	testContext.Helper()
	currentKey := mustGenerateSigningKey(testContext)
	nextKey := mustGenerateSigningKey(testContext)
	enrolledEngine := engines.Engine{Name: sidecarTestEngineName, LAPIURL: "https://peer.example.com", Enabled: true,
		Sidecar: &engines.Sidecar{
			URL: sidecarTestURL, SPKISHA256: sidecarObservedPin,
			KeyID: currentKey.KeyID, PublicKeyHex: currentKey.PublicKeyHex(),
			NextKeyID: nextKey.KeyID, NextPublicKeyHex: nextKey.PublicKeyHex(),
		}}
	genericService := &fakeEngineService{engineList: []engines.Engine{enrolledEngine}}
	sidecarService := &fakeSidecarEngineService{
		fakeEngineService: genericService,
		observedPin:       sidecarObservedPin,
		enrolledEngine:    enrolledEngine,
		currentSecretHex:  hex.EncodeToString(currentKey.SecretBytes()),
		nextSecretHex:     hex.EncodeToString(nextKey.SecretBytes()),
	}
	recorder := &fakeAuditRecorder{}
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		return auth.AccountIdentity{AccountID: accountID, AccountName: authtest.AccountName, AccountRole: accountRole}, true
	})
	handler := newHandler(config.Config{SessionTTL: time.Hour, WebAuthnRPID: issuer}, http.NotFoundHandler(), 0, Services{
		Engines:  sidecarService,
		Audit:    recorder,
		Sessions: sessions,
	})
	return sidecarFixture{
		engineFixture:  engineFixture{handler: handler, cookie: newAuthenticatedCookie(testContext, sessions, testAccountID), service: genericService, recorder: recorder},
		sidecarService: sidecarService,
	}
}

func mustGenerateSigningKey(testContext *testing.T) sidecarauth.SigningKey {
	testContext.Helper()
	generatedKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("generate signing key: %v", generateError)
	}
	return generatedKey
}

func configureSidecarBody(confirm, pin string) string {
	return `{"url":"` + sidecarTestURL + `","spki_sha256":"` + pin + `","confirm":"` + confirm + `"}`
}
