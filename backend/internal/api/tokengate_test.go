package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/geo"
)

type countingRuleLister struct {
	rulesByAccount map[int64][]accessrule.Rule
	listCalls      int
}

func (lister *countingRuleLister) List(_ context.Context, accountID int64) ([]accessrule.Rule, error) {
	lister.listCalls++
	return lister.rulesByAccount[accountID], nil
}

const gateTestToken = "csd_gate-token"

func serveWithGate(gate auth.TokenGate, clientAddress string, identity auth.AccountIdentity) *httptest.ResponseRecorder {
	tokens := authtest.NewTokenStore(map[string]auth.AccountIdentity{gateTestToken: identity})
	handler := auth.RequireAuthentication(authtest.NewSessionStore(time.Hour, time.Now), tokens, gate, nil)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request.RemoteAddr = clientAddress + ":5000"
	request.Header.Set("Authorization", "Bearer "+gateTestToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestTokenRefusedOutsideAccountAccessRules(testContext *testing.T) {
	lister := &countingRuleLister{rulesByAccount: map[int64][]accessrule.Rule{5: {{Kind: accessrule.KindIP, Value: "192.0.2.0/24"}}}}
	gate := NewTokenGate(lister, geo.Unavailable{}, time.Now)
	identity := auth.AccountIdentity{AccountID: 5, AccountRole: auth.RoleAdmin}

	deniedResponse := serveWithGate(gate, "198.51.100.7", identity)
	allowedResponse := serveWithGate(gate, "192.0.2.10", identity)

	if deniedResponse.Code != http.StatusForbidden || deniedResponse.Body.String() != "{\"error\":\"token_denied\"}\n" {
		testContext.Errorf("unexpected denied response %d %q", deniedResponse.Code, deniedResponse.Body.String())
	}
	if allowedResponse.Code != http.StatusNoContent {
		testContext.Errorf("expected 204, got %d", allowedResponse.Code)
	}
}

func TestTokenRefusedWhileAccountLocked(testContext *testing.T) {
	currentTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	gate := NewTokenGate(&countingRuleLister{}, geo.Unavailable{}, func() time.Time { return currentTime })
	lockedIdentity := auth.AccountIdentity{AccountID: 5, LockedUntil: currentTime.Add(time.Minute)}
	expiredLockIdentity := auth.AccountIdentity{AccountID: 5, LockedUntil: currentTime.Add(-time.Minute)}

	lockedResponse := serveWithGate(gate, "198.51.100.7", lockedIdentity)
	expiredLockResponse := serveWithGate(gate, "198.51.100.7", expiredLockIdentity)

	if lockedResponse.Code != http.StatusForbidden {
		testContext.Errorf("locked account must be refused, got %d", lockedResponse.Code)
	}
	if expiredLockResponse.Code != http.StatusNoContent {
		testContext.Errorf("expired lock must not refuse, got %d", expiredLockResponse.Code)
	}
}

func TestTokenGateCachesDecisionPerAccountAndClientForOneMinute(testContext *testing.T) {
	currentTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	lister := &countingRuleLister{}
	gate := NewTokenGate(lister, geo.Unavailable{}, func() time.Time { return currentTime })
	identity := auth.AccountIdentity{AccountID: 5}
	clientAddress := netip.MustParseAddr("198.51.100.7")

	gate.AllowToken(context.Background(), identity, clientAddress)
	gate.AllowToken(context.Background(), identity, clientAddress)
	callsWithinMinute := lister.listCalls
	currentTime = currentTime.Add(tokenGateCacheLifetime + time.Second)
	gate.AllowToken(context.Background(), identity, clientAddress)

	if callsWithinMinute != 1 || lister.listCalls != 2 {
		testContext.Errorf("unexpected list calls: within minute %d, total %d", callsWithinMinute, lister.listCalls)
	}
}
