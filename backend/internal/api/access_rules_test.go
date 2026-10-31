package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/geo"
)

type fakeAccessRules struct {
	rules          []accessrule.Rule
	addError       error
	seenClientIP   netip.Addr
	seenAccountID  int64
	seenAddedKind  string
	seenAddedValue string
}

func (service *fakeAccessRules) List(_ context.Context, _ int64) ([]accessrule.Rule, error) {
	return service.rules, nil
}

func (service *fakeAccessRules) Add(_ context.Context, accountID int64, kind, value string, clientIP netip.Addr, _ geo.Geolocator) (accessrule.Rule, error) {
	service.seenAccountID, service.seenClientIP, service.seenAddedKind, service.seenAddedValue = accountID, clientIP, kind, value
	if service.addError != nil {
		return accessrule.Rule{}, service.addError
	}
	canonicalValue, canonicalError := accessrule.Canonicalize(kind, value)
	if canonicalError != nil {
		return accessrule.Rule{}, canonicalError
	}
	return accessrule.Rule{ID: 5, Kind: kind, Value: canonicalValue}, nil
}

func (service *fakeAccessRules) Delete(_ context.Context, _, ruleID int64, _ netip.Addr, _ geo.Geolocator) error {
	for _, existingRule := range service.rules {
		if existingRule.ID == ruleID {
			return nil
		}
	}
	return accessrule.ErrRuleNotFound
}

type recordedAuditEvent struct {
	action   audit.Action
	target   string
	clientIP string
}

type fakeAuditRecorder struct{ events []recordedAuditEvent }

func (recorder *fakeAuditRecorder) Record(_ context.Context, _ int64, action audit.Action, target, clientIP string) error {
	recorder.events = append(recorder.events, recordedAuditEvent{action: action, target: target, clientIP: clientIP})
	return nil
}

type fixedGeolocator string

func (geolocator fixedGeolocator) CountryCode(context.Context, netip.Addr) (string, error) {
	return string(geolocator), nil
}

type accessRuleFixture struct {
	handler  http.Handler
	cookie   *http.Cookie
	service  *fakeAccessRules
	recorder *fakeAuditRecorder
}

func newAccessRuleFixture(testContext *testing.T, trustedProxyCIDRs []*net.IPNet) accessRuleFixture {
	testContext.Helper()
	service := &fakeAccessRules{}
	recorder := &fakeAuditRecorder{}
	handler := newHandler(config.Config{SessionTTL: time.Hour, TrustedProxyCIDRs: trustedProxyCIDRs}, http.NotFoundHandler(), 0, Services{
		AccessRules:   service,
		Geolocator:    fixedGeolocator("FR"),
		Audit:         recorder,
		Sessions:      authtest.NewSessionStore(time.Hour, time.Now),
		Authenticator: authtest.NewAuthenticator(map[string]string{testAccountName: testPassword}),
	})
	cookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	return accessRuleFixture{handler: handler, cookie: cookie, service: service, recorder: recorder}
}

func (fixture accessRuleFixture) send(method, path, body, forwardedFor string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	if forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", forwardedFor)
	}
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestAccessRulesRequireSession(testContext *testing.T) {
	handler := newAccessRuleFixture(testContext, nil).handler
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/account/access-rules"},
		{http.MethodPost, "/api/account/access-rules"},
		{http.MethodDelete, "/api/account/access-rules/1"},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(route.method, "https://dashboard.example.com"+route.path, nil))
		if recorder.Code != http.StatusUnauthorized {
			testContext.Errorf("%s %s: expected 401, got %d", route.method, route.path, recorder.Code)
		}
	}
}

func TestAddAccessRuleReturns409WhenItWouldLockOutTheCaller(testContext *testing.T) {
	fixture := newAccessRuleFixture(testContext, nil)
	fixture.service.addError = accessrule.ErrWouldLockOut

	recorder := fixture.send(http.MethodPost, "/api/account/access-rules", `{"kind":"ip","value":"203.0.113.0/24"}`, "")

	expectError(testContext, recorder, http.StatusConflict, "would_lock_out_current_client")
	if len(fixture.recorder.events) != 0 {
		testContext.Errorf("no audit event expected, got %+v", fixture.recorder.events)
	}
}

func TestAddAccessRuleRecordsAudit(testContext *testing.T) {
	fixture := newAccessRuleFixture(testContext, nil)

	recorder := fixture.send(http.MethodPost, "/api/account/access-rules", `{"kind":"ip","value":"198.51.100.0/24"}`, "")

	if recorder.Code != http.StatusCreated || strings.TrimSpace(recorder.Body.String()) != `{"id":5,"kind":"ip","value":"198.51.100.0/24"}` {
		testContext.Fatalf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	expectedEvent := recordedAuditEvent{action: audit.ActionAccessRuleAdded, target: "ip:198.51.100.0/24", clientIP: "198.51.100.7"}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0] != expectedEvent {
		testContext.Errorf("unexpected audit events %+v", fixture.recorder.events)
	}
}

func TestAddAccessRuleRejectsUnknownFieldsAndMapsErrors(testContext *testing.T) {
	fixture := newAccessRuleFixture(testContext, nil)
	expectError(testContext, fixture.send(http.MethodPost, "/api/account/access-rules", `{"kind":"ip","value":"1.1.1.1","extra":1}`, ""), http.StatusBadRequest, "invalid_access_rule")

	for expectedCode, serviceError := range map[string]error{
		"access_rule_exists":      accessrule.ErrRuleExists,
		"geolocation_unavailable": accessrule.ErrGeolocationUnavailable,
		"invalid_access_rule":     accessrule.ErrInvalidRule,
	} {
		fixture.service.addError = serviceError
		recorder := fixture.send(http.MethodPost, "/api/account/access-rules", `{"kind":"country","value":"FR"}`, "")
		if !strings.Contains(recorder.Body.String(), expectedCode) {
			testContext.Errorf("%v: expected %s, got %d %q", serviceError, expectedCode, recorder.Code, recorder.Body.String())
		}
	}
}

func TestListAccessRulesReportsClientIPBehindTrustedProxy(testContext *testing.T) {
	fixture := newAccessRuleFixture(testContext, []*net.IPNet{mustParseCIDR(testContext, "198.51.100.0/24")})
	fixture.service.rules = []accessrule.Rule{{ID: 1, Kind: "country", Value: "FR"}}

	recorder := fixture.send(http.MethodGet, "/api/account/access-rules", "", "203.0.113.9")

	expectedBody := `{"rules":[{"id":1,"kind":"country","value":"FR"}],"client_ip":"203.0.113.9","client_country":"FR"}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestDeleteAccessRuleRecordsAuditAndReturns404ForUnknownRule(testContext *testing.T) {
	fixture := newAccessRuleFixture(testContext, nil)
	fixture.service.rules = []accessrule.Rule{{ID: 1, Kind: "ip", Value: "198.51.100.0/24"}}

	expectError(testContext, fixture.send(http.MethodDelete, "/api/account/access-rules/9", "", ""), http.StatusNotFound, "not_found")
	recorder := fixture.send(http.MethodDelete, "/api/account/access-rules/1", "", "")

	if recorder.Code != http.StatusNoContent {
		testContext.Fatalf("expected 204, got %d", recorder.Code)
	}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].action != audit.ActionAccessRuleRemoved || fixture.recorder.events[0].target != "ip:198.51.100.0/24" {
		testContext.Errorf("unexpected audit events %+v", fixture.recorder.events)
	}
}

func TestAddAccessRuleRefusesMatchEverythingPrefix(testContext *testing.T) {
	fixture := newAccessRuleFixture(testContext, nil)

	recorder := fixture.send(http.MethodPost, "/api/account/access-rules", `{"kind":"ip","value":"0.0.0.0/0"}`, "")

	expectError(testContext, recorder, http.StatusBadRequest, "invalid_access_rule")
}
