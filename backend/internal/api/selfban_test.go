package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
)

type selfBanFixture struct {
	handler   http.Handler
	cookie    *http.Cookie
	decisions *fakeDecisions
}

func newSelfBanFixture(testContext *testing.T, trustedProxyCIDRs []*net.IPNet) selfBanFixture {
	testContext.Helper()
	decisions := &fakeDecisions{}
	handler := newHandler(config.Config{SessionTTL: time.Hour, TrustedProxyCIDRs: trustedProxyCIDRs}, http.NotFoundHandler(), 0, Services{
		Decisions:     decisions,
		Sessions:      authtest.NewSessionStore(time.Hour, time.Now),
		Authenticator: authtest.NewAuthenticator(map[string]string{testAccountName: testPassword}),
	})
	cookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	return selfBanFixture{handler: handler, cookie: cookie, decisions: decisions}
}

func (fixture selfBanFixture) ban(remoteAddress string, forwardedFor string, target string) *httptest.ResponseRecorder {
	body := `{"ip":"` + target + `","duration":"4h","reason":"test"}`
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/decisions", strings.NewReader(body))
	request.RemoteAddr = remoteAddress
	request.Header.Set("Content-Type", "application/json")
	if forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", forwardedFor)
	}
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func mustParseCIDR(testContext *testing.T, cidr string) *net.IPNet {
	testContext.Helper()
	_, network, parseError := net.ParseCIDR(cidr)
	if parseError != nil {
		testContext.Fatal(parseError)
	}
	return network
}

func TestBanOfTheClientAddressIsRefusedBeforeAnyUpstreamCall(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, nil)

	expectError(testContext, fixture.ban("198.51.100.7:5555", "", "198.51.100.7"), http.StatusConflict, "self_ban")

	if len(fixture.decisions.added) != 0 {
		testContext.Errorf("no upstream call expected, got %+v", fixture.decisions.added)
	}
}

func TestBanOfARangeContainingTheClientIsRefused(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, nil)

	expectError(testContext, fixture.ban("198.51.100.7:5555", "", "198.51.100.0/24"), http.StatusConflict, "self_ban")

	if len(fixture.decisions.added) != 0 {
		testContext.Errorf("no upstream call expected, got %+v", fixture.decisions.added)
	}
}

func TestBanOfARangeNotContainingTheClientIsAccepted(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, nil)

	recorder := fixture.ban("198.51.100.7:5555", "", "203.0.113.0/24")

	if recorder.Code != http.StatusCreated || len(fixture.decisions.added) != 1 {
		testContext.Errorf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestBanOfAnIPv4TargetIsRefusedForAnIPv4MappedIPv6Client(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, nil)

	expectError(testContext, fixture.ban("[::ffff:198.51.100.7]:5555", "", "198.51.100.7"), http.StatusConflict, "self_ban")
	expectError(testContext, fixture.ban("[::ffff:198.51.100.7]:5555", "", "198.51.100.0/24"), http.StatusConflict, "self_ban")
}

func TestBanOfAnIPv6RangeContainingTheClientIsRefused(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, nil)

	expectError(testContext, fixture.ban("[2001:db8:1::5]:5555", "", "2001:db8::/32"), http.StatusConflict, "self_ban")
}

func TestForgedForwardedForFromAnUntrustedPeerDoesNotChangeTheClientIdentity(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, []*net.IPNet{mustParseCIDR(testContext, "192.0.2.0/24")})

	allowed := fixture.ban("198.51.100.7:5555", "203.0.113.9", "203.0.113.9")
	if allowed.Code != http.StatusCreated {
		testContext.Errorf("banning the claimed address must be allowed, got %d %q", allowed.Code, allowed.Body.String())
	}
	expectError(testContext, fixture.ban("198.51.100.7:5555", "203.0.113.9", "198.51.100.7"), http.StatusConflict, "self_ban")
}

func TestForwardedForFromATrustedProxyIdentifiesTheClient(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, []*net.IPNet{mustParseCIDR(testContext, "192.0.2.0/24")})

	expectError(testContext, fixture.ban("192.0.2.10:5555", "203.0.113.9", "203.0.113.9"), http.StatusConflict, "self_ban")
}

func TestBanIsNotBlockedWhenTheClientAddressCannotBeParsed(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, nil)

	recorder := fixture.ban("not-an-address", "", "198.51.100.0/24")

	if recorder.Code != http.StatusCreated || len(fixture.decisions.added) != 1 {
		testContext.Errorf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestValidationPrecedesTheSelfBanGuard(testContext *testing.T) {
	fixture := newSelfBanFixture(testContext, nil)

	expectError(testContext, fixture.ban("198.51.100.7:5555", "", "198.0.0.0/7"), http.StatusBadRequest, "invalid_target")
	invalidDurationBody := `{"ip":"198.51.100.7","duration":"bad","reason":"test"}`
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/decisions", strings.NewReader(invalidDurationBody))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	expectError(testContext, recorder, http.StatusBadRequest, "invalid_duration")
}
