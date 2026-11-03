package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/allowlists"
	"crowdsec-dashboard/internal/config"
)

var allowlistTestTime = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// sampleAllowlistListing is what the fake service returns for every successful call:
// one writable allowlist "office" on engine "local" with a single entry.
func sampleAllowlistListing() allowlists.Listing {
	entryExpiry := allowlistTestTime.Add(24 * time.Hour)
	return allowlists.Listing{
		Engine:   "local",
		Writable: true,
		Allowlists: []allowlists.View{{
			Name:        "office",
			Description: "office network",
			CreatedAt:   allowlistTestTime,
			UpdatedAt:   allowlistTestTime,
			Entries: []allowlists.Entry{{
				Value:       "203.0.113.7",
				Description: "front desk",
				CreatedAt:   allowlistTestTime,
				ExpiresAt:   &entryExpiry,
			}},
		}},
	}
}

// fakeAllowlistService records every call it receives and answers with failure (when set)
// or with the sample listing and the configured refreshed flag.
type fakeAllowlistService struct {
	mutex         sync.Mutex
	calledMethods []string
	receivedEntry allowlists.EntryInput
	receivedValue string
	failure       error
	notRefreshed  bool
}

func (service *fakeAllowlistService) record(methodName string) {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	service.calledMethods = append(service.calledMethods, methodName)
}

func (service *fakeAllowlistService) callCount() int {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	return len(service.calledMethods)
}

func (service *fakeAllowlistService) mutationResult() (allowlists.MutationResult, error) {
	if service.failure != nil {
		return allowlists.MutationResult{}, service.failure
	}
	if service.notRefreshed {
		return allowlists.MutationResult{Refreshed: false}, nil
	}
	return allowlists.MutationResult{Listing: sampleAllowlistListing(), Refreshed: true}, nil
}

func (service *fakeAllowlistService) List(_ context.Context, _ string) (allowlists.Listing, error) {
	service.record("List")
	if service.failure != nil {
		return allowlists.Listing{}, service.failure
	}
	return sampleAllowlistListing(), nil
}

func (service *fakeAllowlistService) Create(_ context.Context, _, _, _ string) (allowlists.MutationResult, error) {
	service.record("Create")
	return service.mutationResult()
}

func (service *fakeAllowlistService) Delete(_ context.Context, _, _ string) (allowlists.MutationResult, error) {
	service.record("Delete")
	return service.mutationResult()
}

func (service *fakeAllowlistService) AddEntry(_ context.Context, _, _ string, entry allowlists.EntryInput) (allowlists.MutationResult, error) {
	service.record("AddEntry")
	service.receivedEntry = entry
	return service.mutationResult()
}

func (service *fakeAllowlistService) RemoveEntry(_ context.Context, _, _, rawValue string) (allowlists.MutationResult, error) {
	service.record("RemoveEntry")
	service.receivedValue = rawValue
	return service.mutationResult()
}

// allowlistFixture mounts the real router (protect, cross-origin check, route table)
// with the fake allowlist service and an audit recorder.
type allowlistFixture struct {
	environment routeAccessEnvironment
	handler     http.Handler
	service     *fakeAllowlistService
	recorder    *lockedAuditRecorder
}

func newAllowlistFixture(testContext *testing.T) allowlistFixture {
	testContext.Helper()
	environment := newRouteAccessEnvironment(testContext)
	fakeService := &fakeAllowlistService{}
	recorder := &lockedAuditRecorder{}
	services := environment.services()
	services.Allowlists = fakeService
	services.Audit = recorder
	return allowlistFixture{
		environment: environment,
		handler:     newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, services),
		service:     fakeService,
		recorder:    recorder,
	}
}

func (fixture allowlistFixture) request(method, path, body string, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5000"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://dashboard.example.com")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func (fixture allowlistFixture) asAdmin(method, path, body string) *httptest.ResponseRecorder {
	return fixture.request(method, path, body, fixture.environment.adminCookie, "")
}

type allowlistMutationCase struct {
	name   string
	method string
	path   string
	body   string
}

// validAllowlistMutations are the four write routes with bodies the handlers accept.
var validAllowlistMutations = []allowlistMutationCase{
	{name: "create allowlist", method: http.MethodPost, path: "/api/engines/local/allowlists", body: `{"name":"office","description":"office network"}`},
	{name: "delete allowlist", method: http.MethodDelete, path: "/api/engines/local/allowlists/office", body: `{"confirm":"office"}`},
	{name: "add entry", method: http.MethodPost, path: "/api/engines/local/allowlists/office/entries", body: `{"value":"203.0.113.7","description":"front desk"}`},
	{name: "remove entry", method: http.MethodDelete, path: "/api/engines/local/allowlists/office/entries", body: `{"value":"203.0.113.7","confirm":"203.0.113.7"}`},
}
