package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/store/storetest"
)

const hostileAuditTarget = "<script>alert(1)</script>"

// auditReadFixture serves the real router with the real audit reader on the
// throwaway database, so access classes and the response shape are tested end to end.
type auditReadFixture struct {
	environment routeAccessEnvironment
	database    *bun.DB
	handler     http.Handler
}

func newAuditReadFixture(testContext *testing.T) auditReadFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	environment := newRouteAccessEnvironment(testContext)
	services := environment.services()
	services.AuditLog = audit.NewReader(database)
	return auditReadFixture{
		environment: environment,
		database:    database,
		handler:     newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, services),
	}
}

func (fixture auditReadFixture) recordEvents(testContext *testing.T) {
	testContext.Helper()
	var aliceAccountID int64
	insertError := fixture.database.QueryRowContext(context.Background(),
		"INSERT INTO account (account_name, account_role) VALUES ('alice', 'admin') RETURNING account_id").Scan(&aliceAccountID)
	if insertError != nil {
		testContext.Fatalf("insert account: %v", insertError)
	}
	recorder := audit.NewPostgresRecorder(fixture.database)
	recordedEvents := []struct {
		accountID int64
		action    audit.Action
		target    string
	}{
		{aliceAccountID, audit.ActionLoginSuccess, "alice"},
		{0, audit.ActionSyncRun, hostileAuditTarget},
	}
	for _, recordedEvent := range recordedEvents {
		if recordError := recorder.Record(context.Background(), recordedEvent.accountID, recordedEvent.action, recordedEvent.target, "203.0.113.7"); recordError != nil {
			testContext.Fatalf("record %s: %v", recordedEvent.action, recordError)
		}
	}
}

func (fixture auditReadFixture) get(path string, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com"+path, nil)
	request.RemoteAddr = "198.51.100.7:5000"
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeAuditPage(testContext *testing.T, recorder *httptest.ResponseRecorder) (map[string]json.RawMessage, []map[string]json.RawMessage) {
	testContext.Helper()
	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	var pageFields map[string]json.RawMessage
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &pageFields); decodeError != nil {
		testContext.Fatalf("decode page: %v", decodeError)
	}
	var items []map[string]json.RawMessage
	if decodeError := json.Unmarshal(pageFields["items"], &items); decodeError != nil {
		testContext.Fatalf("decode items: %v", decodeError)
	}
	return pageFields, items
}

func sortedKeysOf(fields map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func decodedText(testContext *testing.T, rawValue json.RawMessage) string {
	testContext.Helper()
	var text string
	if decodeError := json.Unmarshal(rawValue, &text); decodeError != nil {
		testContext.Fatalf("decode %s as a string: %v", rawValue, decodeError)
	}
	return text
}

func TestAuditListIsRefusedToReadOnlySessionsAndTokens(testContext *testing.T) {
	fixture := newAuditReadFixture(testContext)

	expectError(testContext, fixture.get("/api/audit", nil, ""), http.StatusUnauthorized, "unauthenticated")
	expectError(testContext, fixture.get("/api/audit", fixture.environment.readOnlyCookie, ""), http.StatusForbidden, "forbidden")
	expectError(testContext, fixture.get("/api/audit", nil, adminWriteTokenValue), http.StatusForbidden, "session_required")
	expectError(testContext, fixture.get("/api/audit", nil, readOnlyTokenSecret), http.StatusForbidden, "session_required")
	if adminResponse := fixture.get("/api/audit", fixture.environment.adminCookie, ""); adminResponse.Code != http.StatusOK {
		testContext.Errorf("an admin session reads the audit log, got %d %q", adminResponse.Code, adminResponse.Body.String())
	}
}

func TestAuditListReturnsOnlyStoredFields(testContext *testing.T) {
	fixture := newAuditReadFixture(testContext)
	fixture.recordEvents(testContext)

	pageFields, items := decodeAuditPage(testContext, fixture.get("/api/audit", fixture.environment.adminCookie, ""))

	expectedPageKeys := []string{"items", "live_status", "may_be_truncated", "page", "per_page", "total", "total_capped", "window_size"}
	if obtainedPageKeys := sortedKeysOf(pageFields); !slices.Equal(obtainedPageKeys, expectedPageKeys) {
		testContext.Errorf("expected page keys %v, got %v", expectedPageKeys, obtainedPageKeys)
	}
	if len(items) != 2 {
		testContext.Fatalf("expected 2 items, got %d", len(items))
	}
	expectedItemKeys := []string{"account", "action", "client_ip", "created_at", "id", "target"}
	for _, item := range items {
		if obtainedItemKeys := sortedKeysOf(item); !slices.Equal(obtainedItemKeys, expectedItemKeys) {
			testContext.Errorf("expected item keys %v, got %v", expectedItemKeys, obtainedItemKeys)
		}
	}
	newestItem, oldestItem := items[0], items[1]
	if obtainedTarget := decodedText(testContext, newestItem["target"]); obtainedTarget != hostileAuditTarget {
		testContext.Errorf("the target comes back byte for byte, got %q", obtainedTarget)
	}
	if string(newestItem["account"]) != "null" {
		testContext.Errorf("an event without account has a null account, got %s", newestItem["account"])
	}
	if obtainedAccount := decodedText(testContext, oldestItem["account"]); obtainedAccount != "alice" {
		testContext.Errorf("expected account alice, got %q", obtainedAccount)
	}
	createdAt, parseError := time.Parse(time.RFC3339Nano, decodedText(testContext, oldestItem["created_at"]))
	if parseError != nil || createdAt.Location() != time.UTC {
		testContext.Errorf("created_at is RFC 3339 in UTC, got %s (%v)", oldestItem["created_at"], parseError)
	}
}

func TestAuditListPassesTheFiltersToTheReader(testContext *testing.T) {
	fixture := newAuditReadFixture(testContext)
	fixture.recordEvents(testContext)
	filteredPaths := map[string]int{
		"/api/audit?action=login_success":                       1,
		"/api/audit?account=alice":                              1,
		"/api/audit?since=1h":                                   2,
		"/api/audit?q=script":                                   1,
		"/api/audit?action=login_success&account=alice&q=alice": 1,
		"/api/audit?action=sync_run&account=alice":              0,
		"/api/audit?page=2&per_page=1":                          1,
		"/api/audit?page=101&per_page=100":                      0,
	}
	for filteredPath, expectedItemCount := range filteredPaths {
		_, items := decodeAuditPage(testContext, fixture.get(filteredPath, fixture.environment.adminCookie, ""))
		if len(items) != expectedItemCount {
			testContext.Errorf("%s: expected %d items, got %d", filteredPath, expectedItemCount, len(items))
		}
	}
}

func TestAuditListRejectsInvalidParameters(testContext *testing.T) {
	fixture := newAuditReadFixture(testContext)
	invalidPaths := []string{
		"/api/audit?q=ab",
		"/api/audit?q=abc%00d",
		"/api/audit?action=BAD!",
		"/api/audit?action=" + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm",
		"/api/audit?account=Bob",
		"/api/audit?since=forever",
		"/api/audit?page=0",
		"/api/audit?per_page=0",
		"/api/audit?page=10002&per_page=1",
		"/api/audit?page=102&per_page=100",
	}
	for _, invalidPath := range invalidPaths {
		expectError(testContext, fixture.get(invalidPath, fixture.environment.adminCookie, ""), http.StatusBadRequest, "invalid_request")
	}
}

func TestAuditSearchTimeoutAnswersSearchTimeout(testContext *testing.T) {
	database := storetest.New(testContext)
	expiringHandlers := auditReadHandlers{lister: audit.NewReader(database), searchTimeout: time.Nanosecond}
	recorder := httptest.NewRecorder()

	expiringHandlers.list(recorder, httptest.NewRequest(http.MethodGet, "/api/audit?q=login", nil))

	expectError(testContext, recorder, http.StatusServiceUnavailable, "search_timeout")
}

func TestAuditListWithoutDatabaseAnswersDatabaseUnavailable(testContext *testing.T) {
	recorder := httptest.NewRecorder()

	auditReadHandlers{}.list(recorder, httptest.NewRequest(http.MethodGet, "/api/audit", nil))

	expectError(testContext, recorder, http.StatusServiceUnavailable, "database_unavailable")
}

func TestAuditListHidesTheTargetOfFailedLogins(testContext *testing.T) {
	fixture := newAuditReadFixture(testContext)
	failureRecorder := audit.NewPostgresRecorder(fixture.database)
	if recordError := failureRecorder.Record(context.Background(), 0, audit.ActionLoginFailure, "typed-secret-value", "203.0.113.7"); recordError != nil {
		testContext.Fatalf("record login_failure: %v", recordError)
	}

	_, items := decodeAuditPage(testContext, fixture.get("/api/audit", fixture.environment.adminCookie, ""))
	if len(items) != 1 || string(items[0]["target"]) != "null" {
		testContext.Fatalf("a login_failure item has a null target, got %v", items)
	}
	_, searchedItems := decodeAuditPage(testContext, fixture.get("/api/audit?q=typed-secret-value", fixture.environment.adminCookie, ""))
	if len(searchedItems) != 0 {
		testContext.Errorf("a search equal to a login_failure target finds nothing, got %d items", len(searchedItems))
	}
}
