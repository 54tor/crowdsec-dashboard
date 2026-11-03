package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func expectNoServiceCallAndNoAudit(testContext *testing.T, fixture allowlistFixture, caseName string) {
	testContext.Helper()
	if callCount := fixture.service.callCount(); callCount != 0 {
		testContext.Errorf("%s: the service must not be called, got %d calls", caseName, callCount)
	}
	if recordedEvents, _ := fixture.recorder.recorded(); len(recordedEvents) != 0 {
		testContext.Errorf("%s: nothing must be audited, got %+v", caseName, recordedEvents)
	}
}

func TestAllowlistMutationsRequireAdmin(testContext *testing.T) {
	for _, mutationCase := range validAllowlistMutations {
		fixture := newAllowlistFixture(testContext)

		response := fixture.request(mutationCase.method, mutationCase.path, mutationCase.body, fixture.environment.readOnlyCookie, "")

		expectError(testContext, response, http.StatusForbidden, "forbidden")
		expectNoServiceCallAndNoAudit(testContext, fixture, mutationCase.name)
	}
}

func TestAllowlistMutationWithReadTokenIs403(testContext *testing.T) {
	for _, mutationCase := range validAllowlistMutations {
		fixture := newAllowlistFixture(testContext)

		response := fixture.request(mutationCase.method, mutationCase.path, mutationCase.body, nil, readOnlyTokenSecret)

		expectError(testContext, response, http.StatusForbidden, "forbidden")
		expectNoServiceCallAndNoAudit(testContext, fixture, mutationCase.name)
	}
}

func TestAllowlistListIsReadableByReadOnly(testContext *testing.T) {
	fixture := newAllowlistFixture(testContext)

	sessionResponse := fixture.request(http.MethodGet, "/api/engines/local/allowlists", "", fixture.environment.readOnlyCookie, "")
	tokenResponse := fixture.request(http.MethodGet, "/api/engines/local/allowlists", "", nil, readOnlyTokenSecret)

	if tokenResponse.Code != http.StatusOK {
		testContext.Errorf("read token must read allowlists, got %d %q", tokenResponse.Code, tokenResponse.Body.String())
	}
	if sessionResponse.Code != http.StatusOK {
		testContext.Fatalf("read-only session must read allowlists, got %d %q", sessionResponse.Code, sessionResponse.Body.String())
	}
	var decodedListing map[string]any
	if decodeError := json.Unmarshal(sessionResponse.Body.Bytes(), &decodedListing); decodeError != nil {
		testContext.Fatalf("decode listing: %v", decodeError)
	}
	expectJSONKeys(testContext, "listing", decodedListing, "engine", "writable", "truncated", "allowlists")
	firstAllowlist := decodedListing["allowlists"].([]any)[0].(map[string]any)
	expectJSONKeys(testContext, "allowlist", firstAllowlist, "name", "description", "console_managed", "created_at", "updated_at", "entries")
	firstEntry := firstAllowlist["entries"].([]any)[0].(map[string]any)
	expectJSONKeys(testContext, "entry", firstEntry, "value", "description", "created_at", "expires_at", "expired")
	if firstEntry["value"] != "203.0.113.7" || decodedListing["engine"] != "local" {
		testContext.Errorf("unexpected listing %s", sessionResponse.Body.String())
	}
}

// expectJSONKeys checks the object has exactly the expected keys: no `supported` field,
// no internal field leaking through a missing json tag.
func expectJSONKeys(testContext *testing.T, objectName string, decodedObject map[string]any, expectedKeys ...string) {
	testContext.Helper()
	if len(decodedObject) != len(expectedKeys) {
		testContext.Errorf("%s: expected keys %v, got %v", objectName, expectedKeys, decodedObject)
	}
	for _, expectedKey := range expectedKeys {
		if _, isPresent := decodedObject[expectedKey]; !isPresent {
			testContext.Errorf("%s: missing key %q in %v", objectName, expectedKey, decodedObject)
		}
	}
}

func TestEveryAllowlistMutationRouteIsAdminInRouteTable(testContext *testing.T) {
	foundAccessByPattern := map[string]routeAccess{}
	for _, route := range routeTableForTest(newRouteAccessEnvironment(testContext)) {
		if !strings.Contains(route.Pattern, "/allowlists") {
			continue
		}
		foundAccessByPattern[route.Pattern] = route.Access
		method, _ := splitRoutePattern(route.Pattern)
		if method != http.MethodGet && route.Access != accessAdmin {
			testContext.Errorf("%s must be accessAdmin, found %d", route.Pattern, route.Access)
		}
		if mutatingRoutesAllowedBelowAdmin[route.Pattern] {
			testContext.Errorf("%s must not be exempted from the admin rule", route.Pattern)
		}
		if _, isPinned := requiredAllowlistRoutes[route.Pattern]; !isPinned {
			testContext.Errorf("%s is not pinned in requiredAllowlistRoutes", route.Pattern)
		}
	}
	for pattern, expectedAccess := range requiredAllowlistRoutes {
		foundAccess, isPresent := foundAccessByPattern[pattern]
		if !isPresent || foundAccess != expectedAccess {
			testContext.Errorf("%s: expected access %d, found %d (present=%v)", pattern, expectedAccess, foundAccess, isPresent)
		}
	}
}

func TestDeleteAllowlistRequiresRetypedName(testContext *testing.T) {
	refusedBodies := []string{``, `{}`, `{"confirm":""}`, `{"confirm":"Office"}`, `{"confirm":"other"}`}
	for _, refusedBody := range refusedBodies {
		fixture := newAllowlistFixture(testContext)

		response := fixture.asAdmin(http.MethodDelete, "/api/engines/local/allowlists/office", refusedBody)

		expectError(testContext, response, http.StatusBadRequest, "confirmation_required")
		expectNoServiceCallAndNoAudit(testContext, fixture, "delete with body "+refusedBody)
	}

	fixture := newAllowlistFixture(testContext)
	response := fixture.asAdmin(http.MethodDelete, "/api/engines/local/allowlists/office", `{"confirm":"office"}`)
	if response.Code != http.StatusOK || fixture.service.callCount() != 1 {
		testContext.Errorf("retyped name must delete, got %d %q", response.Code, response.Body.String())
	}
}

func TestRemoveEntryRequiresRetypedValue(testContext *testing.T) {
	refusedBodies := []string{
		`{"value":"203.0.113.7"}`,
		`{"value":"203.0.113.7","confirm":""}`,
		`{"value":"203.0.113.7","confirm":"203.0.113.8"}`,
		`{"value":"203.0.113.7","confirm":"office"}`,
	}
	for _, refusedBody := range refusedBodies {
		fixture := newAllowlistFixture(testContext)

		response := fixture.asAdmin(http.MethodDelete, "/api/engines/local/allowlists/office/entries", refusedBody)

		expectError(testContext, response, http.StatusBadRequest, "confirmation_required")
		expectNoServiceCallAndNoAudit(testContext, fixture, "remove with body "+refusedBody)
	}

	fixture := newAllowlistFixture(testContext)
	response := fixture.asAdmin(http.MethodDelete, "/api/engines/local/allowlists/office/entries", `{"value":"2001:db8::/48","confirm":"2001:db8::/48"}`)
	if response.Code != http.StatusOK || fixture.service.receivedValue != "2001:db8::/48" {
		testContext.Errorf("retyped value must remove, got %d %q (value %q)", response.Code, response.Body.String(), fixture.service.receivedValue)
	}
}

func TestAddEntryPassesConfirmationThroughToTheService(testContext *testing.T) {
	fixture := newAllowlistFixture(testContext)

	response := fixture.asAdmin(http.MethodPost, "/api/engines/local/allowlists/office/entries",
		`{"value":"198.51.0.0/16","expiration":"7d","description":"partner","confirm":"198.51.0.0/16"}`)

	if response.Code != http.StatusCreated {
		testContext.Fatalf("expected 201, got %d %q", response.Code, response.Body.String())
	}
	receivedEntry := fixture.service.receivedEntry
	if receivedEntry.Value != "198.51.0.0/16" || receivedEntry.Expiration != "7d" || receivedEntry.Description != "partner" || receivedEntry.Confirm != "198.51.0.0/16" {
		testContext.Errorf("unexpected entry passed to the service: %+v", receivedEntry)
	}
}

func TestAllowlistBodyOver2KiBRefused(testContext *testing.T) {
	oversizedDescription := strings.Repeat("a", 2100)
	refusedBodies := []allowlistMutationCase{
		{name: "create over 2 KiB", method: http.MethodPost, path: "/api/engines/local/allowlists", body: `{"name":"office","description":"` + oversizedDescription + `"}`},
		{name: "add entry over 2 KiB", method: http.MethodPost, path: "/api/engines/local/allowlists/office/entries", body: `{"value":"203.0.113.7","description":"` + oversizedDescription + `"}`},
		{name: "create with unknown field", method: http.MethodPost, path: "/api/engines/local/allowlists", body: `{"name":"office","owner":"alice"}`},
		{name: "add entry with unknown field", method: http.MethodPost, path: "/api/engines/local/allowlists/office/entries", body: `{"value":"203.0.113.7","scope":"ip"}`},
		{name: "add entry with trailing data", method: http.MethodPost, path: "/api/engines/local/allowlists/office/entries", body: `{"value":"203.0.113.7"}{}`},
	}
	for _, refusedCase := range refusedBodies {
		fixture := newAllowlistFixture(testContext)

		response := fixture.asAdmin(refusedCase.method, refusedCase.path, refusedCase.body)

		expectError(testContext, response, http.StatusBadRequest, "invalid_request")
		expectNoServiceCallAndNoAudit(testContext, fixture, refusedCase.name)
	}

	fixture := newAllowlistFixture(testContext)
	descriptionUnderLimit := strings.Repeat("a", 1900)
	response := fixture.asAdmin(http.MethodPost, "/api/engines/local/allowlists", `{"name":"office","description":"`+descriptionUnderLimit+`"}`)
	if response.Code != http.StatusCreated {
		testContext.Errorf("a body under 2 KiB must be accepted, got %d %q", response.Code, response.Body.String())
	}
}
