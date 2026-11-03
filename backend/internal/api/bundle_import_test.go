package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/oplock"
)

var importTestTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// importLocalEngine is the in-memory local engine behind POST /api/import: allowlistReads proves
// whether a refused caller ever reached it, addedDecisions what was written into it.
type importLocalEngine struct {
	allowlist      lapi.AllowlistRead
	allowlistReads int
	addedDecisions []lapi.NewDecision
}

func (engine *importLocalEngine) ListAllowlists(context.Context) (lapi.AllowlistRead, error) {
	engine.allowlistReads++
	return engine.allowlist, nil
}

func (engine *importLocalEngine) deps(maxChanges int) bundle.ImportDeps {
	return bundle.ImportDeps{
		ReadHub:           func(context.Context) ([]bundle.HubItem, error) { return []bundle.HubItem{}, nil },
		InstallCollection: func(context.Context, string) error { return nil },
		Allowlists:        engine,
		ReadLocalBans: func(context.Context, int) ([]lapi.SyncDecision, bool, error) {
			localBans := []lapi.SyncDecision{}
			for _, addedDecision := range engine.addedDecisions {
				localBans = append(localBans, lapi.SyncDecision{Origin: "cscli", Scope: addedDecision.Scope, Value: addedDecision.Target, Remaining: time.Hour})
			}
			return localBans, true, nil
		},
		AddDecision: func(_ context.Context, newDecision lapi.NewDecision) error {
			engine.addedDecisions = append(engine.addedDecisions, newDecision)
			return nil
		},
		ShareRules: func(context.Context) (enginesync.Rules, bool) {
			return enginesync.Rules{MaxChanges: maxChanges, MinRemaining: 5 * time.Minute}, true
		},
		Now: func() time.Time { return importTestTime },
	}
}

type importFixture struct {
	environment routeAccessEnvironment
	handler     http.Handler
	recorder    *lockedAuditRecorder
	lock        *oplock.Lock
	engine      *importLocalEngine
}

func newImportFixture(testContext *testing.T, operationLock *oplock.Lock) importFixture {
	testContext.Helper()
	environment := newRouteAccessEnvironment(testContext)
	engine := &importLocalEngine{allowlist: lapi.AllowlistRead{Allowlists: []lapi.Allowlist{}}}
	recorder := &lockedAuditRecorder{}
	services := environment.services()
	services.Audit = recorder
	services.OperationLock = operationLock
	services.BundleImport = engine.deps(500)
	return importFixture{
		environment: environment,
		handler:     newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, services),
		recorder:    recorder,
		lock:        operationLock,
		engine:      engine,
	}
}

func decisionsImportBundle(values ...string) bundle.Bundle {
	decisions := []bundle.Decision{}
	for _, value := range values {
		scope := "Ip"
		if strings.Contains(value, "/") {
			scope = "Range"
		}
		decisions = append(decisions, bundle.Decision{Origin: "crowdsec", Type: "ban", Scope: scope, Value: value, Scenario: "crowdsecurity/ssh-bf", Until: importTestTime.Add(time.Hour)})
	}
	return bundle.Bundle{Format: bundle.Format, Version: bundle.Version, CreatedAt: importTestTime, Sections: bundle.Sections{Decisions: &bundle.DecisionsSection{Decisions: decisions}}}
}

func importBody(testContext *testing.T, mode string, imported bundle.Bundle, confirm, digest string) string {
	testContext.Helper()
	encodedBundle, encodeError := json.Marshal(imported)
	if encodeError != nil {
		testContext.Fatalf("encode bundle: %v", encodeError)
	}
	return importRawBody(testContext, mode, string(encodedBundle), confirm, digest)
}

func importRawBody(testContext *testing.T, mode, rawBundle, confirm, digest string) string {
	testContext.Helper()
	envelope := map[string]any{"mode": mode, "bundle": json.RawMessage(rawBundle), "sections": []string{bundle.SectionDecision}}
	if confirm != "" {
		envelope["confirm"] = confirm
	}
	if digest != "" {
		envelope["digest"] = digest
	}
	encodedEnvelope, encodeError := json.Marshal(envelope)
	if encodeError != nil {
		testContext.Fatalf("encode envelope: %v", encodeError)
	}
	return string(encodedEnvelope)
}

func (fixture importFixture) request(body string, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/import", strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5000"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://dashboard.example.com")
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

func (fixture importFixture) preview(testContext *testing.T, imported bundle.Bundle) bundle.ImportPlan {
	testContext.Helper()
	response := fixture.request(importBody(testContext, "preview", imported, "", ""), fixture.environment.adminCookie, "")
	if response.Code != http.StatusOK {
		testContext.Fatalf("preview: expected 200, got %d %q", response.Code, response.Body.String())
	}
	var plan bundle.ImportPlan
	if decodeError := json.Unmarshal(response.Body.Bytes(), &plan); decodeError != nil {
		testContext.Fatalf("decode plan: %v", decodeError)
	}
	return plan
}

func assertErrorResponse(testContext *testing.T, caseName string, response *httptest.ResponseRecorder, expectedStatus int, expectedCode string) {
	testContext.Helper()
	if response.Code != expectedStatus || !strings.Contains(response.Body.String(), `"`+expectedCode+`"`) {
		testContext.Errorf("%s: expected %d %s, got %d %q", caseName, expectedStatus, expectedCode, response.Code, response.Body.String())
	}
}

func TestImportRequiresAdminSession(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	body := importBody(testContext, "preview", decisionsImportBundle("203.0.113.5"), "", "")
	assertErrorResponse(testContext, "read-only session", fixture.request(body, fixture.environment.readOnlyCookie, ""), http.StatusForbidden, "forbidden")
	if response := fixture.request(body, nil, readOnlyTokenSecret); response.Code != http.StatusForbidden {
		testContext.Errorf("read token: expected 403, got %d", response.Code)
	}
	assertErrorResponse(testContext, "admin write token", fixture.request(body, nil, adminWriteTokenValue), http.StatusForbidden, "session_required")
	if fixture.engine.allowlistReads != 0 {
		testContext.Errorf("a refused caller must never reach the engine, got %d reads", fixture.engine.allowlistReads)
	}
	if response := fixture.request(body, fixture.environment.adminCookie, ""); response.Code != http.StatusOK {
		testContext.Errorf("admin session: expected 200, got %d %q", response.Code, response.Body.String())
	}
}

func TestApplyRequiresImportConfirmAndMatchingDigest(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	imported := decisionsImportBundle("203.0.113.5")
	plan := fixture.preview(testContext, imported)
	refusedCases := map[string]struct {
		confirm, digest string
		expectedStatus  int
		expectedCode    string
	}{
		"no confirmation":     {"", plan.Digest, http.StatusBadRequest, "confirmation_required"},
		"lowercase confirm":   {"import", plan.Digest, http.StatusBadRequest, "confirmation_required"},
		"no digest":           {"IMPORT", "", http.StatusConflict, "import_conflict"},
		"digest of another":   {"IMPORT", strings.Repeat("0", 64), http.StatusConflict, "import_conflict"},
		"wrong confirm token": {"SECRETS", plan.Digest, http.StatusBadRequest, "confirmation_required"},
	}
	for caseName, refusedCase := range refusedCases {
		response := fixture.request(importBody(testContext, "apply", imported, refusedCase.confirm, refusedCase.digest), fixture.environment.adminCookie, "")
		assertErrorResponse(testContext, caseName, response, refusedCase.expectedStatus, refusedCase.expectedCode)
	}
	if len(fixture.engine.addedDecisions) != 0 {
		testContext.Fatalf("a refused apply must write nothing, got %v", fixture.engine.addedDecisions)
	}
	response := fixture.request(importBody(testContext, "apply", imported, "IMPORT", plan.Digest), fixture.environment.adminCookie, "")
	if response.Code != http.StatusOK || len(fixture.engine.addedDecisions) != 1 {
		testContext.Errorf("a confirmed apply with the previewed digest must write, got %d %q", response.Code, response.Body.String())
	}
}

func TestApplyTakesGlobalLockAndReturns409WhenHeld(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	imported := decisionsImportBundle("203.0.113.5")
	plan := fixture.preview(testContext, imported)
	release, acquired := fixture.lock.TryAcquire("sync")
	if !acquired {
		testContext.Fatal("the preview must release the lock")
	}
	assertErrorResponse(testContext, "preview while held", fixture.request(importBody(testContext, "preview", imported, "", ""), fixture.environment.adminCookie, ""), http.StatusConflict, "operation_running")
	assertErrorResponse(testContext, "apply while held", fixture.request(importBody(testContext, "apply", imported, "IMPORT", plan.Digest), fixture.environment.adminCookie, ""), http.StatusConflict, "operation_running")
	release()
	if len(fixture.engine.addedDecisions) != 0 {
		testContext.Fatalf("nothing may be written while another operation runs, got %v", fixture.engine.addedDecisions)
	}
	if response := fixture.request(importBody(testContext, "apply", imported, "IMPORT", plan.Digest), fixture.environment.adminCookie, ""); response.Code != http.StatusOK {
		testContext.Fatalf("apply after release: expected 200, got %d %q", response.Code, response.Body.String())
	}
	releaseAfterApply, acquiredAfterApply := fixture.lock.TryAcquire("sync")
	if !acquiredAfterApply {
		testContext.Fatal("the apply must release the lock")
	}
	releaseAfterApply()
}

func TestImportFailsClosedWithoutLock(testContext *testing.T) {
	fixture := newImportFixture(testContext, nil)
	response := fixture.request(importBody(testContext, "preview", decisionsImportBundle("203.0.113.5"), "", ""), fixture.environment.adminCookie, "")
	assertErrorResponse(testContext, "nil lock", response, http.StatusServiceUnavailable, "operation_lock_unavailable")
	if fixture.engine.allowlistReads != 0 || len(fixture.engine.addedDecisions) != 0 {
		testContext.Errorf("without a lock the engine must not be touched")
	}
}

func TestDecisionsImportRefusesBanOfCallerAddress(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	plan := fixture.preview(testContext, decisionsImportBundle("198.51.100.7", "198.51.100.0/24", "203.0.113.5"))
	ownAddressTargets := 0
	for _, skippedItem := range plan.Skipped {
		if skippedItem.Reason == bundle.ReasonOwnAddress {
			ownAddressTargets++
		}
	}
	if ownAddressTargets != 2 || len(plan.Decisions) != 1 || plan.Decisions[0].Value != "203.0.113.5" {
		testContext.Errorf("the caller's address and a range containing it must be skipped own_address, got %+v", plan)
	}
}

func TestApplyConflictsWhenAllowlistChangedSincePreview(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	imported := decisionsImportBundle("203.0.113.5", "203.0.113.6")
	plan := fixture.preview(testContext, imported)
	fixture.engine.allowlist = lapi.AllowlistRead{Allowlists: []lapi.Allowlist{{Name: "operators", Items: []lapi.AllowlistItem{{Value: "203.0.113.6"}}}}}
	response := fixture.request(importBody(testContext, "apply", imported, "IMPORT", plan.Digest), fixture.environment.adminCookie, "")
	assertErrorResponse(testContext, "allowlist changed", response, http.StatusConflict, "import_conflict")
	if len(fixture.engine.addedDecisions) != 0 {
		testContext.Errorf("a conflicting apply must write nothing, got %v", fixture.engine.addedDecisions)
	}
	if fixture.engine.allowlistReads != 2 {
		testContext.Errorf("the apply must read the allowlists afresh, got %d reads", fixture.engine.allowlistReads)
	}
}

func TestImportRefusesBundleWithUnknownSection(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	header := `"format":"crowdsec-dashboard-bundle","created_at":"2026-11-03T12:00:00Z","engine_version":"v1","contains_secrets":false`
	refusedBundles := map[string]struct {
		rawBundle    string
		expectedCode string
	}{
		"unknown section": {`{` + header + `,"version":1,"sections":{"decisions":{"decisions":[]},"peers":{}}}`, "bundle_invalid"},
		"unknown field":   {`{` + header + `,"version":1,"engine":"peer","sections":{"decisions":{"decisions":[]}}}`, "bundle_invalid"},
		"unknown version": {`{` + header + `,"version":2,"sections":{"decisions":{"decisions":[]}}}`, "bundle_version"},
		"not a bundle":    {`[]`, "bundle_invalid"},
	}
	for caseName, refusedBundle := range refusedBundles {
		response := fixture.request(importRawBody(testContext, "preview", refusedBundle.rawBundle, "", ""), fixture.environment.adminCookie, "")
		assertErrorResponse(testContext, caseName, response, http.StatusBadRequest, refusedBundle.expectedCode)
	}
	oversizedBody := importRawBody(testContext, "preview", `"`+strings.Repeat("a", bundle.MaxBytes+importEnvelopeMarginBytes)+`"`, "", "")
	assertErrorResponse(testContext, "oversized body", fixture.request(oversizedBody, fixture.environment.adminCookie, ""), http.StatusRequestEntityTooLarge, "bundle_too_large")
	unknownMode := importBody(testContext, "replace", decisionsImportBundle("203.0.113.5"), "", "")
	assertErrorResponse(testContext, "unknown mode", fixture.request(unknownMode, fixture.environment.adminCookie, ""), http.StatusBadRequest, "invalid_request")
	if fixture.engine.allowlistReads != 0 {
		testContext.Errorf("a refused bundle must not reach the engine, got %d reads", fixture.engine.allowlistReads)
	}
}

func TestImportRefusesTooManyChangesWithStableCode(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	services := fixture.environment.services()
	services.OperationLock = oplock.New()
	services.BundleImport = fixture.engine.deps(1)
	handler := newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, services)
	fixture.handler = handler
	response := fixture.request(importBody(testContext, "preview", decisionsImportBundle("203.0.113.5", "203.0.113.6"), "", ""), fixture.environment.adminCookie, "")
	assertErrorResponse(testContext, "above SYNC_MAX_CHANGES", response, http.StatusUnprocessableEntity, "too_many_changes")
}

func TestImportPreviewIsNotAudited(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	fixture.preview(testContext, decisionsImportBundle("203.0.113.5"))
	if events, _ := fixture.recorder.recorded(); len(events) != 0 {
		testContext.Errorf("a preview writes nothing and must not be audited, got %+v", events)
	}
}

func TestImportApplyIsAudited(testContext *testing.T) {
	fixture := newImportFixture(testContext, oplock.New())
	imported := decisionsImportBundle("203.0.113.5", "10.0.0.1")
	plan := fixture.preview(testContext, imported)
	if response := fixture.request(importBody(testContext, "apply", imported, "IMPORT", plan.Digest), fixture.environment.adminCookie, ""); response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	events, actorAccountIDs := fixture.recorder.recorded()
	if len(events) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", events)
	}
	expectedTarget := "dry=false hub=0 decisions=1 skipped=1 failed=0"
	if events[0].action != audit.ActionBundleImported || events[0].target != expectedTarget || events[0].clientIP != "198.51.100.7" || actorAccountIDs[0] != adminAccountID {
		testContext.Errorf("unexpected audit event %+v by %v", events[0], actorAccountIDs)
	}
	if strings.Contains(events[0].target, "203.0.113.5") {
		testContext.Errorf("the audit target must never carry bundle content, got %q", events[0].target)
	}
}
