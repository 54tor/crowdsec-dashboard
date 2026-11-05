package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/store/storetest"
)

const searchedAlertsPath = "/api/alerts?q=ssh-bf"

// blockingAlertLister holds every call until releaseCalls is closed or the
// request context ends, and reports each entry on enteredCalls, so a test can
// keep a known number of searches in flight.
type blockingAlertLister struct {
	enteredCalls chan struct{}
	releaseCalls chan struct{}
}

func newBlockingAlertLister() *blockingAlertLister {
	return &blockingAlertLister{enteredCalls: make(chan struct{}, maxConcurrentSearches+1), releaseCalls: make(chan struct{})}
}

func (lister *blockingAlertLister) ListAlerts(ctx context.Context, _ lapi.AlertFilter) ([]lapi.Alert, error) {
	lister.enteredCalls <- struct{}{}
	select {
	case <-lister.releaseCalls:
		return []lapi.Alert{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startBlockedSearches runs searchCount searches in the background and returns
// once each of them is inside the lister, that is, once each holds a slot.
func startBlockedSearches(testContext *testing.T, searchHandler http.HandlerFunc, lister *blockingAlertLister, searchCount int) *sync.WaitGroup {
	testContext.Helper()
	runningSearches := &sync.WaitGroup{}
	for range searchCount {
		runningSearches.Add(1)
		go func() {
			defer runningSearches.Done()
			searchHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil))
		}()
	}
	for range searchCount {
		<-lister.enteredCalls
	}
	return runningSearches
}

func expectSearchBusy(testContext *testing.T, recorder *httptest.ResponseRecorder) {
	testContext.Helper()
	expectError(testContext, recorder, http.StatusTooManyRequests, "search_busy")
	if retryAfter := recorder.Header().Get("Retry-After"); retryAfter != "1" {
		testContext.Errorf("a busy search answers Retry-After 1, got %q", retryAfter)
	}
}

func TestFifthConcurrentSearchIsBusyUntilASearchCompletes(testContext *testing.T) {
	lister := newBlockingAlertLister()
	alertLists := alertReadHandlers{lister: lister, searches: newSearchLimiter(maxConcurrentSearches)}
	runningSearches := startBlockedSearches(testContext, alertLists.list, lister, maxConcurrentSearches)

	busyRecorder := httptest.NewRecorder()
	alertLists.list(busyRecorder, httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil))
	expectSearchBusy(testContext, busyRecorder)

	close(lister.releaseCalls)
	runningSearches.Wait()
	admittedRecorder := httptest.NewRecorder()
	alertLists.list(admittedRecorder, httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil))
	if admittedRecorder.Code != http.StatusOK {
		testContext.Errorf("a search after the others completed is admitted, got %d %q", admittedRecorder.Code, admittedRecorder.Body.String())
	}
}

func TestCancelledSearchReleasesItsSlot(testContext *testing.T) {
	lister := newBlockingAlertLister()
	alertLists := alertReadHandlers{lister: lister, searches: newSearchLimiter(1)}
	cancellableContext, cancelRequest := context.WithCancel(context.Background())
	searchFinished := make(chan struct{})
	go func() {
		defer close(searchFinished)
		alertLists.list(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil).WithContext(cancellableContext))
	}()
	<-lister.enteredCalls

	cancelRequest()
	<-searchFinished
	close(lister.releaseCalls)
	admittedRecorder := httptest.NewRecorder()
	alertLists.list(admittedRecorder, httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil))

	if admittedRecorder.Code != http.StatusOK {
		testContext.Errorf("the slot of a cancelled search is released, got %d %q", admittedRecorder.Code, admittedRecorder.Body.String())
	}
}

func TestTimedOutSearchReleasesItsSlot(testContext *testing.T) {
	alertLists := alertReadHandlers{lister: deadlineAlertLister{}, searchTimeout: time.Millisecond, searches: newSearchLimiter(1)}

	for attemptNumber := 1; attemptNumber <= 2; attemptNumber++ {
		recorder := httptest.NewRecorder()
		alertLists.list(recorder, httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil))
		expectError(testContext, recorder, http.StatusServiceUnavailable, "search_timeout")
	}
}

func TestListWithoutSearchIsNeverLimited(testContext *testing.T) {
	searches := newSearchLimiter(1)
	releaseHeldSlot, slotHeld := searches.tryAcquire()
	if !slotHeld {
		testContext.Fatal("the only slot is free at start")
	}
	defer releaseHeldSlot()
	alertLists := alertReadHandlers{lister: &fakeAlertLister{}, searches: searches}

	unsearchedRecorder := httptest.NewRecorder()
	alertLists.list(unsearchedRecorder, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))
	searchedRecorder := httptest.NewRecorder()
	alertLists.list(searchedRecorder, httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil))

	if unsearchedRecorder.Code != http.StatusOK {
		testContext.Errorf("a list without q is not limited, got %d %q", unsearchedRecorder.Code, unsearchedRecorder.Body.String())
	}
	expectSearchBusy(testContext, searchedRecorder)
}

// routedSearchHandlers builds the real routes with a blocking alert lister and
// the real audit reader on the throwaway database, so the limiter wiring of
// apiRoutes is the one under test.
func routedSearchHandlers(testContext *testing.T, lister *blockingAlertLister) map[string]http.Handler {
	testContext.Helper()
	services := Services{AlertReader: lister, DecisionReader: &fakeDecisionLister{}, AuditLog: audit.NewReader(storetest.New(testContext))}
	handlersByPattern := map[string]http.Handler{}
	for _, route := range apiRoutes(config.Config{SessionTTL: time.Hour}, services, &authHandlers{}) {
		handlersByPattern[route.Pattern] = route.Handler
	}
	return handlersByPattern
}

// Searches held on /api/alerts fill the list limiter: /api/decisions shares
// it and is busy, while the admin audit search has its own slots and runs.
func TestListRoutesShareALimiterThatLeavesTheAuditSearchFree(testContext *testing.T) {
	lister := newBlockingAlertLister()
	handlersByPattern := routedSearchHandlers(testContext, lister)
	runningSearches := startBlockedSearches(testContext, handlersByPattern["GET /api/alerts"].ServeHTTP, lister, maxConcurrentSearches)
	defer runningSearches.Wait()
	defer close(lister.releaseCalls)

	decisionRecorder := httptest.NewRecorder()
	handlersByPattern["GET /api/decisions"].ServeHTTP(decisionRecorder, httptest.NewRequest(http.MethodGet, "/api/decisions?q=ssh-bf", nil))
	auditRecorder := httptest.NewRecorder()
	handlersByPattern["GET /api/audit"].ServeHTTP(auditRecorder, httptest.NewRequest(http.MethodGet, "/api/audit?q=login", nil))

	expectSearchBusy(testContext, decisionRecorder)
	if auditRecorder.Code != http.StatusOK {
		testContext.Errorf("an audit search is admitted while the list slots are full, got %d %q", auditRecorder.Code, auditRecorder.Body.String())
	}
}

// With every audit slot held, another audit search is busy while a list
// search, which draws from the separate list limiter, still runs.
func TestThirdConcurrentAuditSearchIsBusyWithoutTouchingListSearches(testContext *testing.T) {
	auditSearches := newSearchLimiter(maxConcurrentAuditSearches)
	for range maxConcurrentAuditSearches {
		releaseHeldSlot, slotHeld := auditSearches.tryAcquire()
		if !slotHeld {
			testContext.Fatal("the audit slots are free at start")
		}
		defer releaseHeldSlot()
	}
	auditLists := auditReadHandlers{lister: audit.NewReader(storetest.New(testContext)), searches: auditSearches}
	alertLists := alertReadHandlers{lister: &fakeAlertLister{}, searches: newSearchLimiter(maxConcurrentSearches)}

	auditRecorder := httptest.NewRecorder()
	auditLists.list(auditRecorder, httptest.NewRequest(http.MethodGet, "/api/audit?q=login", nil))
	alertRecorder := httptest.NewRecorder()
	alertLists.list(alertRecorder, httptest.NewRequest(http.MethodGet, searchedAlertsPath, nil))

	expectSearchBusy(testContext, auditRecorder)
	if alertRecorder.Code != http.StatusOK {
		testContext.Errorf("a list search is not limited by the audit slots, got %d %q", alertRecorder.Code, alertRecorder.Body.String())
	}
}
