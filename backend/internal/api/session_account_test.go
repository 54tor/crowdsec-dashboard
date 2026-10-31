package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authenticatedRequest(method, path string, sessionCookie *http.Cookie) *http.Request {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, nil)
	request.AddCookie(sessionCookie)
	return request
}

func TestMeReturnsAccountNameAndRole(testContext *testing.T) {
	handler, sessions := newTestHandlerAndSessions(testContext, Services{}, "")
	sessionCookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, authenticatedRequest(http.MethodGet, "/api/auth/me", sessionCookie))

	expectedBody := `{"status":"authenticated","account_name":"` + testAccountName + `","account_role":"admin"}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestLogoutAllInvalidatesEverySessionOfTheAccount(testContext *testing.T) {
	handler, sessions := newTestHandlerAndSessions(testContext, Services{}, "")
	firstCookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
	otherDeviceCookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
	logoutRecorder := httptest.NewRecorder()

	handler.ServeHTTP(logoutRecorder, authenticatedRequest(http.MethodPost, "/api/auth/logout-all", firstCookie))

	if logoutRecorder.Code != http.StatusOK || strings.TrimSpace(logoutRecorder.Body.String()) != `{"status":"ok"}` {
		testContext.Fatalf("unexpected response %d %q", logoutRecorder.Code, logoutRecorder.Body.String())
	}
	clearedCookies := logoutRecorder.Result().Cookies()
	if len(clearedCookies) != 1 || clearedCookies[0].MaxAge != -1 {
		testContext.Errorf("the session cookie must be cleared, got %+v", clearedCookies)
	}
	for description, staleCookie := range map[string]*http.Cookie{"current device": firstCookie, "other device": otherDeviceCookie} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, authenticatedRequest(http.MethodGet, "/api/auth/me", staleCookie))
		if recorder.Code != http.StatusUnauthorized {
			testContext.Errorf("%s: expected 401 after logout-all, got %d", description, recorder.Code)
		}
	}
}

func TestLogoutAllRequiresASession(testContext *testing.T) {
	recorder := httptest.NewRecorder()

	newTestHandler(testContext).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/logout-all", nil))

	if recorder.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 401, got %d", recorder.Code)
	}
}
