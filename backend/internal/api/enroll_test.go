package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/auth"
)

var enrolledIdentity = auth.AccountIdentity{AccountID: 100, AccountName: "founder", AccountRole: "admin"}

const (
	validEnrollmentToken = "token-of-this-start"
	enrollmentPassword   = "a long enough password"
)

type fakeEnrollment struct {
	required         bool
	requiredError    error
	completeError    error
	completionCount  int
	receivedAccount  string
	receivedPassword string
}

func (enrollment *fakeEnrollment) Required(_ context.Context) (bool, error) {
	return enrollment.required, enrollment.requiredError
}

func (enrollment *fakeEnrollment) Complete(_ context.Context, token, accountName, password string) (auth.AccountIdentity, error) {
	if !enrollment.required {
		return auth.AccountIdentity{}, accounts.ErrEnrollmentClosed
	}
	if token != validEnrollmentToken {
		return auth.AccountIdentity{}, accounts.ErrEnrollmentToken
	}
	if enrollment.completeError != nil {
		return auth.AccountIdentity{}, enrollment.completeError
	}
	enrollment.completionCount++
	enrollment.receivedAccount = accountName
	enrollment.receivedPassword = password
	return enrolledIdentity, nil
}

func enrollBody(token string) string {
	return `{"token":"` + token + `","account_name":"founder","password":"` + enrollmentPassword + `"}`
}

func postEnroll(handler http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/enroll", strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func getStatus(handler http.Handler) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/status", nil))
	return recorder
}

func handlerWithEnrollment(testContext *testing.T, enrollment *fakeEnrollment) http.Handler {
	return newTestHandlerWithServices(testContext, Services{Enrollment: enrollment})
}

func TestStatusReportsEnrollmentRequired(testContext *testing.T) {
	requiredRecorder := getStatus(handlerWithEnrollment(testContext, &fakeEnrollment{required: true}))
	closedRecorder := getStatus(handlerWithEnrollment(testContext, &fakeEnrollment{required: false}))

	if strings.TrimSpace(requiredRecorder.Body.String()) != `{"enrollment_required":true}` || requiredRecorder.Code != http.StatusOK {
		testContext.Errorf("unexpected required response %d %q", requiredRecorder.Code, requiredRecorder.Body.String())
	}
	if strings.TrimSpace(closedRecorder.Body.String()) != `{"enrollment_required":false}` {
		testContext.Errorf("unexpected closed response %q", closedRecorder.Body.String())
	}
}

func TestStatusReturns503WhenTheDatabaseFails(testContext *testing.T) {
	recorder := getStatus(handlerWithEnrollment(testContext, &fakeEnrollment{requiredError: errors.New("connection refused")}))

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestEnrollSetsSessionCookieAndCreatesAccount(testContext *testing.T) {
	enrollment := &fakeEnrollment{required: true}
	handler := handlerWithEnrollment(testContext, enrollment)

	enrollRecorder := postEnroll(handler, enrollBody(validEnrollmentToken))

	if enrollRecorder.Code != http.StatusOK || strings.TrimSpace(enrollRecorder.Body.String()) != `{"status":"ok"}` {
		testContext.Fatalf("unexpected response %d %q", enrollRecorder.Code, enrollRecorder.Body.String())
	}
	if enrollment.completionCount != 1 || enrollment.receivedAccount != "founder" || enrollment.receivedPassword != enrollmentPassword {
		testContext.Errorf("enrolment not completed with the submitted values: %+v", enrollment)
	}
	cookies := enrollRecorder.Result().Cookies()
	if len(cookies) != 1 {
		testContext.Fatalf("expected one cookie, got %d", len(cookies))
	}
	sessionCookie := cookies[0]
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.Path != "/" || sessionCookie.MaxAge != 3600 {
		testContext.Errorf("cookie not hardened: %+v", sessionCookie)
	}
	meRequest := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/me", nil)
	meRequest.AddCookie(sessionCookie)
	meRecorder := httptest.NewRecorder()
	handler.ServeHTTP(meRecorder, meRequest)
	if meRecorder.Code != http.StatusOK || !strings.Contains(meRecorder.Body.String(), `"account_name":"founder"`) {
		testContext.Errorf("the enrolment session must identify the new account, got %d %q", meRecorder.Code, meRecorder.Body.String())
	}
}

func TestEnrollReturns404WhenClosed(testContext *testing.T) {
	recorder := postEnroll(handlerWithEnrollment(testContext, &fakeEnrollment{required: false}), enrollBody(validEnrollmentToken))

	if recorder.Code != http.StatusNotFound || strings.TrimSpace(recorder.Body.String()) != `{"error":"not_found"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Error("no cookie expected when enrolment is closed")
	}
}

func TestEnrollRejectsWrongTokenWith403(testContext *testing.T) {
	recorder := postEnroll(handlerWithEnrollment(testContext, &fakeEnrollment{required: true}), enrollBody("wrong"))

	if recorder.Code != http.StatusForbidden || strings.TrimSpace(recorder.Body.String()) != `{"error":"invalid_enrollment_token"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestEnrollWithWrongTokenIsRateLimited(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})
	for attemptNumber := 1; attemptNumber <= loginAttemptsPerIP; attemptNumber++ {
		postEnroll(handler, enrollBody("wrong"))
	}

	recorder := postEnroll(handler, enrollBody(validEnrollmentToken))

	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "60" {
		testContext.Errorf("expected 429 with Retry-After 60, got %d %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
}

func TestEnrollRejectsInvalidRequests(testContext *testing.T) {
	bodies := map[string]string{
		"malformed":        `not json`,
		"missing token":    `{"account_name":"founder","password":"` + enrollmentPassword + `"}`,
		"missing account":  `{"token":"` + validEnrollmentToken + `","password":"` + enrollmentPassword + `"}`,
		"missing password": `{"token":"` + validEnrollmentToken + `","account_name":"founder"}`,
	}
	for description, body := range bodies {
		recorder := postEnroll(handlerWithEnrollment(testContext, &fakeEnrollment{required: true}), body)

		if recorder.Code != http.StatusBadRequest || strings.TrimSpace(recorder.Body.String()) != `{"error":"invalid_request"}` {
			testContext.Errorf("%s: unexpected response %d %q", description, recorder.Code, recorder.Body.String())
		}
	}
}

func TestEnrollRejectsOversizedBody(testContext *testing.T) {
	oversizedBody := `{"token":"` + validEnrollmentToken + `","account_name":"founder","password":"` + strings.Repeat("a", 5000) + `"}`

	recorder := postEnroll(handlerWithEnrollment(testContext, &fakeEnrollment{required: true}), oversizedBody)

	if recorder.Code != http.StatusBadRequest {
		testContext.Errorf("expected 400 for an oversized body, got %d", recorder.Code)
	}
}

func TestEnrollMapsValidationErrors(testContext *testing.T) {
	expectations := map[string]struct {
		failure      error
		expectedCode string
	}{
		"account name": {accounts.ErrInvalidAccountName, "invalid_account_name"},
		"password":     {accounts.ErrPasswordLength, "invalid_password_length"},
	}
	for description, expectation := range expectations {
		handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true, completeError: expectation.failure})

		recorder := postEnroll(handler, enrollBody(validEnrollmentToken))

		if recorder.Code != http.StatusBadRequest || strings.TrimSpace(recorder.Body.String()) != `{"error":"`+expectation.expectedCode+`"}` {
			testContext.Errorf("%s: unexpected response %d %q", description, recorder.Code, recorder.Body.String())
		}
	}
}

func TestEnrollReturns503WhenTheDatabaseFails(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true, completeError: errors.New("connection refused")})

	recorder := postEnroll(handler, enrollBody(validEnrollmentToken))

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}
