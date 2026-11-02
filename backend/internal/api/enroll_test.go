package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/secondfactor"
)

var enrolledIdentity = auth.AccountIdentity{AccountID: 100, AccountName: "founder", AccountRole: "admin"}

const (
	validEnrollmentToken = "token-of-this-start"
	enrollmentPassword   = "a long enough password"
	enrollmentClientIP   = "198.51.100.7"
)

// fakeEnrollment mirrors accounts.Enrollment: a pending state with a real
// secondfactor.Setup is created by Start and is required by Setup and Complete.
type fakeEnrollment struct {
	required         bool
	requiredError    error
	startError       error
	completeError    error
	startCount       int
	completionCount  int
	receivedAccount  string
	receivedPassword string
	pendingSetup     *secondfactor.Setup
}

func (enrollment *fakeEnrollment) Required(_ context.Context) (bool, error) {
	return enrollment.required, enrollment.requiredError
}

func (enrollment *fakeEnrollment) checkToken(token string) error {
	if !enrollment.required {
		return accounts.ErrEnrollmentClosed
	}
	if token != validEnrollmentToken {
		return accounts.ErrEnrollmentToken
	}
	return nil
}

func (enrollment *fakeEnrollment) Start(_ context.Context, token, accountName, password string) error {
	if tokenError := enrollment.checkToken(token); tokenError != nil {
		return tokenError
	}
	if enrollment.startError != nil {
		return enrollment.startError
	}
	enrollment.startCount++
	enrollment.receivedAccount = accountName
	enrollment.receivedPassword = password
	enrollment.pendingSetup = &secondfactor.Setup{}
	return nil
}

func (enrollment *fakeEnrollment) Setup(token string) (*secondfactor.Setup, string, error) {
	if tokenError := enrollment.checkToken(token); tokenError != nil {
		return nil, "", tokenError
	}
	if enrollment.pendingSetup == nil {
		return nil, "", accounts.ErrEnrollmentNotStarted
	}
	return enrollment.pendingSetup, enrollment.receivedAccount, nil
}

func (enrollment *fakeEnrollment) Complete(_ context.Context, token string) (auth.AccountIdentity, error) {
	setup, _, setupError := enrollment.Setup(token)
	if setupError != nil {
		return auth.AccountIdentity{}, setupError
	}
	if enrollment.completeError != nil {
		return auth.AccountIdentity{}, enrollment.completeError
	}
	if !setup.Ready() {
		return auth.AccountIdentity{}, accounts.ErrSecondFactorIncomplete
	}
	enrollment.completionCount++
	enrollment.required = false
	enrollment.pendingSetup = nil
	return enrolledIdentity, nil
}

func enrollBody(token string) string {
	return `{"token":"` + token + `","account_name":"founder","password":"` + enrollmentPassword + `"}`
}

func tokenBody(token string) string {
	return `{"token":"` + token + `"}`
}

func postEnrollStep(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = enrollmentClientIP + ":5555"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func postEnroll(handler http.Handler, body string) *httptest.ResponseRecorder {
	return postEnrollStep(handler, "/api/auth/enroll", body)
}

func getStatus(handler http.Handler) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/status", nil))
	return recorder
}

func handlerWithEnrollment(testContext *testing.T, enrollment *fakeEnrollment) http.Handler {
	return newTestHandlerWithServices(testContext, Services{Enrollment: enrollment})
}

func newEnrollmentWebAuthn(testContext *testing.T) *secondfactor.WebAuthn {
	testContext.Helper()
	relyingParty, relyingPartyError := secondfactor.NewWebAuthn("localhost", []string{"http://localhost:18080"})
	if relyingPartyError != nil {
		testContext.Fatal(relyingPartyError)
	}
	return relyingParty
}

func requireStatus(testContext *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, description string) {
	testContext.Helper()
	if recorder.Code != expectedStatus {
		testContext.Fatalf("%s: expected %d, got %d %q", description, expectedStatus, recorder.Code, recorder.Body.String())
	}
}

func requireErrorBody(testContext *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, expectedCode, description string) {
	testContext.Helper()
	if recorder.Code != expectedStatus || strings.TrimSpace(recorder.Body.String()) != `{"error":"`+expectedCode+`"}` {
		testContext.Errorf("%s: expected %d %s, got %d %q", description, expectedStatus, expectedCode, recorder.Code, recorder.Body.String())
	}
}

// beginTOTPStep calls the TOTP step and returns the secret it disclosed.
func beginTOTPStep(testContext *testing.T, handler http.Handler) string {
	testContext.Helper()
	recorder := postEnrollStep(handler, "/api/auth/enroll/totp", tokenBody(validEnrollmentToken))
	requireStatus(testContext, recorder, http.StatusOK, "totp")
	var totpResponse struct {
		Secret     string `json:"secret"`
		OTPAuthURL string `json:"otpauth_url"`
	}
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &totpResponse); decodeError != nil {
		testContext.Fatal(decodeError)
	}
	if totpResponse.Secret == "" || !strings.HasPrefix(totpResponse.OTPAuthURL, "otpauth://totp/") {
		testContext.Fatalf("expected a secret and an otpauth url, got %q", recorder.Body.String())
	}
	return totpResponse.Secret
}

func currentCode(testContext *testing.T, secret string) string {
	testContext.Helper()
	code, codeError := totp.GenerateCode(secret, time.Now())
	if codeError != nil {
		testContext.Fatal(codeError)
	}
	return code
}

// wrongCodeFor shifts every digit of the current code, so it never equals it.
func wrongCodeFor(testContext *testing.T, secret string) string {
	testContext.Helper()
	shiftedDigits := []byte(currentCode(testContext, secret))
	for digitIndex, digit := range shiftedDigits {
		shiftedDigits[digitIndex] = '0' + (digit-'0'+5)%10
	}
	return string(shiftedDigits)
}

func confirmBody(code string) string {
	return `{"token":"` + validEnrollmentToken + `","code":"` + code + `"}`
}

func recoveryCodesFrom(testContext *testing.T, recorder *httptest.ResponseRecorder) []string {
	testContext.Helper()
	var codesResponse struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &codesResponse); decodeError != nil {
		testContext.Fatal(decodeError)
	}
	return codesResponse.RecoveryCodes
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

func TestEnrollAccountStepSetsNoSessionCookie(testContext *testing.T) {
	enrollment := &fakeEnrollment{required: true}
	handler := handlerWithEnrollment(testContext, enrollment)

	enrollRecorder := postEnroll(handler, enrollBody(validEnrollmentToken))

	expectedBody := `{"status":"second_factor_required","methods":["totp"]}`
	if enrollRecorder.Code != http.StatusOK || strings.TrimSpace(enrollRecorder.Body.String()) != expectedBody {
		testContext.Fatalf("unexpected response %d %q", enrollRecorder.Code, enrollRecorder.Body.String())
	}
	if enrollment.startCount != 1 || enrollment.receivedAccount != "founder" || enrollment.receivedPassword != enrollmentPassword {
		testContext.Errorf("account step not started with the submitted values: %+v", enrollment)
	}
	if enrollment.completionCount != 0 {
		testContext.Error("the account step must not complete the enrollment")
	}
	if cookies := enrollRecorder.Result().Cookies(); len(cookies) != 0 {
		testContext.Errorf("the account step must not open a session, got %v", cookies)
	}
}

func TestEnrollAccountStepOffersWebAuthnWhenConfigured(testContext *testing.T) {
	handler := newTestHandlerWithServices(testContext, Services{Enrollment: &fakeEnrollment{required: true}, WebAuthn: newEnrollmentWebAuthn(testContext)})

	recorder := postEnroll(handler, enrollBody(validEnrollmentToken))

	if strings.TrimSpace(recorder.Body.String()) != `{"status":"second_factor_required","methods":["totp","webauthn"]}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestEnrollTOTPConfirmRejectsWrongCode(testContext *testing.T) {
	enrollment := &fakeEnrollment{required: true}
	handler := handlerWithEnrollment(testContext, enrollment)
	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")
	secret := beginTOTPStep(testContext, handler)

	wrongRecorder := postEnrollStep(handler, "/api/auth/enroll/totp/confirm", confirmBody(wrongCodeFor(testContext, secret)))

	requireErrorBody(testContext, wrongRecorder, http.StatusBadRequest, "invalid_code", "wrong code")
	if len(enrollment.pendingSetup.ConfirmedMethods()) != 0 {
		testContext.Error("a wrong code must not confirm the factor")
	}
	rightRecorder := postEnrollStep(handler, "/api/auth/enroll/totp/confirm", confirmBody(currentCode(testContext, secret)))
	if rightRecorder.Code != http.StatusOK || strings.TrimSpace(rightRecorder.Body.String()) != `{"status":"ok"}` {
		testContext.Errorf("right code: unexpected response %d %q", rightRecorder.Code, rightRecorder.Body.String())
	}
}

func TestEnrollRecoveryCodesRequireConfirmedFactor(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})
	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")
	secret := beginTOTPStep(testContext, handler)

	beforeConfirmRecorder := postEnrollStep(handler, "/api/auth/enroll/recovery-codes", tokenBody(validEnrollmentToken))

	requireErrorBody(testContext, beforeConfirmRecorder, http.StatusConflict, "second_factor_required", "codes before confirmation")
	requireStatus(testContext, postEnrollStep(handler, "/api/auth/enroll/totp/confirm", confirmBody(currentCode(testContext, secret))), http.StatusOK, "confirm")
	firstCodesRecorder := postEnrollStep(handler, "/api/auth/enroll/recovery-codes", tokenBody(validEnrollmentToken))
	secondCodesRecorder := postEnrollStep(handler, "/api/auth/enroll/recovery-codes", tokenBody(validEnrollmentToken))
	requireStatus(testContext, firstCodesRecorder, http.StatusOK, "codes")
	firstCodes := recoveryCodesFrom(testContext, firstCodesRecorder)
	secondCodes := recoveryCodesFrom(testContext, secondCodesRecorder)
	if len(firstCodes) != 10 || strings.Join(firstCodes, ",") != strings.Join(secondCodes, ",") {
		testContext.Errorf("expected the same 10 codes until completion, got %v and %v", firstCodes, secondCodes)
	}
}

func TestEnrollCompleteSetsSessionCookieAndAudits(testContext *testing.T) {
	enrollment := &fakeEnrollment{required: true}
	recorder := &fakeAuditRecorder{}
	handler := newTestHandlerWithServices(testContext, Services{Enrollment: enrollment, Audit: recorder})
	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")
	secret := beginTOTPStep(testContext, handler)
	requireStatus(testContext, postEnrollStep(handler, "/api/auth/enroll/totp/confirm", confirmBody(currentCode(testContext, secret))), http.StatusOK, "confirm")

	incompleteRecorder := postEnrollStep(handler, "/api/auth/enroll/complete", tokenBody(validEnrollmentToken))
	requireErrorBody(testContext, incompleteRecorder, http.StatusConflict, "second_factor_required", "complete before codes")
	if len(incompleteRecorder.Result().Cookies()) != 0 || len(recorder.events) != 0 {
		testContext.Fatal("an incomplete enrollment must neither open a session nor audit")
	}
	requireStatus(testContext, postEnrollStep(handler, "/api/auth/enroll/recovery-codes", tokenBody(validEnrollmentToken)), http.StatusOK, "codes")

	completeRecorder := postEnrollStep(handler, "/api/auth/enroll/complete", tokenBody(validEnrollmentToken))

	if completeRecorder.Code != http.StatusOK || strings.TrimSpace(completeRecorder.Body.String()) != `{"status":"ok"}` {
		testContext.Fatalf("unexpected response %d %q", completeRecorder.Code, completeRecorder.Body.String())
	}
	cookies := completeRecorder.Result().Cookies()
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
	expectedEvents := []recordedAuditEvent{
		{action: audit.ActionSecondFactorEnrolled, target: "totp", clientIP: enrollmentClientIP},
		{action: audit.ActionEnrollmentCompleted, target: "founder", clientIP: enrollmentClientIP},
	}
	if len(recorder.events) != len(expectedEvents) {
		testContext.Fatalf("expected %v, got %v", expectedEvents, recorder.events)
	}
	for eventIndex, expectedEvent := range expectedEvents {
		if recorder.events[eventIndex] != expectedEvent {
			testContext.Errorf("event %d: expected %+v, got %+v", eventIndex, expectedEvent, recorder.events[eventIndex])
		}
	}
	if enrollment.completionCount != 1 {
		testContext.Errorf("expected one completion, got %d", enrollment.completionCount)
	}
}

func TestEnrollReturns404WhenClosed(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: false})
	recorder := postEnroll(handler, enrollBody(validEnrollmentToken))

	if recorder.Code != http.StatusNotFound || strings.TrimSpace(recorder.Body.String()) != `{"error":"not_found"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Error("no cookie expected when enrolment is closed")
	}
	requireErrorBody(testContext, postEnrollStep(handler, "/api/auth/enroll/complete", tokenBody(validEnrollmentToken)), http.StatusNotFound, "not_found", "complete when closed")
	requireErrorBody(testContext, postEnrollStep(handler, "/api/auth/enroll/totp", tokenBody(validEnrollmentToken)), http.StatusNotFound, "not_found", "totp when closed")
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

// Peers whose address does not parse all collapse to the empty audit
// address; the rate limiter must still key them apart by their raw peer.
func TestEnrollCompleteLimiterKeysUnparseablePeersApart(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})
	postCompleteFrom := func(peerAddress string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/enroll/complete", strings.NewReader(tokenBody("wrong")))
		request.RemoteAddr = peerAddress
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	for attemptNumber := 1; attemptNumber <= secondFactorAttemptsPerIP; attemptNumber++ {
		postCompleteFrom("first-unparseable-peer")
	}

	recorder := postCompleteFrom("second-unparseable-peer")

	if recorder.Code == http.StatusTooManyRequests {
		testContext.Error("a different peer must not share the exhausted rate-limit bucket")
	}
}

var enrollmentStepPaths = []string{
	"/api/auth/enroll/totp",
	"/api/auth/enroll/totp/confirm",
	"/api/auth/enroll/webauthn/options",
	"/api/auth/enroll/webauthn/confirm",
	"/api/auth/enroll/recovery-codes",
	"/api/auth/enroll/complete",
}

func TestEnrollStepsRejectWrongToken(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})
	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")

	for _, stepPath := range enrollmentStepPaths {
		wrongTokenBody := `{"token":"wrong","code":"123456","credential":{}}`

		recorder := postEnrollStep(handler, stepPath, wrongTokenBody)

		requireErrorBody(testContext, recorder, http.StatusForbidden, "invalid_enrollment_token", stepPath)
		if len(recorder.Result().Cookies()) != 0 {
			testContext.Errorf("%s: no cookie expected with a wrong token", stepPath)
		}
	}
}

func TestEnrollStepsRequireTheAccountStep(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})

	for _, stepPath := range enrollmentStepPaths {
		recorder := postEnrollStep(handler, stepPath, `{"token":"`+validEnrollmentToken+`","code":"123456","credential":{}}`)

		requireErrorBody(testContext, recorder, http.StatusConflict, "enrollment_not_started", stepPath)
	}
}

func TestEnrollStepsRejectInvalidRequests(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})

	for _, stepPath := range enrollmentStepPaths {
		requireErrorBody(testContext, postEnrollStep(handler, stepPath, `not json`), http.StatusBadRequest, "invalid_request", stepPath+" malformed")
		requireErrorBody(testContext, postEnrollStep(handler, stepPath, `{}`), http.StatusBadRequest, "invalid_request", stepPath+" missing token")
	}
	oversizedTokenBody := `{"token":"` + strings.Repeat("a", 2000) + `"}`
	requireErrorBody(testContext, postEnrollStep(handler, "/api/auth/enroll/totp", oversizedTokenBody), http.StatusBadRequest, "invalid_request", "oversized body")
}

func TestFullTOTPEnrollmentWithOneTypoIsNotRateLimited(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})

	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")
	secret := beginTOTPStep(testContext, handler)
	steps := []struct {
		path           string
		body           string
		expectedStatus int
	}{
		{"/api/auth/enroll/totp/confirm", confirmBody(wrongCodeFor(testContext, secret)), http.StatusBadRequest},
		{"/api/auth/enroll/totp/confirm", confirmBody(currentCode(testContext, secret)), http.StatusOK},
		{"/api/auth/enroll/webauthn/options", tokenBody(validEnrollmentToken), http.StatusNotFound},
		{"/api/auth/enroll/recovery-codes", tokenBody(validEnrollmentToken), http.StatusOK},
		{"/api/auth/enroll/recovery-codes", tokenBody(validEnrollmentToken), http.StatusOK},
		{"/api/auth/enroll/complete", tokenBody(validEnrollmentToken), http.StatusOK},
	}
	for _, currentStep := range steps {
		requireStatus(testContext, postEnrollStep(handler, currentStep.path, currentStep.body), currentStep.expectedStatus, currentStep.path)
	}
}

func TestEnrollWebAuthnOptionsReturns404WhenDisabled(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true})
	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")

	optionsRecorder := postEnrollStep(handler, "/api/auth/enroll/webauthn/options", tokenBody(validEnrollmentToken))
	confirmRecorder := postEnrollStep(handler, "/api/auth/enroll/webauthn/confirm", `{"token":"`+validEnrollmentToken+`","credential":{}}`)

	requireErrorBody(testContext, optionsRecorder, http.StatusNotFound, "webauthn_disabled", "options")
	requireErrorBody(testContext, confirmRecorder, http.StatusNotFound, "webauthn_disabled", "confirm")
}

func TestEnrollWebAuthnStepsWhenConfigured(testContext *testing.T) {
	handler := newTestHandlerWithServices(testContext, Services{Enrollment: &fakeEnrollment{required: true}, WebAuthn: newEnrollmentWebAuthn(testContext)})
	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")

	optionsRecorder := postEnrollStep(handler, "/api/auth/enroll/webauthn/options", tokenBody(validEnrollmentToken))

	requireStatus(testContext, optionsRecorder, http.StatusOK, "options")
	var optionsResponse struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if decodeError := json.Unmarshal(optionsRecorder.Body.Bytes(), &optionsResponse); decodeError != nil || optionsResponse.PublicKey.Challenge == "" {
		testContext.Errorf("expected publicKey creation options, got %q", optionsRecorder.Body.String())
	}
	forgedRecorder := postEnrollStep(handler, "/api/auth/enroll/webauthn/confirm", `{"token":"`+validEnrollmentToken+`","credential":{"id":"forged"}}`)
	requireErrorBody(testContext, forgedRecorder, http.StatusBadRequest, "webauthn_failed", "forged credential")
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
		handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true, startError: expectation.failure})

		recorder := postEnroll(handler, enrollBody(validEnrollmentToken))

		if recorder.Code != http.StatusBadRequest || strings.TrimSpace(recorder.Body.String()) != `{"error":"`+expectation.expectedCode+`"}` {
			testContext.Errorf("%s: unexpected response %d %q", description, recorder.Code, recorder.Body.String())
		}
	}
}

func TestEnrollReturns503WhenTheDatabaseFails(testContext *testing.T) {
	handler := handlerWithEnrollment(testContext, &fakeEnrollment{required: true, startError: errors.New("connection refused")})

	recorder := postEnroll(handler, enrollBody(validEnrollmentToken))

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestEnrollCompleteReturns503WhenTheDatabaseFails(testContext *testing.T) {
	enrollment := &fakeEnrollment{required: true, completeError: errors.New("connection refused")}
	handler := handlerWithEnrollment(testContext, enrollment)
	requireStatus(testContext, postEnroll(handler, enrollBody(validEnrollmentToken)), http.StatusOK, "enroll")

	recorder := postEnrollStep(handler, "/api/auth/enroll/complete", tokenBody(validEnrollmentToken))

	requireErrorBody(testContext, recorder, http.StatusServiceUnavailable, "database_unavailable", "complete")
}
