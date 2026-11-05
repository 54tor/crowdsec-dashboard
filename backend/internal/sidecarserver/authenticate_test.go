package sidecarserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

const pingOKBody = `{"status":"ok"}` + "\n"

func TestUnauthenticatedRequestIsRefusedBeforeTheBodyIsRead(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	request := newSignedRequest(http.MethodPost, sidecarapi.PathExec, "", forbiddenBodyReader{testContext: testContext})

	recorder := fixture.serve(request)

	expectResponse(testContext, recorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeInvalidToken))
}

func TestPingAnswersOnlyToAValidToken(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, nil)

	firstRecorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathPing, token, nil))
	expectResponse(testContext, firstRecorder, http.StatusOK, pingOKBody)

	// The same token a second time must be refused by the replay cache, even
	// though signature, binding and times are all still valid.
	replayRecorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathPing, token, nil))
	expectResponse(testContext, replayRecorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeReplayed))
}

func TestHeaderRefusalsNeverReadTheBody(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	otherKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("GenerateSigningKey: %v", generateError)
	}
	untrustedSigner := sidecarauth.NewSigner(testIssuer, testAudience, otherKey, func() time.Time { return testNow })
	untrustedToken, signError := untrustedSigner.Sign(http.MethodPost, sidecarapi.PathPing, nil)
	if signError != nil {
		testContext.Fatalf("Sign: %v", signError)
	}

	refusalCases := []struct {
		caseName      string
		requestMethod string
		requestURI    string
		authorization string
		expectedCode  string
	}{
		{"garbage token", http.MethodPost, sidecarapi.PathPing, sidecarauth.AuthorizationPrefix + "v4.public.garbage", sidecarauth.CodeInvalidToken},
		{"missing bearer prefix", http.MethodPost, sidecarapi.PathPing, fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, nil), sidecarauth.CodeInvalidToken},
		{"untrusted key", http.MethodPost, sidecarapi.PathPing, sidecarauth.AuthorizationPrefix + untrustedToken, sidecarauth.CodeUnknownKey},
		{"token for another path", http.MethodPost, sidecarapi.PathExec, sidecarauth.AuthorizationPrefix + fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, nil), sidecarauth.CodeRequestMismatch},
		{"token for another method", http.MethodPut, sidecarapi.PathPing, sidecarauth.AuthorizationPrefix + fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, nil), sidecarauth.CodeRequestMismatch},
		{"token for another query", http.MethodPost, sidecarapi.PathPing + "?name=b", sidecarauth.AuthorizationPrefix + fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing+"?name=a", nil), sidecarauth.CodeRequestMismatch},
		{"token for the decoded query", http.MethodPost, sidecarapi.PathPing + "?name=a%2Fb", sidecarauth.AuthorizationPrefix + fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing+"?name=a/b", nil), sidecarauth.CodeRequestMismatch},
		{"unknown route still authenticated first", http.MethodGet, "/v1/unknown", "", sidecarauth.CodeInvalidToken},
	}
	for _, refusalCase := range refusalCases {
		testContext.Run(refusalCase.caseName, func(caseContext *testing.T) {
			request := newSignedRequest(refusalCase.requestMethod, refusalCase.requestURI, "", forbiddenBodyReader{testContext: caseContext})
			if refusalCase.authorization != "" {
				request.Header.Set("Authorization", refusalCase.authorization)
			}

			recorder := fixture.serve(request)

			expectResponse(caseContext, recorder, http.StatusUnauthorized, codeBody(refusalCase.expectedCode))
		})
	}
}

func TestRawQueryIsTheSignedRequestURI(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	encodedRequestURI := sidecarapi.PathPing + "?name=a%2Fb"
	token := fixture.sign(testContext, http.MethodPost, encodedRequestURI, nil)

	recorder := fixture.serve(newSignedRequest(http.MethodPost, encodedRequestURI, token, nil))

	expectResponse(testContext, recorder, http.StatusOK, pingOKBody)
}

func TestBodyIsCheckedAgainstTheSignedHash(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, []byte("signed body"))

	recorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathPing, token, strings.NewReader("another body")))

	expectResponse(testContext, recorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeBodyMismatch))
}

func TestSignedBodyIsAccepted(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	signedBody := []byte("signed body")
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, signedBody)

	recorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathPing, token, bytes.NewReader(signedBody)))

	expectResponse(testContext, recorder, http.StatusOK, pingOKBody)
}

func TestOversizeBodyIsRefused(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	// One byte above the ping cap, correctly signed: only the size cap refuses it.
	oversizeBody := bytes.Repeat([]byte("a"), pingBodyLimit+1)
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, oversizeBody)

	recorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathPing, token, bytes.NewReader(oversizeBody)))

	expectResponse(testContext, recorder, http.StatusRequestEntityTooLarge, codeBody(sidecarapi.CodeBodyTooLarge))
}

func TestHandlerWithoutVerifierRefusesEveryRequest(testContext *testing.T) {
	handler := NewHandler(Dependencies{Executor: forbiddenExecutor{testContext: testContext}})
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, newSignedRequest(http.MethodPost, sidecarapi.PathPing, "anything", forbiddenBodyReader{testContext: testContext}))

	expectResponse(testContext, recorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeInvalidToken))
}

func TestRefusalLogCarriesTheCodeButNotTheToken(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathPing, nil)

	fixture.serve(newSignedRequest(http.MethodPut, sidecarapi.PathPing, token, nil))

	logLine := fixture.logOutput.String()
	if !strings.Contains(logLine, `"msg":"sidecar_auth_refused"`) || !strings.Contains(logLine, `"code":"request_mismatch"`) {
		testContext.Errorf("expected a refusal log line with its code, got %q", logLine)
	}
	if strings.Contains(logLine, token) || strings.Contains(logLine, fixture.signingKey.KeyID) {
		testContext.Errorf("refusal log leaks the token or its key id: %q", logLine)
	}
}
