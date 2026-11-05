package sidecarserver

import (
	"net/http"
	"testing"

	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

func TestHealthAnswersOkWithoutAuthentication(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)

	recorder := fixture.serve(newSignedRequest(http.MethodGet, sidecarapi.PathHealth, "", nil))

	expectResponse(testContext, recorder, http.StatusOK, "ok")
}

func TestHealthOnlyOpensItsReadMethods(testContext *testing.T) {
	fixture := newAuthenticatedFixture(testContext)

	recorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathHealth, "", forbiddenBodyReader{testContext: testContext}))

	expectResponse(testContext, recorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeInvalidToken))
}
