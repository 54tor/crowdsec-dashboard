package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
)

const (
	unauthenticatedBody = "{\"error\":\"unauthenticated\"}\n"
	forbiddenBody       = "{\"error\":\"forbidden\"}\n"
)

func serveWithRole(testContext *testing.T, requiredRole string, identity *auth.AccountIdentity) (*httptest.ResponseRecorder, bool) {
	testContext.Helper()
	nextHandlerCalled := false
	protected := auth.RequireRole(requiredRole)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		nextHandlerCalled = true
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	if identity != nil {
		request = request.WithContext(auth.ContextWithIdentity(request.Context(), *identity))
	}
	recorder := httptest.NewRecorder()
	protected.ServeHTTP(recorder, request)
	return recorder, nextHandlerCalled
}

func TestRequireRoleLetsAdminThrough(testContext *testing.T) {
	recorder, nextHandlerCalled := serveWithRole(testContext, auth.RoleAdmin, &auth.AccountIdentity{AccountID: 1, AccountRole: auth.RoleAdmin})

	if recorder.Code != http.StatusNoContent || !nextHandlerCalled {
		testContext.Errorf("admin must pass: code %d, handler called %v", recorder.Code, nextHandlerCalled)
	}
}

func TestRequireRoleRejectsReadOnlyWith403Forbidden(testContext *testing.T) {
	recorder, nextHandlerCalled := serveWithRole(testContext, auth.RoleAdmin, &auth.AccountIdentity{AccountID: 2, AccountRole: auth.RoleReadOnly})

	if nextHandlerCalled {
		testContext.Error("handler must not run for read_only")
	}
	if recorder.Code != http.StatusForbidden || recorder.Body.String() != forbiddenBody {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestRequireRoleWithoutIdentityReturns401(testContext *testing.T) {
	recorder, nextHandlerCalled := serveWithRole(testContext, auth.RoleAdmin, nil)

	if nextHandlerCalled {
		testContext.Error("handler must not run without identity")
	}
	if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != unauthenticatedBody {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestRequireRoleDeniesUnknownAndEmptyRoles(testContext *testing.T) {
	for _, unknownRole := range []string{"", "root", "ADMIN", "admin ", "superadmin"} {
		recorder, nextHandlerCalled := serveWithRole(testContext, auth.RoleAdmin, &auth.AccountIdentity{AccountID: 3, AccountRole: unknownRole})

		if nextHandlerCalled || recorder.Code != http.StatusForbidden {
			testContext.Errorf("role %q must be denied: code %d, handler called %v", unknownRole, recorder.Code, nextHandlerCalled)
		}
	}
}

func TestRequireRoleDeniesEmptyRequiredRole(testContext *testing.T) {
	recorder, nextHandlerCalled := serveWithRole(testContext, "", &auth.AccountIdentity{AccountID: 4, AccountRole: ""})

	if nextHandlerCalled || recorder.Code != http.StatusForbidden {
		testContext.Errorf("empty required role must deny everyone: code %d, handler called %v", recorder.Code, nextHandlerCalled)
	}
}

func TestRequireRoleForbiddenBodyNamesNoRole(testContext *testing.T) {
	recorder, _ := serveWithRole(testContext, auth.RoleAdmin, &auth.AccountIdentity{AccountID: 2, AccountRole: auth.RoleReadOnly})

	if recorder.Body.String() != forbiddenBody {
		testContext.Errorf("body must be the fixed generic error, got %q", recorder.Body.String())
	}
}

func TestRequireRoleAfterRequireSessionHidesRoleFromUnauthenticated(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	chain := auth.RequireAuthentication(store, nil, nil, nil)(auth.RequireRole(auth.RoleAdmin)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		testContext.Error("handler must not run")
	})))
	recorder := httptest.NewRecorder()

	chain.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/x", nil))

	if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != unauthenticatedBody {
		testContext.Errorf("unauthenticated caller must get 401, got %d %q", recorder.Code, recorder.Body.String())
	}
}
