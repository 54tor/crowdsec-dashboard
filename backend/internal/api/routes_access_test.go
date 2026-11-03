package api

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
)

const (
	readOnlyAccountID    int64 = 11
	adminAccountID       int64 = 12
	readOnlyTokenSecret        = "csd_read-only-token"
	adminWriteTokenValue       = "csd_admin-write-token"
)

var pathParameterPattern = regexp.MustCompile(`\{[^}]*\}`)

var mutatingRoutesAllowedBelowAdmin = map[string]bool{
	"POST /api/auth/logout-all":                   true,
	"POST /api/account/access-rules":              true,
	"DELETE /api/account/access-rules/{id}":       true,
	"POST /api/tokens":                            true,
	"DELETE /api/tokens/{id}":                     true,
	"POST /api/auth/enroll":                       true,
	"POST /api/auth/enroll/totp":                  true,
	"POST /api/auth/enroll/totp/confirm":          true,
	"POST /api/auth/enroll/webauthn/options":      true,
	"POST /api/auth/enroll/webauthn/confirm":      true,
	"POST /api/auth/enroll/recovery-codes":        true,
	"POST /api/auth/enroll/complete":              true,
	"POST /api/auth/login":                        true,
	"POST /api/auth/login/totp":                   true,
	"POST /api/auth/login/recovery-code":          true,
	"POST /api/auth/login/webauthn/options":       true,
	"POST /api/auth/login/webauthn":               true,
	"POST /api/auth/login/setup/totp":             true,
	"POST /api/auth/login/setup/totp/confirm":     true,
	"POST /api/auth/login/setup/webauthn/options": true,
	"POST /api/auth/login/setup/webauthn/confirm": true,
	"POST /api/auth/login/setup/recovery-codes":   true,
	"POST /api/auth/login/setup/complete":         true,
	"POST /api/auth/logout":                       true,
}

type allowEveryTokenGate struct{}

func (allowEveryTokenGate) AllowToken(_ context.Context, _ auth.AccountIdentity, _ netip.Addr) (bool, error) {
	return true, nil
}

type routeAccessEnvironment struct {
	sessions       *authtest.SessionStore
	tokens         *authtest.TokenStore
	readOnlyCookie *http.Cookie
	adminCookie    *http.Cookie
}

func newRouteAccessEnvironment(testContext *testing.T) routeAccessEnvironment {
	testContext.Helper()
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		accountRole := auth.RoleReadOnly
		if accountID == adminAccountID {
			accountRole = auth.RoleAdmin
		}
		return auth.AccountIdentity{AccountID: accountID, AccountName: "alice", AccountRole: accountRole, AuthMethod: auth.AuthMethodSession}, true
	})
	tokens := authtest.NewTokenStore(map[string]auth.AccountIdentity{
		readOnlyTokenSecret:  {AccountID: adminAccountID, AccountName: "alice", AccountRole: auth.RoleReadOnly},
		adminWriteTokenValue: {AccountID: adminAccountID, AccountName: "alice", AccountRole: auth.RoleAdmin},
	})
	return routeAccessEnvironment{
		sessions:       sessions,
		tokens:         tokens,
		readOnlyCookie: newAuthenticatedCookie(testContext, sessions, readOnlyAccountID),
		adminCookie:    newAuthenticatedCookie(testContext, sessions, adminAccountID),
	}
}

func (environment routeAccessEnvironment) services() Services {
	return Services{Sessions: environment.sessions, Tokens: environment.tokens, TokenGate: allowEveryTokenGate{}}
}

func routeTableForTest(environment routeAccessEnvironment) []apiRoute {
	return apiRoutes(config.Config{SessionTTL: time.Hour}, environment.services(), &authHandlers{})
}

func splitRoutePattern(pattern string) (method, path string) {
	method, path, _ = strings.Cut(pattern, " ")
	return method, path
}

func concretePath(path string) string {
	return pathParameterPattern.ReplaceAllString(path, "x")
}

type recordingHandler struct{ wasCalled bool }

func (handler *recordingHandler) ServeHTTP(responseWriter http.ResponseWriter, _ *http.Request) {
	handler.wasCalled = true
	responseWriter.WriteHeader(http.StatusNoContent)
}

func mountRouteBehindProtect(environment routeAccessEnvironment, route apiRoute) (http.Handler, *recordingHandler) {
	recorder := &recordingHandler{}
	router := http.NewServeMux()
	router.Handle(route.Pattern, protect(route.Access, recorder, environment.sessions, environment.tokens, allowEveryTokenGate{}, nil))
	return router, recorder
}

func requestRoute(handler http.Handler, route apiRoute, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
	method, path := splitRoutePattern(route.Pattern)
	request := httptest.NewRequest(method, "https://dashboard.example.com"+concretePath(path), nil)
	request.RemoteAddr = "198.51.100.7:5000"
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func isAdminRoute(route apiRoute) bool {
	return route.Access == accessAdmin || route.Access == accessAdminSessionOnly
}

func isSessionOnlyRoute(route apiRoute) bool {
	return route.Access == accessSessionOnly || route.Access == accessAdminSessionOnly
}

func TestEveryMutatingRouteIsAdminUnlessListed(testContext *testing.T) {
	for _, route := range routeTableForTest(newRouteAccessEnvironment(testContext)) {
		method, _ := splitRoutePattern(route.Pattern)
		if method == http.MethodGet || isAdminRoute(route) || mutatingRoutesAllowedBelowAdmin[route.Pattern] {
			continue
		}
		testContext.Errorf("mutating route %q is neither admin nor listed", route.Pattern)
	}
}

func TestReadOnlySessionGets403OnEveryAdminRoute(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	for _, route := range routeTableForTest(environment) {
		if !isAdminRoute(route) {
			continue
		}
		handler, recorder := mountRouteBehindProtect(environment, route)
		response := requestRoute(handler, route, environment.readOnlyCookie, "")
		if response.Code != http.StatusForbidden || recorder.wasCalled {
			testContext.Errorf("%s: expected 403 without reaching the handler, got %d (called=%v)", route.Pattern, response.Code, recorder.wasCalled)
		}
	}
}

func TestReadTokenGets403OnEveryAdminRoute(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	for _, route := range routeTableForTest(environment) {
		if !isAdminRoute(route) {
			continue
		}
		handler, recorder := mountRouteBehindProtect(environment, route)
		response := requestRoute(handler, route, nil, readOnlyTokenSecret)
		if response.Code != http.StatusForbidden || recorder.wasCalled {
			testContext.Errorf("%s: expected 403 without reaching the handler, got %d (called=%v)", route.Pattern, response.Code, recorder.wasCalled)
		}
	}
}

func TestAdminWriteTokenGets403OnEngineWrites(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	engineWrites := map[string]bool{"POST /api/engines": true, "PATCH /api/engines/{name}": true, "DELETE /api/engines/{name}": true}
	checkedRoutes := 0
	for _, route := range routeTableForTest(environment) {
		if !engineWrites[route.Pattern] {
			continue
		}
		checkedRoutes++
		handler, recorder := mountRouteBehindProtect(environment, route)
		response := requestRoute(handler, route, nil, adminWriteTokenValue)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "session_required") || recorder.wasCalled {
			testContext.Errorf("%s: expected 403 session_required, got %d %q", route.Pattern, response.Code, response.Body.String())
		}
	}
	if checkedRoutes != len(engineWrites) {
		testContext.Errorf("expected %d engine write routes, found %d", len(engineWrites), checkedRoutes)
	}
}

func TestTokenGets403SessionRequiredOnSessionOnlyRoutes(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	for _, route := range routeTableForTest(environment) {
		if !isSessionOnlyRoute(route) {
			continue
		}
		handler, recorder := mountRouteBehindProtect(environment, route)
		response := requestRoute(handler, route, nil, adminWriteTokenValue)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "session_required") || recorder.wasCalled {
			testContext.Errorf("%s: expected 403 session_required, got %d %q", route.Pattern, response.Code, response.Body.String())
		}
	}
}

func TestWriteTokenOfAdminReachesAdminRoute(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	reachedRoutes := 0
	for _, route := range routeTableForTest(environment) {
		if route.Access != accessAdmin {
			continue
		}
		reachedRoutes++
		handler, recorder := mountRouteBehindProtect(environment, route)
		response := requestRoute(handler, route, nil, adminWriteTokenValue)
		if response.Code != http.StatusNoContent || !recorder.wasCalled {
			testContext.Errorf("%s: expected the handler to be reached, got %d", route.Pattern, response.Code)
		}
	}
	if reachedRoutes == 0 {
		testContext.Error("no accessAdmin route in the table")
	}
}

func TestReadOnlySessionCanReadEveryGetRoute(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	for _, route := range routeTableForTest(environment) {
		method, _ := splitRoutePattern(route.Pattern)
		if method != http.MethodGet || route.Access != accessAuthenticated {
			continue
		}
		handler, recorder := mountRouteBehindProtect(environment, route)
		response := requestRoute(handler, route, environment.readOnlyCookie, "")
		if response.Code == http.StatusForbidden || !recorder.wasCalled {
			testContext.Errorf("%s: read-only session must reach the handler, got %d", route.Pattern, response.Code)
		}
	}
}

func TestReadOnlySessionGets403ThroughRealHandler(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	realHandler := newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, environment.services())
	for _, route := range routeTableForTest(environment) {
		if !isAdminRoute(route) {
			continue
		}
		response := requestRoute(realHandler, route, environment.readOnlyCookie, "")
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "forbidden") {
			testContext.Errorf("%s: expected 403 forbidden through newHandler, got %d %q", route.Pattern, response.Code, response.Body.String())
		}
	}
}

func TestBearerTokenGets403SessionRequiredThroughRealHandler(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	realHandler := newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, environment.services())
	checkedRoutes := 0
	for _, route := range routeTableForTest(environment) {
		if !isSessionOnlyRoute(route) {
			continue
		}
		checkedRoutes++
		response := requestRoute(realHandler, route, nil, adminWriteTokenValue)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "session_required") {
			testContext.Errorf("%s: expected 403 session_required through newHandler, got %d %q", route.Pattern, response.Code, response.Body.String())
		}
	}
	if checkedRoutes == 0 {
		testContext.Error("no session-only route in the table")
	}
}

func TestOnlyRegisterRoutesCallsHandleForAPI(testContext *testing.T) {
	fileSet := token.NewFileSet()
	packages, parseError := parser.ParseDir(fileSet, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if parseError != nil {
		testContext.Fatalf("parse package: %v", parseError)
	}
	for _, parsedPackage := range packages {
		for _, parsedFile := range parsedPackage.Files {
			for _, declaration := range parsedFile.Decls {
				functionDeclaration, isFunction := declaration.(*ast.FuncDecl)
				if !isFunction || functionDeclaration.Name.Name == "registerRoutes" {
					continue
				}
				assertNoAPIHandle(testContext, fileSet, functionDeclaration)
			}
		}
	}
}

func assertNoAPIHandle(testContext *testing.T, fileSet *token.FileSet, functionDeclaration *ast.FuncDecl) {
	testContext.Helper()
	ast.Inspect(functionDeclaration, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector || (selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc") {
			return true
		}
		pattern, isLiteral := call.Args[0].(*ast.BasicLit)
		if !isLiteral || strings.Contains(pattern.Value, "/api/") {
			testContext.Errorf("%s: %s outside registerRoutes", fileSet.Position(call.Pos()), selector.Sel.Name)
		}
		return true
	})
}

var requiredSessionOnlyRoutes = map[string]routeAccess{
	"POST /api/auth/logout-all":             accessSessionOnly,
	"GET /api/account/access-rules":         accessSessionOnly,
	"POST /api/account/access-rules":        accessSessionOnly,
	"DELETE /api/account/access-rules/{id}": accessSessionOnly,
	"GET /api/tokens":                       accessSessionOnly,
	"POST /api/tokens":                      accessSessionOnly,
	"DELETE /api/tokens/{id}":               accessSessionOnly,

	"GET /api/accounts":                             accessAdminSessionOnly,
	"POST /api/accounts":                            accessAdminSessionOnly,
	"POST /api/accounts/{name}/role":                accessAdminSessionOnly,
	"POST /api/accounts/{name}/second-factor/reset": accessAdminSessionOnly,
	"POST /api/accounts/{name}/sessions/revoke":     accessAdminSessionOnly,
	"POST /api/accounts/{name}/unlock":              accessAdminSessionOnly,
	"DELETE /api/accounts/{name}":                   accessAdminSessionOnly,
}

var requiredSyncRoutes = map[string]routeAccess{
	"GET /api/sync":      accessAuthenticated,
	"POST /api/sync/run": accessAdmin,
	"POST /api/export":   accessAdmin,
	"POST /api/import":   accessAdminSessionOnly,
}

// requiredAllowlistRoutes pins the access class of every allowlist route; any new
// /allowlists route must be added here (see TestEveryAllowlistMutationRouteIsAdminInRouteTable).
var requiredAllowlistRoutes = map[string]routeAccess{
	"GET /api/engines/{name}/allowlists":                        accessAuthenticated,
	"POST /api/engines/{name}/allowlists":                       accessAdmin,
	"DELETE /api/engines/{name}/allowlists/{allowlist}":         accessAdmin,
	"POST /api/engines/{name}/allowlists/{allowlist}/entries":   accessAdmin,
	"DELETE /api/engines/{name}/allowlists/{allowlist}/entries": accessAdmin,
}

var publicRoutePattern = regexp.MustCompile(`^(POST /api/auth/(login|enroll|logout)(/.*)?|GET /api/healthz|GET /api/auth/status)$`)

func TestSessionOnlyRoutesKeepTheirAccessClass(testContext *testing.T) {
	foundAccessByPattern := map[string]routeAccess{}
	for _, route := range routeTableForTest(newRouteAccessEnvironment(testContext)) {
		foundAccessByPattern[route.Pattern] = route.Access
	}
	for pattern, expectedAccess := range requiredSessionOnlyRoutes {
		foundAccess, isPresent := foundAccessByPattern[pattern]
		if !isPresent || foundAccess != expectedAccess {
			testContext.Errorf("%s: expected access %d, found %d (present=%v)", pattern, expectedAccess, foundAccess, isPresent)
		}
	}
}

func TestOnlyTheClosedSetOfRoutesIsPublic(testContext *testing.T) {
	for _, route := range routeTableForTest(newRouteAccessEnvironment(testContext)) {
		if route.Access == accessPublic && !publicRoutePattern.MatchString(route.Pattern) {
			testContext.Errorf("%s must not be public", route.Pattern)
		}
		if !publicRoutePattern.MatchString(route.Pattern) {
			continue
		}
		if route.Access != accessPublic {
			testContext.Errorf("%s is expected to stay public", route.Pattern)
		}
	}
}
