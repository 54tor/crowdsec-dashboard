package api

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
)

const (
	administratorAccountID int64 = 31
	targetAccountID        int64 = 32
	readOnlyCallerID       int64 = 33
	targetAccountName            = "bob"
	validPassword                = "correct horse battery"
)

type managedAccount struct {
	accountID int64
	role      string
	locked    bool
}

type fakeAccountManager struct {
	accountByName map[string]*managedAccount
	sessions      *authtest.SessionStore
	tokens        *fakeTokenManager
	unlocked      []string
}

func (manager *fakeAccountManager) find(accountName string) (*managedAccount, error) {
	account, isKnown := manager.accountByName[accountName]
	if !isKnown {
		return nil, accounts.ErrAccountNotFound
	}
	return account, nil
}

func (manager *fakeAccountManager) List(context.Context) ([]accounts.AccountSummary, error) {
	summaries := []accounts.AccountSummary{}
	for accountName, account := range manager.accountByName {
		summaries = append(summaries, accounts.AccountSummary{
			AccountID: account.accountID, AccountName: accountName, AccountRole: account.role, CreatedAt: time.Now(), Locked: account.locked,
		})
	}
	return summaries, nil
}

func (manager *fakeAccountManager) CreateAccount(_ context.Context, accountName, password, role string, _ time.Duration) (int64, error) {
	if role != auth.RoleAdmin && role != auth.RoleReadOnly {
		return 0, accounts.ErrInvalidRole
	}
	if len(password) < 12 || len(password) > 128 {
		return 0, accounts.ErrPasswordLength
	}
	if _, exists := manager.accountByName[accountName]; exists {
		return 0, accounts.ErrAccountExists
	}
	createdID := int64(100 + len(manager.accountByName))
	manager.accountByName[accountName] = &managedAccount{accountID: createdID, role: role}
	return createdID, nil
}

func (manager *fakeAccountManager) ChangeRole(_ context.Context, accountName, role string) (string, error) {
	if role != auth.RoleAdmin && role != auth.RoleReadOnly {
		return "", accounts.ErrInvalidRole
	}
	account, findError := manager.find(accountName)
	if findError != nil {
		return "", findError
	}
	if role == auth.RoleReadOnly && account.role == auth.RoleAdmin && manager.administratorCount() == 1 {
		return "", accounts.ErrLastAdmin
	}
	previousRole := account.role
	account.role = role
	return previousRole, nil
}

func (manager *fakeAccountManager) administratorCount() int {
	administrators := 0
	for _, account := range manager.accountByName {
		if account.role == auth.RoleAdmin {
			administrators++
		}
	}
	return administrators
}

func (manager *fakeAccountManager) Delete(_ context.Context, accountName string) error {
	if _, findError := manager.find(accountName); findError != nil {
		return findError
	}
	delete(manager.accountByName, accountName)
	return nil
}

func (manager *fakeAccountManager) ResetSecondFactor(_ context.Context, accountName string) error {
	_, findError := manager.find(accountName)
	return findError
}

func (manager *fakeAccountManager) RevokeSessionsAndTokens(ctx context.Context, accountName string) error {
	account, findError := manager.find(accountName)
	if findError != nil {
		return findError
	}
	manager.tokens.revokeAllOf(account.accountID)
	return manager.sessions.DestroyAllForAccount(ctx, account.accountID)
}

func (manager *fakeAccountManager) Unlock(_ context.Context, accountName string) error {
	account, findError := manager.find(accountName)
	if findError != nil {
		return findError
	}
	account.locked = false
	manager.unlocked = append(manager.unlocked, accountName)
	return nil
}

func (manager *fakeTokenManager) revokeAllOf(accountID int64) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	revocationTime := time.Now()
	for _, entry := range manager.stored {
		if entry.accountID == accountID {
			entry.token.RevokedAt = &revocationTime
		}
	}
}

type accountFixture struct {
	handler  http.Handler
	manager  *fakeAccountManager
	tokens   *fakeTokenManager
	sessions *authtest.SessionStore
	recorder *fakeAuditRecorder
	cookies  map[int64]*http.Cookie
}

func newAccountFixture(testContext *testing.T) accountFixture {
	testContext.Helper()
	roleByAccountID := map[int64]string{administratorAccountID: auth.RoleAdmin, targetAccountID: auth.RoleReadOnly, readOnlyCallerID: auth.RoleReadOnly}
	tokens := &fakeTokenManager{}
	recorder := &fakeAuditRecorder{}
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		accountRole, isKnown := roleByAccountID[accountID]
		return auth.AccountIdentity{AccountID: accountID, AccountName: "alice", AccountRole: accountRole, AuthMethod: auth.AuthMethodSession}, isKnown
	})
	manager := &fakeAccountManager{
		accountByName: map[string]*managedAccount{
			"alice":           {accountID: administratorAccountID, role: auth.RoleAdmin},
			targetAccountName: {accountID: targetAccountID, role: auth.RoleReadOnly, locked: true},
		},
		sessions: sessions,
		tokens:   tokens,
	}
	handler := newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, Services{
		Sessions: sessions, Tokens: tokens, TokenGate: allowEveryTokenGate{}, TokenManager: tokens,
		AccountManager: manager, Audit: recorder,
	})
	cookies := map[int64]*http.Cookie{}
	for accountID := range roleByAccountID {
		cookies[accountID] = newAuthenticatedCookie(testContext, sessions, accountID)
	}
	return accountFixture{handler: handler, manager: manager, tokens: tokens, sessions: sessions, recorder: recorder, cookies: cookies}
}

func (fixture accountFixture) send(method, path, body string, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
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

func (fixture accountFixture) asAdministrator(method, path, body string) *httptest.ResponseRecorder {
	return fixture.send(method, path, body, fixture.cookies[administratorAccountID], "")
}

type accountActionRoute struct {
	description string
	method      string
	path        string
	body        string
	action      audit.Action
}

var accountActionRoutes = []accountActionRoute{
	{"create", http.MethodPost, "/api/accounts", `{"account_name":"carol","password":"` + validPassword + `","account_role":"read_only"}`, audit.ActionAccountCreated},
	{"role", http.MethodPost, "/api/accounts/bob/role", `{"account_role":"admin"}`, audit.ActionAccountRoleChanged},
	{"second factor reset", http.MethodPost, "/api/accounts/bob/second-factor/reset", ``, audit.ActionAccountSecondFactorReset},
	{"sessions revoke", http.MethodPost, "/api/accounts/bob/sessions/revoke", ``, audit.ActionAccountSessionsRevoked},
	{"unlock", http.MethodPost, "/api/accounts/bob/unlock", ``, audit.ActionAccountUnlocked},
	{"delete", http.MethodDelete, "/api/accounts/bob", `{"confirm":"bob"}`, audit.ActionAccountDeleted},
}

func TestAccountRoutesRejectReadOnlySession(testContext *testing.T) {
	fixture := newAccountFixture(testContext)
	for _, route := range append(accountActionRoutes, accountActionRoute{"list", http.MethodGet, "/api/accounts", ``, ""}) {
		recorder := fixture.send(route.method, route.path, route.body, fixture.cookies[readOnlyCallerID], "")
		expectError(testContext, recorder, http.StatusForbidden, "forbidden")
	}
}

func TestAccountRoutesRejectAdminToken(testContext *testing.T) {
	fixture := newAccountFixture(testContext)
	plaintext, _, createError := fixture.tokens.Create(context.Background(), auth.AccountIdentity{AccountID: administratorAccountID, AccountRole: auth.RoleAdmin}, "ci", "write", 48*time.Hour)
	if createError != nil {
		testContext.Fatal(createError)
	}

	recorder := fixture.send(http.MethodGet, "/api/accounts", "", nil, plaintext)

	expectError(testContext, recorder, http.StatusForbidden, "session_required")
}

func TestListAccountsReturnsDocumentedFields(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodGet, "/api/accounts", "")

	body := recorder.Body.String()
	for _, field := range []string{`"account_name"`, `"account_role"`, `"created_at"`, `"second_factor_enrolled"`, `"locked"`} {
		if recorder.Code != http.StatusOK || !strings.Contains(body, field) {
			testContext.Fatalf("missing %s in %d %q", field, recorder.Code, body)
		}
	}
}

func TestDemotingLastAdminReturns409LastAdmin(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts/alice/role", `{"account_role":"read_only"}`)

	expectError(testContext, recorder, http.StatusConflict, "last_admin")
}

func TestChangeRoleWithUnknownRoleReturns400(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts/bob/role", `{"account_role":"root"}`)

	expectError(testContext, recorder, http.StatusBadRequest, "invalid_role")
}

func TestUnknownAccountReturns404(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts/nobody/unlock", "")

	expectError(testContext, recorder, http.StatusNotFound, "not_found")
}

func TestCreateDuplicateAccountReturns409AccountExists(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts", `{"account_name":"bob","password":"`+validPassword+`","account_role":"read_only"}`)

	expectError(testContext, recorder, http.StatusConflict, "account_exists")
}

func TestCreateAccountWithInvalidPasswordReturns400InvalidPasswordLength(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts", `{"account_name":"carol","password":"short","account_role":"read_only"}`)

	expectError(testContext, recorder, http.StatusBadRequest, "invalid_password_length")
}

func TestCreateAccountReturns201WithName(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts", `{"account_name":"carol","password":"`+validPassword+`","account_role":"read_only"}`)

	if recorder.Code != http.StatusCreated || strings.TrimSpace(recorder.Body.String()) != `{"account_name":"carol"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestRevokeSessionsLogsTargetOut(testContext *testing.T) {
	fixture := newAccountFixture(testContext)
	_, token, createError := fixture.tokens.Create(context.Background(), auth.AccountIdentity{AccountID: targetAccountID, AccountRole: auth.RoleReadOnly}, "ci", "read", 48*time.Hour)
	if createError != nil {
		testContext.Fatal(createError)
	}

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts/bob/sessions/revoke", "")

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	meRecorder := fixture.send(http.MethodGet, "/api/auth/me", "", fixture.cookies[targetAccountID], "")
	if meRecorder.Code != http.StatusUnauthorized {
		testContext.Errorf("target session must be invalid, got %d", meRecorder.Code)
	}
	storedTokens, _ := fixture.tokens.List(context.Background(), targetAccountID)
	if len(storedTokens) != 1 || storedTokens[0].TokenID != token.TokenID || storedTokens[0].RevokedAt == nil {
		testContext.Errorf("target token must be revoked, got %+v", storedTokens)
	}
}

func TestLogoutAllAlsoRevokesTokens(testContext *testing.T) {
	fixture := newAccountFixture(testContext)
	fixture.tokens.Create(context.Background(), auth.AccountIdentity{AccountID: administratorAccountID, AccountRole: auth.RoleAdmin}, "ci", "read", 48*time.Hour)
	fixture.manager.accountByName["alice"].accountID = administratorAccountID

	recorder := fixture.asAdministrator(http.MethodPost, "/api/auth/logout-all", "")

	storedTokens, _ := fixture.tokens.List(context.Background(), administratorAccountID)
	if recorder.Code != http.StatusOK || len(storedTokens) != 1 || storedTokens[0].RevokedAt == nil {
		testContext.Errorf("logout-all must revoke tokens: %d %+v", recorder.Code, storedTokens)
	}
}

func TestUnlockClearsLockout(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts/bob/unlock", "")

	if recorder.Code != http.StatusOK || len(fixture.manager.unlocked) != 1 || fixture.manager.accountByName["bob"].locked {
		testContext.Errorf("unlock failed: %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestDeleteRequiresConfirm(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	for _, body := range []string{``, `{"confirm":"alice"}`} {
		recorder := fixture.asAdministrator(http.MethodDelete, "/api/accounts/bob", body)
		expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	}
	if _, stillThere := fixture.manager.accountByName["bob"]; !stillThere {
		testContext.Error("account must not be deleted without confirmation")
	}
}

func TestEveryAccountActionIsAudited(testContext *testing.T) {
	for _, route := range accountActionRoutes {
		fixture := newAccountFixture(testContext)

		recorder := fixture.asAdministrator(route.method, route.path, route.body)

		if recorder.Code >= 300 || len(fixture.recorder.events) != 1 || fixture.recorder.events[0].action != route.action {
			testContext.Errorf("%s: code %d events %+v", route.description, recorder.Code, fixture.recorder.events)
		}
	}
}

func TestRoleChangeAuditTargetNamesBothRoles(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	fixture.asAdministrator(http.MethodPost, "/api/accounts/bob/role", `{"account_role":"admin"}`)

	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].target != "account:bob:read_only->admin" {
		testContext.Errorf("unexpected audit %+v", fixture.recorder.events)
	}
}

func TestAuditNeverContainsPassword(testContext *testing.T) {
	fixture := newAccountFixture(testContext)

	var capturedLogs strings.Builder
	log.SetOutput(&capturedLogs)
	defer log.SetOutput(os.Stderr)

	recorder := fixture.asAdministrator(http.MethodPost, "/api/accounts", `{"account_name":"carol","password":"`+validPassword+`","account_role":"read_only"}`)

	if recorder.Code != http.StatusCreated || len(fixture.recorder.events) != 1 {
		testContext.Fatalf("expected 201 and one audit event, got %d and %+v", recorder.Code, fixture.recorder.events)
	}
	if strings.Contains(capturedLogs.String(), validPassword) {
		testContext.Errorf("password leaked into logs %q", capturedLogs.String())
	}
	for _, event := range fixture.recorder.events {
		if strings.Contains(event.target, validPassword) {
			testContext.Errorf("password leaked into audit target %q", event.target)
		}
	}
}
