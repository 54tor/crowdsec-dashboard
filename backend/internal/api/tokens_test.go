package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/apitokens"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
)

const (
	tokenOwnerAccountID int64 = 21
	otherAccountID      int64 = 22
)

type storedToken struct {
	token     apitokens.Token
	plaintext string
	accountID int64
	role      string
}

type fakeTokenManager struct {
	mutex    sync.Mutex
	stored   []*storedToken
	sequence int64
}

func (manager *fakeTokenManager) Create(_ context.Context, identity auth.AccountIdentity, name, scope string, lifetime time.Duration) (string, apitokens.Token, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if scope != apitokens.ScopeRead && scope != apitokens.ScopeWrite {
		return "", apitokens.Token{}, apitokens.ErrScopeNotAllowed
	}
	if scope == apitokens.ScopeWrite && identity.AccountRole == auth.RoleReadOnly {
		return "", apitokens.Token{}, apitokens.ErrScopeNotAllowed
	}
	if lifetime < 24*time.Hour || lifetime > 365*24*time.Hour {
		return "", apitokens.Token{}, apitokens.ErrInvalidLifetime
	}
	if name == "" {
		return "", apitokens.Token{}, apitokens.ErrInvalidName
	}
	manager.sequence++
	plaintext := "csd_plaintext-" + strconv.FormatInt(manager.sequence, 10)
	token := apitokens.Token{TokenID: manager.sequence, Name: name, Scope: scope, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(lifetime)}
	manager.stored = append(manager.stored, &storedToken{token: token, plaintext: plaintext, accountID: identity.AccountID, role: identity.AccountRole})
	return plaintext, token, nil
}

func (manager *fakeTokenManager) List(_ context.Context, accountID int64) ([]apitokens.Token, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	var tokens []apitokens.Token
	for _, entry := range manager.stored {
		if entry.accountID == accountID {
			tokens = append(tokens, entry.token)
		}
	}
	return tokens, nil
}

func (manager *fakeTokenManager) Revoke(_ context.Context, accountID, tokenID int64) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	for _, entry := range manager.stored {
		if entry.token.TokenID == tokenID && entry.accountID == accountID && entry.token.RevokedAt == nil {
			revocationTime := time.Now()
			entry.token.RevokedAt = &revocationTime
			return nil
		}
	}
	return apitokens.ErrTokenNotFound
}

func (manager *fakeTokenManager) Lookup(_ context.Context, plaintext string) (auth.AccountIdentity, bool, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	for _, entry := range manager.stored {
		if entry.plaintext == plaintext && entry.token.RevokedAt == nil {
			return auth.AccountIdentity{AccountID: entry.accountID, AccountName: "alice", AccountRole: entry.role, AuthMethod: auth.AuthMethodToken}, true, nil
		}
	}
	return auth.AccountIdentity{}, false, nil
}

type tokenFixture struct {
	handler  http.Handler
	manager  *fakeTokenManager
	recorder *fakeAuditRecorder
	cookies  map[int64]*http.Cookie
}

func newTokenFixture(testContext *testing.T, roleByAccountID map[int64]string) tokenFixture {
	testContext.Helper()
	manager := &fakeTokenManager{}
	recorder := &fakeAuditRecorder{}
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		accountRole, isKnown := roleByAccountID[accountID]
		return auth.AccountIdentity{AccountID: accountID, AccountName: "alice", AccountRole: accountRole, AuthMethod: auth.AuthMethodSession}, isKnown
	})
	handler := newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, Services{
		Sessions:     sessions,
		Tokens:       manager,
		TokenGate:    allowEveryTokenGate{},
		TokenManager: manager,
		Audit:        recorder,
	})
	cookies := map[int64]*http.Cookie{}
	for accountID := range roleByAccountID {
		cookies[accountID] = newAuthenticatedCookie(testContext, sessions, accountID)
	}
	return tokenFixture{handler: handler, manager: manager, recorder: recorder, cookies: cookies}
}

func (fixture tokenFixture) send(method, path, body string, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
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

func adminTokenFixture(testContext *testing.T) tokenFixture {
	return newTokenFixture(testContext, map[int64]string{tokenOwnerAccountID: auth.RoleAdmin, otherAccountID: auth.RoleAdmin})
}

const createReadTokenBody = `{"name":"ci","scope":"read","expires_in_days":30}`

func decodeCreatedToken(testContext *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	testContext.Helper()
	var created map[string]any
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &created); decodeError != nil {
		testContext.Fatalf("decode %q: %v", recorder.Body.String(), decodeError)
	}
	return created
}

func TestCreateTokenReturnsPlaintextOnceWithNoStore(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)

	recorder := fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], "")

	if recorder.Code != http.StatusCreated || recorder.Header().Get("Cache-Control") != "no-store" {
		testContext.Fatalf("expected 201 no-store, got %d %q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}
	created := decodeCreatedToken(testContext, recorder)
	plaintext, _ := created["token"].(string)
	if !strings.HasPrefix(plaintext, "csd_") || created["name"] != "ci" || created["scope"] != "read" || created["token_id"] == nil || created["expires_at"] == nil {
		testContext.Errorf("unexpected creation response %v", created)
	}
}

func TestListTokensNeverContainsPlaintextOrHash(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)
	created := decodeCreatedToken(testContext, fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], ""))
	plaintext, _ := created["token"].(string)

	recorder := fixture.send(http.MethodGet, "/api/tokens", "", fixture.cookies[tokenOwnerAccountID], "")

	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || strings.Contains(body, plaintext) || strings.Contains(strings.ToLower(body), "hash") || !strings.Contains(body, `"token_id"`) {
		testContext.Errorf("unexpected list %d %q", recorder.Code, body)
	}
}

func TestListTokensReturnsEmptyArrayWhenNoToken(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)

	recorder := fixture.send(http.MethodGet, "/api/tokens", "", fixture.cookies[tokenOwnerAccountID], "")

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "[]" {
		testContext.Errorf("expected an empty array, got %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestCreateWriteTokenAsReadOnlyReturns403ScopeNotAllowed(testContext *testing.T) {
	fixture := newTokenFixture(testContext, map[int64]string{tokenOwnerAccountID: auth.RoleReadOnly})

	recorder := fixture.send(http.MethodPost, "/api/tokens", `{"name":"ci","scope":"write","expires_in_days":30}`, fixture.cookies[tokenOwnerAccountID], "")

	expectError(testContext, recorder, http.StatusForbidden, "scope_not_allowed")
}

func TestReadOnlyAccountCanCreateReadToken(testContext *testing.T) {
	fixture := newTokenFixture(testContext, map[int64]string{tokenOwnerAccountID: auth.RoleReadOnly})

	recorder := fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], "")

	if recorder.Code != http.StatusCreated {
		testContext.Errorf("expected 201, got %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestCreateTokenWithBearerReturns403SessionRequired(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)
	created := decodeCreatedToken(testContext, fixture.send(http.MethodPost, "/api/tokens", `{"name":"ci","scope":"write","expires_in_days":30}`, fixture.cookies[tokenOwnerAccountID], ""))
	plaintext, _ := created["token"].(string)

	recorder := fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, nil, plaintext)

	expectError(testContext, recorder, http.StatusForbidden, "session_required")
}

func TestCreateTokenRejectsUnknownFieldsAndBadExpiry(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)
	cookie := fixture.cookies[tokenOwnerAccountID]
	rejectedCases := []struct {
		description  string
		body         string
		expectedCode string
	}{
		{"unknown field", `{"name":"ci","scope":"read","expires_in_days":30,"extra":1}`, "invalid_request"},
		{"trailing data", createReadTokenBody + `{}`, "invalid_request"},
		{"unknown scope", `{"name":"ci","scope":"admin","expires_in_days":30}`, "invalid_request"},
		{"zero days", `{"name":"ci","scope":"read","expires_in_days":0}`, "invalid_expiry"},
		{"negative days", `{"name":"ci","scope":"read","expires_in_days":-3}`, "invalid_expiry"},
		{"too many days", `{"name":"ci","scope":"read","expires_in_days":366}`, "invalid_expiry"},
		{"huge days", `{"name":"ci","scope":"read","expires_in_days":9223372036854775807}`, "invalid_expiry"},
		{"empty name", `{"name":"","scope":"read","expires_in_days":30}`, "invalid_token_name"},
	}
	for _, rejectedCase := range rejectedCases {
		recorder := fixture.send(http.MethodPost, "/api/tokens", rejectedCase.body, cookie, "")
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), rejectedCase.expectedCode) {
			testContext.Errorf("%s: expected 400 %s, got %d %q", rejectedCase.description, rejectedCase.expectedCode, recorder.Code, recorder.Body.String())
		}
	}
}

func TestRevokeOtherAccountsTokenReturns404(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)
	created := decodeCreatedToken(testContext, fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], ""))
	tokenID := strconv.Itoa(int(created["token_id"].(float64)))

	recorder := fixture.send(http.MethodDelete, "/api/tokens/"+tokenID, `{"confirm":"`+tokenID+`"}`, fixture.cookies[otherAccountID], "")

	expectError(testContext, recorder, http.StatusNotFound, "not_found")
}

func TestRevokeWithoutConfirmReturns400(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)
	created := decodeCreatedToken(testContext, fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], ""))
	tokenID := strconv.Itoa(int(created["token_id"].(float64)))

	recorder := fixture.send(http.MethodDelete, "/api/tokens/"+tokenID, `{"confirm":"nope"}`, fixture.cookies[tokenOwnerAccountID], "")

	expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
}

func TestTokenCreationIsAuditedWithoutPlaintext(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)

	recorder := fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], "")

	created := decodeCreatedToken(testContext, recorder)
	plaintext, _ := created["token"].(string)
	if len(fixture.recorder.events) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", fixture.recorder.events)
	}
	auditedEvent := fixture.recorder.events[0]
	if auditedEvent.action != audit.ActionAPITokenCreated || strings.Contains(auditedEvent.target, "csd_") || strings.Contains(auditedEvent.target, plaintext) ||
		auditedEvent.target != "api_token:1:ci" || auditedEvent.clientIP != "198.51.100.7" {
		testContext.Errorf("unexpected audit event %+v", auditedEvent)
	}
}

func TestTokenRevocationIsAudited(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)
	fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], "")

	recorder := fixture.send(http.MethodDelete, "/api/tokens/1", `{"confirm":"1"}`, fixture.cookies[tokenOwnerAccountID], "")

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"ok"}` {
		testContext.Fatalf("expected 200 ok, got %d %q", recorder.Code, recorder.Body.String())
	}
	lastEvent := fixture.recorder.events[len(fixture.recorder.events)-1]
	if lastEvent.action != audit.ActionAPITokenRevoked || lastEvent.target != "api_token:1:ci" {
		testContext.Errorf("unexpected audit event %+v", lastEvent)
	}
}

func TestRevokedTokenNoLongerAuthenticates(testContext *testing.T) {
	fixture := adminTokenFixture(testContext)
	created := decodeCreatedToken(testContext, fixture.send(http.MethodPost, "/api/tokens", createReadTokenBody, fixture.cookies[tokenOwnerAccountID], ""))
	plaintext, _ := created["token"].(string)
	tokenID := strconv.Itoa(int(created["token_id"].(float64)))
	beforeRevocation := fixture.send(http.MethodGet, "/api/auth/me", "", nil, plaintext)

	fixture.send(http.MethodDelete, "/api/tokens/"+tokenID, `{"confirm":"`+tokenID+`"}`, fixture.cookies[tokenOwnerAccountID], "")
	afterRevocation := fixture.send(http.MethodGet, "/api/auth/me", "", nil, plaintext)

	if beforeRevocation.Code != http.StatusOK || afterRevocation.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 200 then 401, got %d then %d", beforeRevocation.Code, afterRevocation.Code)
	}
}
