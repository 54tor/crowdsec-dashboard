package api

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"crowdsec-dashboard/internal/apitokens"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
)

const (
	maxTokenBodyBytes = 1024
	maximumExpiryDays = 365
	hoursPerDay       = 24
	tokenTargetPrefix = "api_token:"
)

type TokenManager interface {
	Create(ctx context.Context, identity auth.AccountIdentity, name, scope string, lifetime time.Duration) (string, apitokens.Token, error)
	List(ctx context.Context, accountID int64) ([]apitokens.Token, error)
	Revoke(ctx context.Context, accountID, tokenID int64) error
}

type tokenHandlers struct {
	manager      TokenManager
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
}

type createTokenRequest struct {
	Name          string `json:"name"`
	Scope         string `json:"scope"`
	ExpiresInDays int64  `json:"expires_in_days"`
}

type tokenView struct {
	TokenID   int64      `json:"token_id"`
	Name      string     `json:"name"`
	Scope     string     `json:"scope"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type createdTokenView struct {
	TokenID   int64     `json:"token_id"`
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token"`
}

func tokenAuditTarget(tokenID int64, name string) string {
	return tokenTargetPrefix + strconv.FormatInt(tokenID, 10) + ":" + name
}

func (handlers tokenHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	tokens, listError := handlers.manager.List(request.Context(), identity.AccountID)
	if listError != nil {
		log.Printf("list api tokens: %v", listError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	views := make([]tokenView, 0, len(tokens))
	for _, token := range tokens {
		views = append(views, tokenView(token))
	}
	writeJSON(responseWriter, http.StatusOK, views)
}

func (handlers tokenHandlers) create(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	var submission createTokenRequest
	limitedBody := http.MaxBytesReader(responseWriter, request.Body, maxTokenBodyBytes)
	if decodeError := decodeSingleObject(limitedBody, &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if submission.ExpiresInDays < 1 || submission.ExpiresInDays > maximumExpiryDays {
		writeError(responseWriter, http.StatusBadRequest, "invalid_expiry")
		return
	}
	lifetime := time.Duration(submission.ExpiresInDays) * hoursPerDay * time.Hour
	plaintext, token, createError := handlers.manager.Create(request.Context(), identity, submission.Name, submission.Scope, lifetime)
	if createError != nil {
		writeTokenError(responseWriter, submission.Scope, createError)
		return
	}
	audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, audit.ActionAPITokenCreated,
		tokenAuditTarget(token.TokenID, token.Name), auth.ClientIP(request, handlers.trustedCIDRs))
	responseWriter.Header().Set("Cache-Control", "no-store")
	writeJSON(responseWriter, http.StatusCreated, createdTokenView{
		TokenID: token.TokenID, Name: token.Name, Scope: token.Scope, ExpiresAt: token.ExpiresAt, Token: plaintext,
	})
}

func (handlers tokenHandlers) revoke(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	tokenID, parseError := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if parseError != nil || tokenID <= 0 {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	if requireConfirm(request, request.PathValue("id")) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	revokedName := handlers.tokenName(request.Context(), identity.AccountID, tokenID)
	if revokeError := handlers.manager.Revoke(request.Context(), identity.AccountID, tokenID); revokeError != nil {
		writeTokenError(responseWriter, "", revokeError)
		return
	}
	audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, audit.ActionAPITokenRevoked,
		tokenAuditTarget(tokenID, revokedName), auth.ClientIP(request, handlers.trustedCIDRs))
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

func (handlers tokenHandlers) tokenName(ctx context.Context, accountID, tokenID int64) string {
	tokens, listError := handlers.manager.List(ctx, accountID)
	if listError != nil {
		return ""
	}
	for _, token := range tokens {
		if token.TokenID == tokenID {
			return token.Name
		}
	}
	return ""
}

func writeTokenError(responseWriter http.ResponseWriter, requestedScope string, operationError error) {
	switch {
	case errors.Is(operationError, apitokens.ErrInvalidName):
		writeError(responseWriter, http.StatusBadRequest, "invalid_token_name")
	case errors.Is(operationError, apitokens.ErrInvalidLifetime):
		writeError(responseWriter, http.StatusBadRequest, "invalid_expiry")
	case errors.Is(operationError, apitokens.ErrScopeNotAllowed) && requestedScope != apitokens.ScopeRead && requestedScope != apitokens.ScopeWrite:
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
	case errors.Is(operationError, apitokens.ErrScopeNotAllowed):
		writeError(responseWriter, http.StatusForbidden, "scope_not_allowed")
	case errors.Is(operationError, apitokens.ErrNameTaken):
		writeError(responseWriter, http.StatusConflict, "token_name_taken")
	case errors.Is(operationError, apitokens.ErrTokenNotFound):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	default:
		log.Printf("api token operation: %v", operationError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
	}
}
