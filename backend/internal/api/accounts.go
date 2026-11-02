package api

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
)

const (
	maxAccountBodyBytes = 2048
	accountTargetPrefix = "account:"
)

type AccountManager interface {
	List(ctx context.Context) ([]accounts.AccountSummary, error)
	CreateAccount(ctx context.Context, accountName, password, role string, setupWindow time.Duration) (int64, error)
	ChangeRole(ctx context.Context, accountName, role string) error
	Delete(ctx context.Context, accountName string) error
	ResetSecondFactor(ctx context.Context, accountName string) error
	RevokeSessionsAndTokens(ctx context.Context, accountName string) error
	Unlock(ctx context.Context, accountName string) error
}

type accountHandlers struct {
	manager      AccountManager
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
}

type createAccountRequest struct {
	AccountName string `json:"account_name"`
	Password    string `json:"password"`
	AccountRole string `json:"account_role"`
}

type changeRoleRequest struct {
	AccountRole string `json:"account_role"`
}

type accountView struct {
	AccountName          string    `json:"account_name"`
	AccountRole          string    `json:"account_role"`
	CreatedAt            time.Time `json:"created_at"`
	SecondFactorEnrolled bool      `json:"second_factor_enrolled"`
	Locked               bool      `json:"locked"`
}

func (handlers accountHandlers) record(request *http.Request, action audit.Action, target string) {
	identity, _ := auth.IdentityFromContext(request.Context())
	audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, action,
		accountTargetPrefix+target, auth.ClientIP(request, handlers.trustedCIDRs))
}

func (handlers accountHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	summaries, listError := handlers.manager.List(request.Context())
	if listError != nil {
		writeAccountError(responseWriter, listError)
		return
	}
	views := make([]accountView, 0, len(summaries))
	for _, summary := range summaries {
		views = append(views, accountView{
			AccountName: summary.AccountName, AccountRole: summary.AccountRole, CreatedAt: summary.CreatedAt,
			SecondFactorEnrolled: summary.SecondFactorEnrolled, Locked: summary.Locked,
		})
	}
	writeJSON(responseWriter, http.StatusOK, views)
}

func (handlers accountHandlers) create(responseWriter http.ResponseWriter, request *http.Request) {
	var submission createAccountRequest
	if decodeError := decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maxAccountBodyBytes), &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	_, createError := handlers.manager.CreateAccount(request.Context(), submission.AccountName, submission.Password, submission.AccountRole, accounts.SecondFactorSetupWindow)
	if createError != nil {
		writeAccountError(responseWriter, createError)
		return
	}
	handlers.record(request, audit.ActionAccountCreated, submission.AccountName+":"+submission.AccountRole)
	writeJSON(responseWriter, http.StatusCreated, map[string]string{"account_name": submission.AccountName})
}

func (handlers accountHandlers) changeRole(responseWriter http.ResponseWriter, request *http.Request) {
	accountName := request.PathValue("name")
	var submission changeRoleRequest
	if decodeError := decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maxAccountBodyBytes), &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	previousRole := handlers.currentRole(request.Context(), accountName)
	if changeError := handlers.manager.ChangeRole(request.Context(), accountName, submission.AccountRole); changeError != nil {
		writeAccountError(responseWriter, changeError)
		return
	}
	handlers.record(request, audit.ActionAccountRoleChanged, accountName+":"+previousRole+"->"+submission.AccountRole)
	writeStatus(responseWriter, "ok")
}

func (handlers accountHandlers) currentRole(ctx context.Context, accountName string) string {
	summaries, listError := handlers.manager.List(ctx)
	if listError != nil {
		return ""
	}
	for _, summary := range summaries {
		if summary.AccountName == accountName {
			return summary.AccountRole
		}
	}
	return ""
}

func (handlers accountHandlers) simpleAction(action audit.Action, operate func(AccountManager, context.Context, string) error) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		accountName := request.PathValue("name")
		if operateError := operate(handlers.manager, request.Context(), accountName); operateError != nil {
			writeAccountError(responseWriter, operateError)
			return
		}
		handlers.record(request, action, accountName)
		writeStatus(responseWriter, "ok")
	}
}

func (handlers accountHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	accountName := request.PathValue("name")
	if requireConfirm(request, accountName) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if deleteError := handlers.manager.Delete(request.Context(), accountName); deleteError != nil {
		writeAccountError(responseWriter, deleteError)
		return
	}
	handlers.record(request, audit.ActionAccountDeleted, accountName)
	writeStatus(responseWriter, "ok")
}

func writeAccountError(responseWriter http.ResponseWriter, operationError error) {
	switch {
	case errors.Is(operationError, accounts.ErrLastAdmin):
		writeError(responseWriter, http.StatusConflict, "last_admin")
	case errors.Is(operationError, accounts.ErrAccountExists):
		writeError(responseWriter, http.StatusConflict, "account_exists")
	case errors.Is(operationError, accounts.ErrInvalidRole):
		writeError(responseWriter, http.StatusBadRequest, "invalid_role")
	case errors.Is(operationError, accounts.ErrInvalidAccountName):
		writeError(responseWriter, http.StatusBadRequest, "invalid_account_name")
	case errors.Is(operationError, accounts.ErrPasswordLength):
		writeError(responseWriter, http.StatusBadRequest, "invalid_password_length")
	case errors.Is(operationError, accounts.ErrAccountNotFound):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	default:
		log.Printf("account operation: %v", operationError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
	}
}
