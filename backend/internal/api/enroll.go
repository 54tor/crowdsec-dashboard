package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/auth"
)

type EnrollmentService interface {
	Required(ctx context.Context) (bool, error)
	Complete(ctx context.Context, token, accountName, password string) (auth.AccountIdentity, error)
}

type enrollmentHandlers struct {
	enrollment EnrollmentService
	auth       *authHandlers
}

type enrollRequest struct {
	Token       string `json:"token"`
	AccountName string `json:"account_name"`
	Password    string `json:"password"`
}

func (handlers enrollmentHandlers) status(responseWriter http.ResponseWriter, request *http.Request) {
	isRequired, requiredError := handlers.enrollment.Required(request.Context())
	if requiredError != nil {
		log.Printf("enrollment status: %v", requiredError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string]bool{"enrollment_required": isRequired})
}

func (handlers enrollmentHandlers) enroll(responseWriter http.ResponseWriter, request *http.Request) {
	if !handlers.auth.limiter.Allow(auth.ClientIP(request, handlers.auth.trustedCIDRs)) {
		writeTooManyAttempts(responseWriter)
		return
	}
	var submission enrollRequest
	request.Body = http.MaxBytesReader(responseWriter, request.Body, maxLoginBodyBytes)
	if decodeError := json.NewDecoder(request.Body).Decode(&submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if submission.Token == "" || submission.AccountName == "" || submission.Password == "" {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	select {
	case handlers.auth.hashSlots <- struct{}{}:
		defer func() { <-handlers.auth.hashSlots }()
	default:
		writeTooManyAttempts(responseWriter)
		return
	}
	identity, completeError := handlers.enrollment.Complete(request.Context(), submission.Token, submission.AccountName, submission.Password)
	if completeError != nil {
		writeEnrollmentError(responseWriter, completeError)
		return
	}
	handlers.auth.openSession(responseWriter, request, identity)
}

func writeEnrollmentError(responseWriter http.ResponseWriter, completeError error) {
	switch {
	case errors.Is(completeError, accounts.ErrEnrollmentClosed):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	case errors.Is(completeError, accounts.ErrEnrollmentToken):
		writeError(responseWriter, http.StatusForbidden, "invalid_enrollment_token")
	case errors.Is(completeError, accounts.ErrInvalidAccountName):
		writeError(responseWriter, http.StatusBadRequest, "invalid_account_name")
	case errors.Is(completeError, accounts.ErrPasswordLength):
		writeError(responseWriter, http.StatusBadRequest, "invalid_password_length")
	default:
		log.Printf("complete enrollment: %v", completeError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
	}
}
