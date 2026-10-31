package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/secondfactor"
)

type EnrollmentService interface {
	Required(ctx context.Context) (bool, error)
	Start(ctx context.Context, token, accountName, password string) error
	Setup(token string) (*secondfactor.Setup, string, error)
	Complete(ctx context.Context, token string) (auth.AccountIdentity, error)
}

type enrollmentHandlers struct {
	enrollment EnrollmentService
	auth       *authHandlers
	recorder   audit.Recorder
	webAuthn   *secondfactor.WebAuthn
}

type enrollmentTokenRequest struct {
	Token string `json:"token"`
}

type enrollmentStepResponse struct {
	Status  string   `json:"status"`
	Methods []string `json:"methods"`
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
	if startError := handlers.enrollment.Start(request.Context(), submission.Token, submission.AccountName, submission.Password); startError != nil {
		enrollmentFailure(startError).write(responseWriter)
		return
	}
	writeJSON(responseWriter, http.StatusOK, enrollmentStepResponse{Status: "second_factor_required", Methods: handlers.methods()})
}

func (handlers enrollmentHandlers) methods() []string {
	return availableSecondFactorMethods(handlers.webAuthn)
}

func availableSecondFactorMethods(webAuthn *secondfactor.WebAuthn) []string {
	if webAuthn == nil {
		return []string{"totp"}
	}
	return []string{"totp", "webauthn"}
}

func (handlers enrollmentHandlers) resolveSetup(request *http.Request) (*secondfactor.Setup, string, apiFailure) {
	token, failure := decodeEnrollmentToken(request)
	if failure.failed() {
		return nil, "", failure
	}
	setup, accountName, setupError := handlers.enrollment.Setup(token)
	if setupError != nil {
		return nil, "", enrollmentFailure(setupError)
	}
	return setup, accountName, apiFailure{}
}

func decodeEnrollmentToken(request *http.Request) (string, apiFailure) {
	var submission enrollmentTokenRequest
	if decodeError := json.NewDecoder(request.Body).Decode(&submission); decodeError != nil || submission.Token == "" {
		return "", invalidRequestFailure
	}
	return submission.Token, apiFailure{}
}

func (handlers enrollmentHandlers) setupHandlers() secondFactorSetupHandlers {
	return secondFactorSetupHandlers{
		resolveSetup: handlers.resolveSetup,
		webAuthn:     handlers.webAuthn,
		limiter:      handlers.auth.secondFactorLimiter,
		trustedCIDRs: handlers.auth.trustedCIDRs,
		now:          time.Now,
	}
}

func (handlers enrollmentHandlers) complete(responseWriter http.ResponseWriter, request *http.Request) {
	clientIP := auth.ClientIP(request, handlers.auth.trustedCIDRs)
	if !handlers.auth.secondFactorLimiter.Allow(clientIP) {
		writeTooManyAttempts(responseWriter)
		return
	}
	request.Body = http.MaxBytesReader(responseWriter, request.Body, maxLoginBodyBytes)
	token, failure := decodeEnrollmentToken(request)
	if failure.failed() {
		failure.write(responseWriter)
		return
	}
	setup, _, setupError := handlers.enrollment.Setup(token)
	if setupError != nil {
		enrollmentFailure(setupError).write(responseWriter)
		return
	}
	enrolledMethods := setup.ConfirmedMethods()
	identity, completeError := handlers.enrollment.Complete(request.Context(), token)
	if completeError != nil {
		enrollmentFailure(completeError).write(responseWriter)
		return
	}
	for _, enrolledMethod := range enrolledMethods {
		audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, audit.ActionSecondFactorEnrolled, enrolledMethod, clientIP)
	}
	audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, audit.ActionEnrollmentCompleted, identity.AccountName, clientIP)
	handlers.auth.openSession(responseWriter, request, identity)
}

func enrollmentFailure(enrollmentError error) apiFailure {
	switch {
	case errors.Is(enrollmentError, accounts.ErrEnrollmentClosed):
		return apiFailure{status: http.StatusNotFound, code: "not_found"}
	case errors.Is(enrollmentError, accounts.ErrEnrollmentToken):
		return apiFailure{status: http.StatusForbidden, code: "invalid_enrollment_token"}
	case errors.Is(enrollmentError, accounts.ErrEnrollmentNotStarted):
		return apiFailure{status: http.StatusConflict, code: "enrollment_not_started"}
	case errors.Is(enrollmentError, accounts.ErrSecondFactorIncomplete):
		return apiFailure{status: http.StatusConflict, code: "second_factor_required"}
	case errors.Is(enrollmentError, accounts.ErrInvalidAccountName):
		return apiFailure{status: http.StatusBadRequest, code: "invalid_account_name"}
	case errors.Is(enrollmentError, accounts.ErrPasswordLength):
		return apiFailure{status: http.StatusBadRequest, code: "invalid_password_length"}
	default:
		log.Printf("enrollment: %v", enrollmentError)
		return apiFailure{status: http.StatusServiceUnavailable, code: "database_unavailable"}
	}
}
