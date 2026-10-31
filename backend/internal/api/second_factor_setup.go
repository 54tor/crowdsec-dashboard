package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	maxWebAuthnBodyBytes      = 64 * 1024
	secondFactorAttemptsPerIP = 30
)

type apiFailure struct {
	status             int
	code               string
	retryAfter         string
	clearsPendingLogin bool
}

func (failure apiFailure) failed() bool {
	return failure.status != 0
}

func (failure apiFailure) write(responseWriter http.ResponseWriter) {
	if failure.retryAfter != "" {
		responseWriter.Header().Set("Retry-After", failure.retryAfter)
	}
	if failure.clearsPendingLogin {
		http.SetCookie(responseWriter, pendingLoginCookie("", -1))
	}
	writeError(responseWriter, failure.status, failure.code)
}

var invalidRequestFailure = apiFailure{status: http.StatusBadRequest, code: "invalid_request"}

type setupResolver func(request *http.Request) (*secondfactor.Setup, string, apiFailure)

type secondFactorSetupHandlers struct {
	resolveSetup setupResolver
	webAuthn     *secondfactor.WebAuthn
	limiter      *auth.LoginLimiter
	trustedCIDRs []*net.IPNet
	now          func() time.Time
}

type secondFactorSetupRequest struct {
	Code       string          `json:"code"`
	Credential json.RawMessage `json:"credential"`
}

func (handlers secondFactorSetupHandlers) prepare(responseWriter http.ResponseWriter, request *http.Request, maxBodyBytes int64) (*secondfactor.Setup, string, secondFactorSetupRequest, bool) {
	if !handlers.limiter.Allow(auth.ClientIP(request, handlers.trustedCIDRs)) {
		writeTooManyAttempts(responseWriter)
		return nil, "", secondFactorSetupRequest{}, false
	}
	requestBody, readError := io.ReadAll(http.MaxBytesReader(responseWriter, request.Body, maxBodyBytes))
	var submission secondFactorSetupRequest
	if readError != nil || json.Unmarshal(requestBody, &submission) != nil {
		invalidRequestFailure.write(responseWriter)
		return nil, "", secondFactorSetupRequest{}, false
	}
	request.Body = io.NopCloser(bytes.NewReader(requestBody))
	setup, accountName, failure := handlers.resolveSetup(request)
	if failure.failed() {
		failure.write(responseWriter)
		return nil, "", secondFactorSetupRequest{}, false
	}
	return setup, accountName, submission, true
}

func (handlers secondFactorSetupHandlers) beginTOTP(responseWriter http.ResponseWriter, request *http.Request) {
	setup, accountName, _, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	enrollment, beginError := setup.BeginTOTP(accountName)
	if beginError != nil {
		log.Printf("begin totp enrollment: %v", beginError)
		writeError(responseWriter, http.StatusServiceUnavailable, "second_factor_unavailable")
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string]string{"secret": enrollment.Secret, "otpauth_url": enrollment.URL})
}

func (handlers secondFactorSetupHandlers) confirmTOTP(responseWriter http.ResponseWriter, request *http.Request) {
	setup, _, submission, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	if confirmError := setup.ConfirmTOTP(submission.Code, handlers.now()); confirmError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_code")
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

func (handlers secondFactorSetupHandlers) beginWebAuthn(responseWriter http.ResponseWriter, request *http.Request) {
	setup, accountName, _, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	if handlers.webAuthn == nil {
		writeError(responseWriter, http.StatusNotFound, "webauthn_disabled")
		return
	}
	creation, beginError := setup.BeginWebAuthn(handlers.webAuthn, accountName)
	if beginError != nil {
		log.Printf("begin webauthn enrollment: %v", beginError)
		writeError(responseWriter, http.StatusServiceUnavailable, "second_factor_unavailable")
		return
	}
	writeJSON(responseWriter, http.StatusOK, creation)
}

func (handlers secondFactorSetupHandlers) confirmWebAuthn(responseWriter http.ResponseWriter, request *http.Request) {
	setup, _, submission, isPrepared := handlers.prepare(responseWriter, request, maxWebAuthnBodyBytes)
	if !isPrepared {
		return
	}
	if handlers.webAuthn == nil {
		writeError(responseWriter, http.StatusNotFound, "webauthn_disabled")
		return
	}
	if confirmError := setup.ConfirmWebAuthn(handlers.webAuthn, submission.Credential); confirmError != nil {
		if !errors.Is(confirmError, secondfactor.ErrWebAuthnFailed) {
			log.Printf("confirm webauthn enrollment: %v", confirmError)
		}
		writeError(responseWriter, http.StatusBadRequest, "webauthn_failed")
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

func (handlers secondFactorSetupHandlers) recoveryCodes(responseWriter http.ResponseWriter, request *http.Request) {
	setup, _, _, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	recoveryCodes, codesError := setup.RecoveryCodes()
	if errors.Is(codesError, secondfactor.ErrNoConfirmedFactor) {
		writeError(responseWriter, http.StatusConflict, "second_factor_required")
		return
	}
	if codesError != nil {
		log.Printf("generate recovery codes: %v", codesError)
		writeError(responseWriter, http.StatusServiceUnavailable, "second_factor_unavailable")
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string][]string{"recovery_codes": recoveryCodes})
}
