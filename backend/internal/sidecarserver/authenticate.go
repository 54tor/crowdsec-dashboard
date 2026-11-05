package sidecarserver

import (
	"context"
	"errors"
	"io"
	"net/http"

	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

type bodyBindingContextKey struct{}

var errMissingBodyBinding = errors.New("sidecar request has no verified body binding")
var errMissingVerifier = errors.New("sidecar has no token verifier")

func authenticate(verifier *sidecarauth.Verifier, refusalLog *throttledRefusalLog, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		binding, verifyError := verifyRequestHeader(verifier, request)
		if verifyError != nil {
			refusalCode := refusalCodeOf(verifyError)
			refusalLog.record(request, refusalCode)
			writeCode(writer, http.StatusUnauthorized, refusalCode)
			return
		}
		boundContext := context.WithValue(request.Context(), bodyBindingContextKey{}, binding)
		boundContext = withRequestID(boundContext, newRequestID())
		next.ServeHTTP(writer, request.WithContext(boundContext))
	})
}

func verifyRequestHeader(verifier *sidecarauth.Verifier, request *http.Request) (sidecarauth.BodyBinding, error) {
	if verifier == nil {
		return sidecarauth.BodyBinding{}, errMissingVerifier
	}
	return verifier.Verify(request.Header.Get("Authorization"), request.Method, request.RequestURI)
}

func refusalCodeOf(verifyError error) string {
	var refusal *sidecarauth.RefusalError
	if errors.As(verifyError, &refusal) {
		return refusal.Code
	}
	return sidecarauth.CodeInvalidToken
}

func readBoundBody(writer http.ResponseWriter, request *http.Request, limit int64) ([]byte, error) {
	binding, hasBinding := request.Context().Value(bodyBindingContextKey{}).(sidecarauth.BodyBinding)
	if !hasBinding {
		return nil, errMissingBodyBinding
	}
	body, readError := io.ReadAll(http.MaxBytesReader(writer, request.Body, limit))
	if readError != nil {
		return nil, readError
	}
	if checkError := binding.Check(body); checkError != nil {
		return nil, checkError
	}
	return body, nil
}

func outcomeOfBodyError(bodyError error) execOutcome {
	var tooLarge *http.MaxBytesError
	if errors.As(bodyError, &tooLarge) {
		return execOutcome{http.StatusRequestEntityTooLarge, sidecarapi.CodeBodyTooLarge}
	}
	var refusal *sidecarauth.RefusalError
	if errors.As(bodyError, &refusal) {
		return execOutcome{http.StatusUnauthorized, refusal.Code}
	}
	return execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidRequest}
}
