package sidecarserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

type bodyBindingContextKey struct{}

var errMissingBodyBinding = errors.New("sidecar request has no verified body binding")
var errMissingVerifier = errors.New("sidecar has no token verifier")

func authenticate(verifier *sidecarauth.Verifier, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		binding, verifyError := verifyRequestHeader(verifier, request)
		if verifyError != nil {
			refusalCode := refusalCodeOf(verifyError)
			logRefusal(logger, request, refusalCode)
			writeCode(writer, http.StatusUnauthorized, refusalCode)
			return
		}
		boundContext := context.WithValue(request.Context(), bodyBindingContextKey{}, binding)
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

func writeBodyError(writer http.ResponseWriter, bodyError error) {
	var tooLarge *http.MaxBytesError
	if errors.As(bodyError, &tooLarge) {
		writeCode(writer, http.StatusRequestEntityTooLarge, sidecarapi.CodeBodyTooLarge)
		return
	}
	var refusal *sidecarauth.RefusalError
	if errors.As(bodyError, &refusal) {
		writeCode(writer, http.StatusUnauthorized, refusal.Code)
		return
	}
	writeCode(writer, http.StatusBadRequest, sidecarapi.CodeInvalidRequest)
}
