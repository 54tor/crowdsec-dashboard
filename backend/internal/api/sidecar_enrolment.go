package api

import (
	"encoding/hex"
	"net/http"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/sidecarclient"
)

type sidecarHandlers struct {
	engineHandlers
	issuer string
}

type sidecarObserveRequest struct {
	URL string `json:"url"`
}

type sidecarConfigureRequest struct {
	URL        string `json:"url"`
	SPKISHA256 string `json:"spki_sha256"`
	Confirm    string `json:"confirm"`
}

func (handlers sidecarHandlers) observe(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	var submission sidecarObserveRequest
	if decodeError := decodeEngineBody(responseWriter, request, &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if destinationError := validateSidecarDestination(submission.URL); destinationError != nil {
		writeEngineError(responseWriter, "observe sidecar", destinationError)
		return
	}
	observedPin, observeError := handlers.service.ObserveSidecar(request.Context(), name, submission.URL)
	if observeError != nil {
		handlers.writeSidecarError(responseWriter, name, "observe sidecar", observeError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, sidecarObservationResponse{SPKISHA256: observedPin})
}

func (handlers sidecarHandlers) configure(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	var submission sidecarConfigureRequest
	if decodeError := decodeEngineBody(responseWriter, request, &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if submission.Confirm == "" || submission.Confirm != name {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if handlers.issuer == "" {
		writeError(responseWriter, http.StatusServiceUnavailable, "sidecar_issuer_missing")
		return
	}
	submittedPin, inputError := validateSidecarSubmission(submission)
	if inputError != nil {
		writeEngineError(responseWriter, "configure sidecar", inputError)
		return
	}
	observedPin, observeError := handlers.service.ObserveSidecar(request.Context(), name, submission.URL)
	if observeError != nil {
		handlers.writeSidecarError(responseWriter, name, "configure sidecar", observeError)
		return
	}
	if observedPin != submittedPin {
		writeError(responseWriter, http.StatusConflict, "sidecar_fingerprint_changed")
		return
	}
	configuredEngine, configureError := handlers.service.ConfigureSidecar(request.Context(), name,
		engines.SidecarInput{URL: submission.URL, SPKISHA256: submittedPin})
	if configureError != nil {
		handlers.writeSidecarError(responseWriter, name, "configure sidecar", configureError)
		return
	}
	handlers.record(request, audit.ActionEngineSidecarConfigured, name)
	reloadWarning := handlers.reloadRegistry(request.Context())
	writeJSON(responseWriter, http.StatusOK, sidecarEnrolmentResponse{
		Sidecar:        newSidecarView(configuredEngine.Sidecar),
		TrustedKeyLine: currentTrustedKeyLine(configuredEngine.Sidecar),
		Issuer:         handlers.issuer,
		Audience:       name,
		Warning:        reloadWarning,
	})
}

func (handlers sidecarHandlers) test(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if _, pingError := handlers.service.PingSidecar(request.Context(), name, false); pingError != nil {
		handlers.writeSidecarError(responseWriter, name, "test sidecar", pingError)
		return
	}
	handlers.record(request, audit.ActionEngineTested, name)
	writeStatus(responseWriter, "ok")
}

func (handlers sidecarHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if requireConfirm(request, name) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if removeError := handlers.service.RemoveSidecar(request.Context(), name); removeError != nil {
		handlers.writeSidecarError(responseWriter, name, "remove sidecar", removeError)
		return
	}
	handlers.record(request, audit.ActionEngineSidecarRemoved, name)
	response := map[string]string{"status": "removed"}
	if warning := handlers.reloadRegistry(request.Context()); warning != "" {
		response["warning"] = warning
	}
	writeJSON(responseWriter, http.StatusOK, response)
}

func validateSidecarSubmission(submission sidecarConfigureRequest) (string, error) {
	if destinationError := validateSidecarDestination(submission.URL); destinationError != nil {
		return "", destinationError
	}
	pinDigest, pinError := sidecarclient.ParsePin(submission.SPKISHA256)
	if pinError != nil {
		return "", engines.ErrInvalidEngine
	}
	return hex.EncodeToString(pinDigest), nil
}

func validateSidecarDestination(rawURL string) error {
	if engines.ValidateSidecarURL(rawURL) != nil {
		return engines.ErrInvalidEngine
	}
	return refuseInternalDestination(rawURL)
}
