package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/netparse"
)

const (
	maxBanBodyBytes = 4096
	maxReasonLength = 200
)

type decisionHandlers struct {
	service      DecisionService
	lister       DecisionLister
	trustedCIDRs []*net.IPNet
}

type banRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"`
	Reason   string `json:"reason"`
}

func banScope(target string) (string, bool) {
	if _, addressError := netip.ParseAddr(target); addressError == nil {
		return "ip", true
	}
	prefix, prefixError := netip.ParsePrefix(target)
	if prefixError != nil {
		return "", false
	}
	return "range", netparse.MeetsBanPrefixFloor(prefix)
}

func targetContainsClient(target string, clientAddress string) bool {
	client, clientError := netip.ParseAddr(clientAddress)
	if clientError != nil {
		return false
	}
	client = client.Unmap()
	if address, addressError := netip.ParseAddr(target); addressError == nil {
		return address.Unmap() == client
	}
	prefix, prefixError := netip.ParsePrefix(target)
	if prefixError != nil {
		return false
	}
	return prefix.Contains(client)
}

func validReason(reason string) bool {
	if utf8.RuneCountInString(reason) > maxReasonLength {
		return false
	}
	for _, character := range reason {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (handlers decisionHandlers) add(responseWriter http.ResponseWriter, request *http.Request) {
	var ban banRequest
	limitedBody := http.MaxBytesReader(responseWriter, request.Body, maxBanBodyBytes)
	if decodeError := json.NewDecoder(limitedBody).Decode(&ban); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	scope, targetAllowed := banScope(ban.IP)
	if cscli.ValidateTarget(ban.IP) != nil || !targetAllowed {
		writeError(responseWriter, http.StatusBadRequest, "invalid_target")
		return
	}
	if cscli.ValidateDuration(ban.Duration) != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_duration")
		return
	}
	if !validReason(ban.Reason) {
		writeError(responseWriter, http.StatusBadRequest, "invalid_reason")
		return
	}
	if targetContainsClient(ban.IP, auth.ClientIP(request, handlers.trustedCIDRs)) {
		writeError(responseWriter, http.StatusConflict, "self_ban")
		return
	}
	newDecision := lapi.NewDecision{Target: ban.IP, Scope: scope, Type: "ban", Duration: ban.Duration, Reason: ban.Reason}
	if addError := handlers.service.Add(request.Context(), newDecision); addError != nil {
		writeUpstreamError(responseWriter, addError)
		return
	}
	writeJSON(responseWriter, http.StatusCreated, map[string]string{"status": "created"})
}

func (handlers decisionHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	rawID := request.PathValue("id")
	if requireConfirm(request, rawID) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	decisionID, parseError := strconv.ParseInt(rawID, 10, 64)
	expectedScope := request.URL.Query().Get("scope")
	expectedValue := request.URL.Query().Get("value")
	if parseError != nil || decisionID <= 0 || expectedScope == "" || expectedValue == "" {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if handlers.lister == nil {
		writeError(responseWriter, http.StatusBadGateway, "lapi_unavailable")
		return
	}
	liveDecision, found, lookupError := findLiveDecision(request.Context(), handlers.lister, decisionID, expectedScope, expectedValue)
	if lookupError != nil {
		writeUpstreamError(responseWriter, lookupError)
		return
	}
	if !found {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	isSameTarget := strings.EqualFold(liveDecision.Scope, expectedScope) && liveDecision.Value == expectedValue
	if !isSameTarget {
		writeError(responseWriter, http.StatusConflict, "target_mismatch")
		return
	}
	if deleteError := handlers.service.Delete(request.Context(), decisionID); deleteError != nil {
		writeUpstreamError(responseWriter, deleteError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "deleted"})
}
