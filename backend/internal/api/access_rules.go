package api

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/geo"
)

const maxAccessRuleBodyBytes = 1024

type AccessRuleService interface {
	List(ctx context.Context, accountID int64) ([]accessrule.Rule, error)
	Add(ctx context.Context, accountID int64, kind, value string, clientIP netip.Addr, geolocator geo.Geolocator) (accessrule.Rule, error)
	Delete(ctx context.Context, accountID, ruleID int64, clientIP netip.Addr, geolocator geo.Geolocator) error
}

type accessRuleHandlers struct {
	service      AccessRuleService
	geolocator   geo.Geolocator
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
}

type accessRuleRequest struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type accessRuleListResponse struct {
	Rules         []accessrule.Rule `json:"rules"`
	ClientIP      string            `json:"client_ip"`
	ClientCountry *string           `json:"client_country"`
}

func (handlers accessRuleHandlers) resolveGeolocator() geo.Geolocator {
	if handlers.geolocator == nil {
		return geo.Unavailable{}
	}
	return handlers.geolocator
}

func (handlers accessRuleHandlers) clientAddress(request *http.Request) (string, netip.Addr) {
	clientIP := auth.ClientIP(request, handlers.trustedCIDRs)
	parsedAddress, _ := netip.ParseAddr(clientIP)
	return clientIP, parsedAddress.Unmap()
}

func (handlers accessRuleHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	rules, listError := handlers.service.List(request.Context(), identity.AccountID)
	if listError != nil {
		log.Printf("list access rules: %v", listError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	clientIP, clientAddress := handlers.clientAddress(request)
	response := accessRuleListResponse{Rules: rules, ClientIP: clientIP}
	if clientCountry, lookupError := handlers.resolveGeolocator().CountryCode(request.Context(), clientAddress); lookupError == nil {
		response.ClientCountry = &clientCountry
	}
	writeJSON(responseWriter, http.StatusOK, response)
}

func (handlers accessRuleHandlers) add(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	var submission accessRuleRequest
	limitedBody := http.MaxBytesReader(responseWriter, request.Body, maxAccessRuleBodyBytes)
	if decodeError := decodeSingleObject(limitedBody, &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_access_rule")
		return
	}
	_, clientAddress := handlers.clientAddress(request)
	addedRule, addError := handlers.service.Add(request.Context(), identity.AccountID, submission.Kind, submission.Value, clientAddress, handlers.resolveGeolocator())
	if addError != nil {
		writeAccessRuleError(responseWriter, "add access rule", addError)
		return
	}
	audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, audit.ActionAccessRuleAdded, addedRule.Kind+":"+addedRule.Value, audit.ClientIPText(clientAddress))
	writeJSON(responseWriter, http.StatusCreated, addedRule)
}

func (handlers accessRuleHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	ruleID, parseError := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if parseError != nil || ruleID <= 0 {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	_, clientAddress := handlers.clientAddress(request)
	removedRule := accessrule.Rule{}
	if existingRules, listError := handlers.service.List(request.Context(), identity.AccountID); listError == nil {
		for _, existingRule := range existingRules {
			if existingRule.ID == ruleID {
				removedRule = existingRule
			}
		}
	}
	if deleteError := handlers.service.Delete(request.Context(), identity.AccountID, ruleID, clientAddress, handlers.resolveGeolocator()); deleteError != nil {
		writeAccessRuleError(responseWriter, "delete access rule", deleteError)
		return
	}
	audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, audit.ActionAccessRuleRemoved, removedRule.Kind+":"+removedRule.Value, audit.ClientIPText(clientAddress))
	responseWriter.WriteHeader(http.StatusNoContent)
}

func writeAccessRuleError(responseWriter http.ResponseWriter, operation string, operationError error) {
	switch {
	case errors.Is(operationError, accessrule.ErrInvalidRule):
		writeError(responseWriter, http.StatusBadRequest, "invalid_access_rule")
	case errors.Is(operationError, accessrule.ErrPrefixTooBroad):
		writeError(responseWriter, http.StatusBadRequest, "prefix_too_broad")
	case errors.Is(operationError, accessrule.ErrRuleNotFound):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	case errors.Is(operationError, accessrule.ErrRuleExists):
		writeError(responseWriter, http.StatusConflict, "access_rule_exists")
	case errors.Is(operationError, accessrule.ErrWouldLockOut):
		writeError(responseWriter, http.StatusConflict, "would_lock_out_current_client")
	case errors.Is(operationError, accessrule.ErrGeolocationUnavailable):
		writeError(responseWriter, http.StatusConflict, "geolocation_unavailable")
	default:
		log.Printf("%s: %v", operation, operationError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
	}
}
