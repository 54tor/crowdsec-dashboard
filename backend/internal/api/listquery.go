package api

import (
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/engines"
)

const (
	defaultPerPage = 50
	maxPerPage     = 100
	maxPage        = 10000
)

const (
	liveStatusOK          = "ok"
	liveStatusUnavailable = "unavailable"
	ipv4MappedPrefixBits  = 96
)

var (
	scenarioPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$`)
	engineNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

type listQuery struct {
	Page           int
	PerPage        int
	Scenario       string
	IP             string
	Since          string
	Engine         string
	IncludeExpired bool
}

type page[T any] struct {
	Items          []T    `json:"items"`
	Page           int    `json:"page"`
	PerPage        int    `json:"per_page"`
	WindowSize     int    `json:"window_size"`
	MayBeTruncated bool   `json:"may_be_truncated"`
	Total          int    `json:"total"`
	TotalCapped    bool   `json:"total_capped"`
	LiveStatus     string `json:"live_status"`
}

func parseBounded(values url.Values, key string, fallback, upperBound int) (int, bool) {
	rawValue := values.Get(key)
	if rawValue == "" {
		return fallback, true
	}
	parsed, parseError := strconv.Atoi(rawValue)
	return parsed, parseError == nil && parsed >= 1 && parsed <= upperBound
}

func parseListQuery(request *http.Request) (listQuery, bool) {
	values := request.URL.Query()
	pageNumber, pageValid := parseBounded(values, "page", 1, maxPage)
	perPage, perPageValid := parseBounded(values, "per_page", defaultPerPage, math.MaxInt)
	normalisedIP, ipValid := normaliseIPFilter(values.Get("ip"))
	includeExpired, includeExpiredValid := parseOptionalBool(values.Get("include_expired"))
	query := listQuery{
		Page:           pageNumber,
		PerPage:        min(perPage, maxPerPage),
		Scenario:       values.Get("scenario"),
		IP:             normalisedIP,
		Since:          values.Get("since"),
		Engine:         values.Get("engine"),
		IncludeExpired: includeExpired,
	}
	valid := pageValid && perPageValid && ipValid && includeExpiredValid
	valid = valid && (query.Scenario == "" || scenarioPattern.MatchString(query.Scenario))
	valid = valid && (query.IP == "" || cscli.ValidateTarget(query.IP) == nil)
	valid = valid && (query.Since == "" || cscli.ValidateDuration(query.Since) == nil)
	valid = valid && (query.Engine == "" || engineNamePattern.MatchString(query.Engine))
	return query, valid
}

func normaliseIPFilter(rawIP string) (string, bool) {
	if rawIP == "" {
		return "", true
	}
	if address, addressError := netip.ParseAddr(rawIP); addressError == nil {
		if address.Zone() != "" {
			return "", false
		}
		return address.Unmap().String(), true
	}
	prefix, prefixError := netip.ParsePrefix(rawIP)
	if prefixError != nil {
		return rawIP, true
	}
	isMappedIPv4Prefix := prefix.Addr().Is4In6() && prefix.Bits() >= ipv4MappedPrefixBits
	if isMappedIPv4Prefix {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-ipv4MappedPrefixBits)
	}
	return prefix.Masked().String(), true
}

func parseOptionalBool(rawValue string) (bool, bool) {
	switch rawValue {
	case "":
		return false, true
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

func includesLocalEngine(query listQuery) bool {
	return query.Engine == "" || query.Engine == engines.ReservedLocalName
}

func slicePage[T any](window []T, query listQuery) []T {
	if query.Page-1 > len(window)/query.PerPage {
		return []T{}
	}
	start := (query.Page - 1) * query.PerPage
	if start >= len(window) {
		return []T{}
	}
	return window[start : min(len(window)-start, query.PerPage)+start]
}
