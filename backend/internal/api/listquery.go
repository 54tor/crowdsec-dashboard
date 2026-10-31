package api

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"crowdsec-dashboard/internal/cscli"
)

const (
	defaultPerPage = 50
	maxPerPage     = 100
)

var scenarioPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$`)

type listQuery struct {
	Page     int
	PerPage  int
	Scenario string
	IP       string
	Since    string
}

type page[T any] struct {
	Items     []T  `json:"items"`
	Page      int  `json:"page"`
	PerPage   int  `json:"per_page"`
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

func parsePositive(values url.Values, key string, fallback int) (int, bool) {
	rawValue := values.Get(key)
	if rawValue == "" {
		return fallback, true
	}
	parsed, parseError := strconv.Atoi(rawValue)
	return parsed, parseError == nil && parsed >= 1
}

func parseListQuery(request *http.Request) (listQuery, bool) {
	values := request.URL.Query()
	pageNumber, pageValid := parsePositive(values, "page", 1)
	perPage, perPageValid := parsePositive(values, "per_page", defaultPerPage)
	query := listQuery{
		Page:     pageNumber,
		PerPage:  min(perPage, maxPerPage),
		Scenario: values.Get("scenario"),
		IP:       values.Get("ip"),
		Since:    values.Get("since"),
	}
	valid := pageValid && perPageValid
	valid = valid && (query.Scenario == "" || scenarioPattern.MatchString(query.Scenario))
	valid = valid && (query.IP == "" || cscli.ValidateTarget(query.IP) == nil)
	valid = valid && (query.Since == "" || cscli.ValidateDuration(query.Since) == nil)
	return query, valid
}

func slicePage[T any](window []T, query listQuery) []T {
	start := (query.Page - 1) * query.PerPage
	if start >= len(window) {
		return []T{}
	}
	return window[start:min(start+query.PerPage, len(window))]
}
