package api

import (
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"crowdsec-dashboard/internal/cscli"
)

const (
	defaultPerPage = 50
	maxPerPage     = 100
	maxPage        = 10000
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
	Items          []T  `json:"items"`
	Page           int  `json:"page"`
	PerPage        int  `json:"per_page"`
	WindowSize     int  `json:"window_size"`
	MayBeTruncated bool `json:"may_be_truncated"`
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
	if query.Page-1 > len(window)/query.PerPage {
		return []T{}
	}
	start := (query.Page - 1) * query.PerPage
	if start >= len(window) {
		return []T{}
	}
	return window[start : min(len(window)-start, query.PerPage)+start]
}
