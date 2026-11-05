package api

import (
	"math"
	"net/http"
	"regexp"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/search"
	"crowdsec-dashboard/internal/store"
)

var auditActionPattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

type auditQuery struct {
	Page, PerPage                  int
	Action, Account, Since, Search string
}

func parseAuditQuery(request *http.Request) (auditQuery, bool) {
	values := request.URL.Query()
	pageNumber, pageValid := parseBounded(values, "page", 1, maxPage)
	perPage, perPageValid := parseBounded(values, "per_page", defaultPerPage, math.MaxInt)
	searchTerm, searchTermValid := search.ParseTerm(values.Get("q"))
	query := auditQuery{
		Page:    pageNumber,
		PerPage: min(perPage, maxPerPage),
		Action:  values.Get("action"),
		Account: values.Get("account"),
		Since:   values.Get("since"),
		Search:  searchTerm,
	}
	valid := pageValid && perPageValid && searchTermValid
	valid = valid && (query.Page-1)*query.PerPage <= store.MaximumCountedRows
	valid = valid && (query.Action == "" || auditActionPattern.MatchString(query.Action))
	valid = valid && (query.Account == "" || accounts.ValidateAccountName(query.Account) == nil)
	valid = valid && (query.Since == "" || cscli.ValidateDuration(query.Since) == nil)
	return query, valid
}
