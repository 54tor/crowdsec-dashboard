package audit

import (
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/search"
)

const eventSearchCondition = `(audit_event_action ILIKE ? ESCAPE '\'
	OR (audit_event_action <> ? AND audit_event_target ILIKE ? ESCAPE '\')
	OR audit_event_account_id = ANY(ARRAY(SELECT account_id FROM account WHERE account_name ILIKE ? ESCAPE '\')))`

func eventSearchPredicate(selectQuery *bun.SelectQuery, term string) *bun.SelectQuery {
	if term == "" {
		return selectQuery
	}
	containsPattern := search.ContainsPattern(term)
	return selectQuery.Where(eventSearchCondition, containsPattern, string(ActionLoginFailure), containsPattern, containsPattern)
}
