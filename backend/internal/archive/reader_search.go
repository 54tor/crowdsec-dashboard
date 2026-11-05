package archive

import (
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/search"
)

const alertSearchCondition = `(alert_source_value ILIKE ? ESCAPE '\'
	OR alert_scenario_name ILIKE ? ESCAPE '\'
	OR alert_message ILIKE ? ESCAPE '\'
	OR alert_machine_id ILIKE ? ESCAPE '\'
	OR alert_engine_id = ANY(ARRAY(SELECT engine_id FROM engine WHERE engine_name ILIKE ? ESCAPE '\')))`

func alertSearchPredicate(selectQuery *bun.SelectQuery, term string) *bun.SelectQuery {
	if term == "" {
		return selectQuery
	}
	containsPattern := search.ContainsPattern(term)
	return selectQuery.Where(alertSearchCondition, containsPattern, containsPattern, containsPattern, containsPattern, containsPattern)
}
