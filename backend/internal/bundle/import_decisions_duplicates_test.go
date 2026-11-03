package bundle

import (
	"testing"
	"time"
)

// Two bans on the same target inside one bundle: whatever their order, exactly one ban is planned
// and it is the longer one (planning the short one first would mark the long one as covered).
func TestSameTargetDecisionsPlanOnlyTheLongerBan(testContext *testing.T) {
	ordersByName := map[string][]Decision{
		"short first": {banUntil("203.0.113.50", time.Hour), banUntil("203.0.113.50", 5*time.Hour)},
		"long first":  {banUntil("203.0.113.50", 5*time.Hour), banUntil("203.0.113.50", time.Hour)},
	}
	var digests []string
	for orderName, decisions := range ordersByName {
		plan := planOrFail(testContext, newImportFixture(), decisionsBundle(decisions...), SectionDecision)
		if len(plan.Decisions) != 1 || !plan.Decisions[0].Until.Equal(importTestTime.Add(5*time.Hour)) {
			testContext.Errorf("%s: expected only the 5h ban, got %+v", orderName, plan.Decisions)
		}
		digests = append(digests, plan.Digest)
	}
	if digests[0] != digests[1] {
		testContext.Errorf("the digest must not depend on the bundle order, got %v", digests)
	}
}
