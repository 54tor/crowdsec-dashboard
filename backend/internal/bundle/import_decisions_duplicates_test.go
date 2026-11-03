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

// Two spellings of one target (upper-case IPv6, bare address against its /32) are grouped on the
// canonical target: the longer ban is planned and the shorter one is a duplicate.
func TestSameTargetSpelledDifferentlyPlansOnlyTheLongerBan(testContext *testing.T) {
	spellingsByName := map[string][2]string{
		"ipv6 case":    {"2001:DB8::1", "2001:db8::1"},
		"bare and /32": {"203.0.113.50", "203.0.113.50/32"},
		"/32 and bare": {"203.0.113.50/32", "203.0.113.50"},
	}
	for caseName, spellings := range spellingsByName {
		shortBan := banUntil(spellings[0], time.Hour)
		longBan := banUntil(spellings[1], 5*time.Hour)
		plan := planOrFail(testContext, newImportFixture(), decisionsBundle(shortBan, longBan), SectionDecision)
		if len(plan.Decisions) != 1 || !plan.Decisions[0].Until.Equal(importTestTime.Add(5*time.Hour)) {
			testContext.Errorf("%s: expected only the 5h ban, got %+v", caseName, plan.Decisions)
		}
	}
}
