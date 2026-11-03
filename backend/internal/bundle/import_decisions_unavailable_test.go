package bundle

import (
	"testing"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

// Each reason that makes the decisions import impossible has its own stable code, so the preview
// can tell the operator what to fix instead of a bare section_unavailable.
func TestDecisionsImportUnavailableReportsItsCause(testContext *testing.T) {
	casesByExpectedCode := map[string]func(fixture *importFixture) *importFixture{
		ErrorCodeAllowlistUnavailable: func(fixture *importFixture) *importFixture {
			fixture.allowlists = &fakeAllowlistReader{readError: lapi.ErrAllowlistsUnreadable}
			return fixture
		},
		ErrorCodeEngineAddressesUnknown: func(fixture *importFixture) *importFixture {
			fixture.rulesUnavailable = true
			return fixture
		},
		ErrorCodeLocalBansIncomplete: func(fixture *importFixture) *importFixture {
			fixture.localBansPartial = true
			return fixture
		},
	}
	for expectedCode, breakFixture := range casesByExpectedCode {
		fixture := breakFixture(newImportFixture())
		plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.40", time.Hour)), SectionDecision)
		if obtainedCode := plan.UnavailableCodes[SectionDecision]; obtainedCode != expectedCode {
			testContext.Errorf("expected unavailable code %q, got %q (%+v)", expectedCode, obtainedCode, plan.UnavailableCodes)
		}
	}
}

func TestDecisionsImportWithoutWiringReportsDependencyMissing(testContext *testing.T) {
	deps := newImportFixture().deps()
	deps.AddDecision = nil
	plan, planError := PlanImport(testContext.Context(), deps, decisionsBundle(banUntil("203.0.113.40", time.Hour)), []string{SectionDecision})
	if planError != nil || plan.UnavailableCodes[SectionDecision] != ErrorCodeDependencyMissing {
		testContext.Errorf("expected %q, got %v %+v", ErrorCodeDependencyMissing, planError, plan.UnavailableCodes)
	}
}
