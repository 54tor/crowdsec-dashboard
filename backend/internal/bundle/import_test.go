package bundle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

func TestPreviewIsStableAndDigestIsDeterministic(testContext *testing.T) {
	fixture := newImportFixture()
	firstBan, secondBan := banUntil("203.0.113.20", time.Hour), banUntil("203.0.113.0/28", 2*time.Hour)
	imported := decisionsBundle(firstBan, secondBan)
	firstPlan := planOrFail(testContext, fixture, imported, SectionDecision)
	secondPlan := planOrFail(testContext, fixture, imported, SectionDecision)
	if firstPlan.Digest == "" || firstPlan.Digest != secondPlan.Digest {
		testContext.Fatalf("the same bundle on the same state must give the same digest, got %q and %q", firstPlan.Digest, secondPlan.Digest)
	}
	reordered := planOrFail(testContext, fixture, decisionsBundle(secondBan, firstBan), SectionDecision)
	if reordered.Digest != firstPlan.Digest {
		testContext.Errorf("the digest must not depend on the bundle order, got %q and %q", reordered.Digest, firstPlan.Digest)
	}
	// The preview and the apply run a few seconds apart: the digest must survive that.
	fixture.now = importTestTime.Add(20 * time.Second)
	if later := planOrFail(testContext, fixture, imported, SectionDecision); later.Digest != firstPlan.Digest {
		testContext.Errorf("seconds elapsed between preview and apply must not change the digest")
	}
	changed := planOrFail(testContext, fixture, decisionsBundle(firstBan), SectionDecision)
	if changed.Digest == firstPlan.Digest {
		testContext.Errorf("a different plan must give a different digest")
	}
	fixture.allowlists.read = allowlistOf("203.0.113.20")
	if allowlisted := planOrFail(testContext, fixture, imported, SectionDecision); allowlisted.Digest == firstPlan.Digest {
		testContext.Errorf("skipped items are part of the digest: an allowlisted target must change it")
	}
}

func TestHubImportInstallsOnlyAbsentCollections(testContext *testing.T) {
	fixture := newImportFixture()
	imported := hubBundle(
		HubCollection{Name: "crowdsecurity/linux", Version: "0.5"},
		HubCollection{Name: "crowdsecurity/nginx", Version: "0.2"},
		HubCollection{Name: "crowdsecurity/nginx", Version: "0.2"},
	)
	plan := planOrFail(testContext, fixture, imported, SectionHub)
	if len(plan.Hub) != 1 || plan.Hub[0].Name != "crowdsecurity/nginx" {
		testContext.Fatalf("only the absent collection must be planned, got %+v", plan.Hub)
	}
	if reason := skippedReason(plan, "crowdsecurity/linux"); reason != ReasonAlreadyInstalled {
		testContext.Errorf("an installed collection must be skipped already_installed, got %q", reason)
	}
	if !slices.Contains(plan.Warnings, "version_mismatch:crowdsecurity/linux") {
		testContext.Errorf("a version mismatch must be reported as a warning, got %v", plan.Warnings)
	}
	report, applyError := Apply(context.Background(), fixture.deps(), plan)
	if applyError != nil {
		testContext.Fatalf("unexpected apply error %v", applyError)
	}
	if !slices.Equal(fixture.installedNames, []string{"crowdsecurity/nginx"}) {
		testContext.Errorf("expected only nginx installed, got %v", fixture.installedNames)
	}
	if report.Sections[0].Applied != 1 || report.Sections[0].Status != StatusApplied {
		testContext.Errorf("unexpected hub report %+v", report.Sections[0])
	}
	tooManyCollections := make([]HubCollection, 0, MaxImportedCollections+1)
	for collectionIndex := range MaxImportedCollections + 1 {
		tooManyCollections = append(tooManyCollections, HubCollection{Name: fmt.Sprintf("example/collection-%d", collectionIndex)})
	}
	if _, planError := PlanImport(context.Background(), fixture.deps(), hubBundle(tooManyCollections...), []string{SectionHub}); !errors.Is(planError, ErrTooManyChanges) {
		testContext.Errorf("more than %d collections to install must be refused, got %v", MaxImportedCollections, planError)
	}
}

func TestDecisionsImportSkipsExpiredAndShortBans(testContext *testing.T) {
	fixture := newImportFixture()
	imported := decisionsBundle(
		banUntil("203.0.113.1", -time.Minute),
		banUntil("203.0.113.2", 4*time.Minute),
		banUntil("203.0.113.3", time.Hour),
	)
	plan := planOrFail(testContext, fixture, imported, SectionDecision)
	if reason := skippedReason(plan, "203.0.113.1"); reason != ReasonExpired {
		testContext.Errorf("an expired ban must be skipped expired, got %q", reason)
	}
	if reason := skippedReason(plan, "203.0.113.2"); reason != "too_short" {
		testContext.Errorf("a ban under 5 minutes must be skipped too_short, got %q", reason)
	}
	if !slices.Equal(plannedValues(plan), []string{"203.0.113.3"}) {
		testContext.Errorf("expected only the long ban planned, got %v", plannedValues(plan))
	}
}

func TestDecisionsImportRefusesWholeBundleAboveMaxChanges(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.shareRules.MaxChanges = 2
	imported := decisionsBundle(banUntil("203.0.113.1", time.Hour), banUntil("203.0.113.2", time.Hour), banUntil("203.0.113.3", time.Hour))
	if _, planError := PlanImport(context.Background(), fixture.deps(), imported, []string{SectionDecision}); !errors.Is(planError, ErrTooManyChanges) {
		testContext.Errorf("above SYNC_MAX_CHANGES the import must be refused whole, got %v", planError)
	}
	fixture.shareRules.MaxChanges = 100000
	overCap := make([]Decision, 0, MaxImportedDecisions+1)
	for decisionIndex := range MaxImportedDecisions + 1 {
		address := netip.AddrFrom4([4]byte{203, 0, byte(113 + decisionIndex/250), byte(1 + decisionIndex%250)})
		overCap = append(overCap, banUntil(address.String(), time.Hour))
	}
	if _, planError := PlanImport(context.Background(), fixture.deps(), decisionsBundle(overCap...), []string{SectionDecision}); !errors.Is(planError, ErrTooManyChanges) {
		testContext.Errorf("above %d decisions the import must be refused whole, got %v", MaxImportedDecisions, planError)
	}
	if len(fixture.addedDecisions) != 0 {
		testContext.Errorf("a refused bundle must write nothing, got %v", fixture.addedDecisions)
	}
}

func TestDecisionsImportRefusesPrivateAndTooWideRanges(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.shareRules.Exclusions = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	fixture.shareRules.EngineAddrs = map[string][]netip.Addr{"peer": {netip.MustParseAddr("203.0.113.200")}}
	imported := decisionsBundle(
		banUntil("10.0.0.1", time.Hour),
		banUntil("192.168.1.0/24", time.Hour),
		banUntil("100.64.0.9", time.Hour),
		banUntil("fe80::1", time.Hour),
		banUntil("4.0.0.0/7", time.Hour),
		banUntil("2001:db8::/31", time.Hour),
		banUntil("192.0.2.5", time.Hour),
		banUntil("203.0.113.200", time.Hour),
		banUntil("not-an-address", time.Hour),
	)
	plan := planOrFail(testContext, fixture, imported, SectionDecision)
	expectedReasons := map[string]string{
		"10.0.0.1":       "private",
		"192.168.1.0/24": "private",
		"100.64.0.9":     "private",
		"fe80::1":        "private",
		"4.0.0.0/7":      "prefix_too_wide",
		"2001:db8::/31":  "prefix_too_wide",
		"192.0.2.5":      "excluded",
		"203.0.113.200":  "engine_address",
		"not-an-address": ReasonInvalidTarget,
	}
	for target, expectedReason := range expectedReasons {
		if obtainedReason := skippedReason(plan, target); obtainedReason != expectedReason {
			testContext.Errorf("%s: expected %q, got %q", target, expectedReason, obtainedReason)
		}
	}
	if len(plan.Decisions) != 0 {
		testContext.Errorf("nothing must be planned, got %v", plannedValues(plan))
	}
}

func TestDecisionsImportSkipsAllowlistedTargets(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.allowlists.read = allowlistOf("203.0.113.10", "198.51.100.64/26", "2001:db8:1::/48")
	imported := decisionsBundle(
		banUntil("203.0.113.10", time.Hour),
		banUntil("203.0.113.0/24", time.Hour),
		banUntil("198.51.100.70", time.Hour),
		banUntil("2001:db8:1::5", time.Hour),
		banUntil("203.0.114.1", time.Hour),
	)
	plan := planOrFail(testContext, fixture, imported, SectionDecision)
	for _, allowlistedTarget := range []string{"203.0.113.10", "203.0.113.0/24", "198.51.100.70", "2001:db8:1::5"} {
		if reason := skippedReason(plan, allowlistedTarget); reason != "allowlisted" {
			testContext.Errorf("%s: expected allowlisted, got %q", allowlistedTarget, reason)
		}
	}
	if !slices.Equal(plannedValues(plan), []string{"203.0.114.1"}) {
		testContext.Errorf("only the non-allowlisted target may be planned, got %v", plannedValues(plan))
	}
	if plan.SkippedCounts[SectionDecision]["allowlisted"] != 4 {
		testContext.Errorf("the preview must count allowlisted per section, got %v", plan.SkippedCounts)
	}
	report, applyError := Apply(context.Background(), fixture.deps(), plan)
	if applyError != nil {
		testContext.Fatalf("unexpected apply error %v", applyError)
	}
	if report.Sections[0].SkippedReasons["allowlisted"] != 4 || report.Sections[0].Applied != 1 {
		testContext.Errorf("the apply report must count allowlisted per section, got %+v", report.Sections[0])
	}
	if len(fixture.addedDecisions) != 1 || fixture.addedDecisions[0].Target != "203.0.114.1" {
		testContext.Errorf("only the non-allowlisted target may be written, got %v", fixture.addedDecisions)
	}
	if fixture.allowlists.reads != 1 {
		testContext.Errorf("one plan reads the allowlists exactly once, got %d", fixture.allowlists.reads)
	}
}

func TestDecisionsImportIgnoresExpiredEntries(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.allowlists.read = lapi.AllowlistRead{Allowlists: []lapi.Allowlist{{Name: "operators", Items: []lapi.AllowlistItem{
		{Value: "203.0.113.30", Expiration: importTestTime.Add(-time.Hour).Format(time.RFC3339)},
		{Value: "203.0.113.31", Expiration: importTestTime.Add(time.Hour).Format(time.RFC3339)},
	}}}}
	plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.30", time.Hour), banUntil("203.0.113.31", time.Hour)), SectionDecision)
	if !slices.Equal(plannedValues(plan), []string{"203.0.113.30"}) {
		testContext.Errorf("an expired entry must not block, an active one must, got %v", plannedValues(plan))
	}
	if reason := skippedReason(plan, "203.0.113.31"); reason != "allowlisted" {
		testContext.Errorf("expected the active entry to block, got %q", reason)
	}
}

func TestDecisionsImportRefusedWhenLocalAllowlistUnavailable(testContext *testing.T) {
	unreadableReads := map[string]*fakeAllowlistReader{
		"read error": {readError: lapi.ErrAllowlistsUnreadable},
		"truncated":  {read: lapi.AllowlistRead{Allowlists: []lapi.Allowlist{}, Truncated: true}},
		"bad entry":  {read: allowlistOf("not-an-address")},
	}
	for caseName, unreadableReader := range unreadableReads {
		fixture := newImportFixture()
		fixture.allowlists = unreadableReader
		plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.40", time.Hour)), SectionDecision)
		if !slices.Equal(plan.Unavailable, []string{SectionDecision}) || len(plan.Decisions) != 0 {
			testContext.Errorf("%s: the decisions section must be section_unavailable with nothing planned, got %+v", caseName, plan)
		}
		if _, applyError := Apply(context.Background(), fixture.deps(), plan); !errors.Is(applyError, ErrSectionUnavailable) {
			testContext.Errorf("%s: apply must refuse an unavailable section, got %v", caseName, applyError)
		}
		if len(fixture.addedDecisions) != 0 {
			testContext.Errorf("%s: nothing may be written, got %v", caseName, fixture.addedDecisions)
		}
	}
}

func TestDecisionsImportUnavailableWhenStateOrEngineAddressesUnknown(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.rulesUnavailable = true
	if plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.41", time.Hour)), SectionDecision); !slices.Equal(plan.Unavailable, []string{SectionDecision}) {
		testContext.Errorf("unknown engine addresses must make the section unavailable, got %+v", plan)
	}
	fixture = newImportFixture()
	fixture.localBansPartial = true
	if plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.41", time.Hour)), SectionDecision); !slices.Equal(plan.Unavailable, []string{SectionDecision}) {
		testContext.Errorf("a partial read of the local bans must make the section unavailable, got %+v", plan)
	}
}

func TestImportNeverWritesWhenAllowlistsRouteFails500(testContext *testing.T) {
	// Rule 19: the real allowlist read of the local engine answers 500, so no decision may be
	// written. The control case (200) proves the same wiring does write when the read succeeds.
	writesByAllowlistStatus := map[int]int32{http.StatusInternalServerError: 0, http.StatusOK: 1}
	for allowlistStatus, expectedWrites := range writesByAllowlistStatus {
		client, alertWrites := fakeLocalLAPIServer(testContext, allowlistStatus)
		fixture := newImportFixture()
		deps := fixture.deps()
		deps.Allowlists = client
		deps.ReadLocalBans = client.ReadSyncBans
		deps.AddDecision = client.AddDecision
		plan, planError := PlanImport(context.Background(), deps, decisionsBundle(banUntil("203.0.113.50", time.Hour)), []string{SectionDecision})
		if planError != nil {
			testContext.Fatalf("status %d: unexpected plan error %v", allowlistStatus, planError)
		}
		_, applyError := Apply(context.Background(), deps, plan)
		isRefusedAsUnavailable := errors.Is(applyError, ErrSectionUnavailable)
		if (allowlistStatus == http.StatusInternalServerError) != isRefusedAsUnavailable {
			testContext.Errorf("allowlists answering %d: unexpected apply error %v", allowlistStatus, applyError)
		}
		if alertWrites.Load() != expectedWrites {
			testContext.Errorf("allowlists answering %d: expected %d writes, got %d", allowlistStatus, expectedWrites, alertWrites.Load())
		}
	}
}

func TestDecisionsImportSkipsDuplicatesOfLocalBans(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.localBans = []lapi.SyncDecision{
		{Origin: "crowdsec", Scope: "Range", Value: "203.0.113.0/24", Remaining: time.Hour},
		{Origin: "dashboard-sync", Scope: "Ip", Value: "203.0.114.9", Scenario: "sync/peer", Remaining: time.Hour},
	}
	imported := decisionsBundle(banUntil("203.0.113.60", time.Hour), banUntil("203.0.114.9", time.Hour), banUntil("203.0.115.1", time.Hour), banUntil("203.0.115.1", time.Hour))
	plan := planOrFail(testContext, fixture, imported, SectionDecision)
	if !slices.Equal(plannedValues(plan), []string{"203.0.115.1"}) {
		testContext.Errorf("covered and repeated targets must be skipped, got %v", plannedValues(plan))
	}
	if plan.SkippedCounts[SectionDecision][ReasonDuplicate] != 3 {
		testContext.Errorf("expected 3 duplicates, got %v", plan.SkippedCounts)
	}
}

func TestApplyIsIdempotentOnReplay(testContext *testing.T) {
	fixture := newImportFixture()
	imported := Bundle{Format: Format, Version: Version, Sections: Sections{
		Hub:       &HubSection{Collections: []HubCollection{{Name: "crowdsecurity/nginx"}}},
		Decisions: &DecisionsSection{Decisions: []Decision{banUntil("203.0.113.70", time.Hour)}},
	}}
	sections := []string{SectionHub, SectionDecision}
	if _, applyError := Apply(context.Background(), fixture.deps(), planOrFail(testContext, fixture, imported, sections...)); applyError != nil {
		testContext.Fatalf("unexpected apply error %v", applyError)
	}
	writesAfterFirstApply := len(fixture.installedNames) + len(fixture.addedDecisions)
	replayPlan := planOrFail(testContext, fixture, imported, sections...)
	report, applyError := Apply(context.Background(), fixture.deps(), replayPlan)
	if applyError != nil {
		testContext.Fatalf("unexpected replay error %v", applyError)
	}
	if writesAfterFirstApply != 2 || len(fixture.installedNames)+len(fixture.addedDecisions) != 2 {
		testContext.Errorf("the replay must write nothing, got installs %v decisions %v", fixture.installedNames, fixture.addedDecisions)
	}
	if skippedReason(replayPlan, "crowdsecurity/nginx") != ReasonAlreadyInstalled || skippedReason(replayPlan, "203.0.113.70") != ReasonDuplicate {
		testContext.Errorf("the replay must report already_installed and duplicate, got %+v", replayPlan.Skipped)
	}
	for _, sectionReport := range report.Sections {
		if sectionReport.Applied != 0 || sectionReport.Status != StatusApplied {
			testContext.Errorf("unexpected replay report %+v", sectionReport)
		}
	}
}

func TestApplyStopsAtFirstFailingSectionAndReportsPerSection(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.installError = errInstallFailed
	imported := Bundle{Format: Format, Version: Version, Sections: Sections{
		Hub:       &HubSection{Collections: []HubCollection{{Name: "crowdsecurity/nginx"}}},
		Decisions: &DecisionsSection{Decisions: []Decision{banUntil("203.0.113.80", time.Hour)}},
	}}
	plan := planOrFail(testContext, fixture, imported, SectionDecision, SectionHub)
	report, applyError := Apply(context.Background(), fixture.deps(), plan)
	if applyError != nil {
		testContext.Fatalf("a failing section is reported, not returned, got %v", applyError)
	}
	expectedReports := []SectionReport{
		{Section: SectionHub, Status: StatusFailed, Failed: 1, ErrorCode: ErrorCodeApplyFailed},
		{Section: SectionDecision, Status: StatusNotRun},
	}
	if len(report.Sections) != len(expectedReports) {
		testContext.Fatalf("expected one report per section in apply order, got %+v", report.Sections)
	}
	for reportIndex, expectedReport := range expectedReports {
		obtainedReport := report.Sections[reportIndex]
		if obtainedReport.Section != expectedReport.Section || obtainedReport.Status != expectedReport.Status || obtainedReport.Failed != expectedReport.Failed || obtainedReport.ErrorCode != expectedReport.ErrorCode {
			testContext.Errorf("section %d: expected %+v, got %+v", reportIndex, expectedReport, obtainedReport)
		}
	}
	if len(fixture.addedDecisions) != 0 {
		testContext.Errorf("sections after the failing one must not run, got %v", fixture.addedDecisions)
	}
}

func TestImportedDecisionsAreMarkedImportScenario(testContext *testing.T) {
	fixture := newImportFixture()
	plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.90", 90*time.Minute), banUntil("203.0.113.0/30", time.Hour)), SectionDecision)
	if _, applyError := Apply(context.Background(), fixture.deps(), plan); applyError != nil {
		testContext.Fatalf("unexpected apply error %v", applyError)
	}
	expectedDecisions := []lapi.NewDecision{
		{Target: "203.0.113.0/30", Scope: "range", Type: "ban", Duration: "1h0m0s", Reason: "import/2026-11-03", Scenario: "import/2026-11-03"},
		{Target: "203.0.113.90", Scope: "ip", Type: "ban", Duration: "1h30m0s", Reason: "import/2026-11-03", Scenario: "import/2026-11-03"},
	}
	if !slices.Equal(fixture.addedDecisions, expectedDecisions) {
		testContext.Errorf("expected %+v, got %+v", expectedDecisions, fixture.addedDecisions)
	}
}

func TestImportReportsUnregisteredSectionsUnavailable(testContext *testing.T) {
	fixture := newImportFixture()
	imported := Bundle{Format: Format, Version: Version, Sections: Sections{Config: &ConfigSection{Files: []ConfigFile{}}}}
	plan := planOrFail(testContext, fixture, imported, SectionConfig)
	if !slices.Equal(plan.Unavailable, []string{SectionConfig}) {
		testContext.Errorf("config must be section_unavailable until registered, got %v", plan.Unavailable)
	}
}

func TestImportRefusesInvalidSectionLists(testContext *testing.T) {
	fixture := newImportFixture()
	imported := decisionsBundle(banUntil("203.0.113.95", time.Hour))
	invalidSectionLists := [][]string{{}, {"peers"}, {SectionDecision, SectionDecision}, {SectionHub}}
	for _, invalidSections := range invalidSectionLists {
		if _, planError := PlanImport(context.Background(), fixture.deps(), imported, invalidSections); !errors.Is(planError, ErrInvalidRequest) {
			testContext.Errorf("%v: expected ErrInvalidRequest, got %v", invalidSections, planError)
		}
	}
}

func TestHubImportSkipsInvalidCollectionNames(testContext *testing.T) {
	fixture := newImportFixture()
	invalidNames := []string{"-force", "../x", "a/b/c", strings.Repeat("a", 65), ""}
	collections := []HubCollection{{Name: "crowdsecurity/nginx"}}
	for _, invalidName := range invalidNames {
		collections = append(collections, HubCollection{Name: invalidName})
	}
	plan := planOrFail(testContext, fixture, hubBundle(collections...), SectionHub)
	if len(plan.Hub) != 1 || plan.Hub[0].Name != "crowdsecurity/nginx" {
		testContext.Errorf("only the valid name may be planned for install, got %+v", plan.Hub)
	}
	for _, invalidName := range invalidNames {
		if reason := skippedReason(plan, invalidName); reason != ReasonInvalidName {
			testContext.Errorf("%q: expected invalid_name, got %q", invalidName, reason)
		}
	}
}

func TestPlanStopsWhenTheContextExpires(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.hubReadDelay = time.Minute
	expiringContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, planError := PlanImport(expiringContext, fixture.deps(), hubBundle(HubCollection{Name: "crowdsecurity/nginx"}), []string{SectionHub})
	if !errors.Is(planError, context.DeadlineExceeded) {
		testContext.Errorf("an expired plan must report the deadline, got %v", planError)
	}
}

func TestDecisionsImportKeepsLongerBanOverShorterCoveringOne(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.localBans = []lapi.SyncDecision{
		{Origin: "crowdsec", Scope: "Range", Value: "203.0.113.0/24", Remaining: 10 * time.Minute},
		{Origin: "crowdsec", Scope: "Range", Value: "203.0.114.0/24", Remaining: 30 * 24 * time.Hour},
	}
	imported := decisionsBundle(banUntil("203.0.113.7", 7*24*time.Hour), banUntil("203.0.114.7", 7*24*time.Hour))
	plan := planOrFail(testContext, fixture, imported, SectionDecision)
	if !slices.Equal(plannedValues(plan), []string{"203.0.113.7"}) {
		testContext.Errorf("a shorter covering ban must not suppress a longer import, got %v", plannedValues(plan))
	}
	if reason := skippedReason(plan, "203.0.114.7"); reason != ReasonDuplicate {
		testContext.Errorf("a longer covering ban makes the import a duplicate, got %q", reason)
	}
}

func TestDecisionsImportSkipsBansLongerThanTheManualMaximum(testContext *testing.T) {
	fixture := newImportFixture()
	plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.8", 10000*time.Hour), banUntil("203.0.113.9", 9999*time.Hour)), SectionDecision)
	if reason := skippedReason(plan, "203.0.113.8"); reason != ReasonTooLong {
		testContext.Errorf("a ban beyond 9999h must be skipped too_long, got %q", reason)
	}
	if !slices.Equal(plannedValues(plan), []string{"203.0.113.9"}) {
		testContext.Errorf("a ban at the maximum stays importable, got %v", plannedValues(plan))
	}
}

func TestApplyRechecksTheAllowlistBeforeEachWrite(testContext *testing.T) {
	// The recheck is a second line of defence on the same snapshot: here the plan carries a
	// target that the plan's own guard refuses, as if the first check had been bypassed.
	fixture := newImportFixture()
	plan := planOrFail(testContext, fixture, decisionsBundle(banUntil("203.0.113.11", time.Hour)), SectionDecision)
	sectionPlan := plan.sectionPlans[SectionDecision]
	sectionPlan.allowlistGuard = allowguard.FromRead(allowlistOf("203.0.113.11"), nil, importTestTime)
	plan.sectionPlans[SectionDecision] = sectionPlan
	report, applyError := Apply(context.Background(), fixture.deps(), plan)
	if applyError != nil {
		testContext.Fatalf("unexpected apply error %v", applyError)
	}
	if len(fixture.addedDecisions) != 0 || report.Sections[0].SkippedReasons["allowlisted"] != 1 {
		testContext.Errorf("the recheck must skip allowlisted with no write, got %v %+v", fixture.addedDecisions, report.Sections[0])
	}
}

func TestApplyKeepsTheSectionFailureCause(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.installError = errInstallFailed
	plan := planOrFail(testContext, fixture, hubBundle(HubCollection{Name: "crowdsecurity/nginx"}), SectionHub)
	report, _ := Apply(context.Background(), fixture.deps(), plan)
	if !errors.Is(report.Sections[0].Failure, errInstallFailed) {
		testContext.Errorf("the failing cause must be kept for the code mapping, got %v", report.Sections[0].Failure)
	}
}
