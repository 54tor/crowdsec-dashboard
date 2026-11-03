package bundle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

// importedAlertFrom builds an alert as an export writes it: dated the day before the test clock,
// with the original decision and uuid of the source engine.
func importedAlertFrom(value string, startOffset time.Duration) lapi.Alert {
	scope := "Ip"
	if strings.Contains(value, "/") {
		scope = "Range"
	}
	startAt := importTestTime.Add(-24 * time.Hour).Add(startOffset)
	return lapi.Alert{
		UUID:        "source-engine-uuid-" + value,
		Scenario:    "crowdsecurity/ssh-bf",
		Message:     "imported",
		EventsCount: 1,
		StartAt:     startAt.Format(time.RFC3339),
		StopAt:      startAt.Add(time.Minute).Format(time.RFC3339),
		Source:      lapi.Source{Scope: scope, Value: value},
		Decisions:   []lapi.Decision{{ID: 7, Origin: "crowdsec", Type: "ban", Duration: "3h0m0s"}},
	}
}

func guardOf(values ...string) allowguard.Guard {
	return allowguard.FromRead(allowlistOf(values...), nil, importTestTime)
}

func alertsBundle(alerts ...lapi.Alert) Bundle {
	return Bundle{Format: Format, Version: Version, Sections: Sections{Alerts: &AlertsSection{Alerts: alerts}}}
}

func plannedAlertValues(plan ImportPlan) []string {
	values := []string{}
	for _, alertAction := range plan.Alerts {
		values = append(values, alertAction.Value)
	}
	return values
}

func applyOrFail(testContext *testing.T, fixture *importFixture, plan ImportPlan) ApplyReport {
	testContext.Helper()
	report, applyError := Apply(context.Background(), fixture.deps(), plan)
	if applyError != nil {
		testContext.Fatalf("unexpected apply error %v", applyError)
	}
	return report
}

func TestAlertImportPushesPlannedAlertsAsSanitisedCopies(testContext *testing.T) {
	fixture := newImportFixture()
	plan := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.10", 0), importedAlertFrom("203.0.113.0/28", time.Minute)), SectionAlerts)
	report := applyOrFail(testContext, fixture, plan)
	if len(fixture.pushedAlerts) != 2 || report.Sections[0].Applied != 2 || report.Sections[0].Status != StatusApplied {
		testContext.Fatalf("both alerts must be pushed, got %d pushes and %+v", len(fixture.pushedAlerts), report.Sections[0])
	}
	for _, pushedAlert := range fixture.pushedAlerts {
		if !pushedAlert.Simulated || pushedAlert.Decisions != nil || pushedAlert.UUID != "" {
			testContext.Errorf("the pushed alert must be the sanitised simulated copy, got %+v", pushedAlert)
		}
	}
}

func TestAlertImportCapsAtFiveHundred(testContext *testing.T) {
	fixture := newImportFixture()
	tooManyAlerts := make([]lapi.Alert, 0, MaxImportedAlerts+1)
	for alertIndex := range MaxImportedAlerts + 1 {
		tooManyAlerts = append(tooManyAlerts, importedAlertFrom(fmt.Sprintf("203.0.%d.%d", 113+alertIndex/250, alertIndex%250+1), 0))
	}
	if _, planError := PlanImport(context.Background(), fixture.deps(), alertsBundle(tooManyAlerts...), []string{SectionAlerts}); !errors.Is(planError, ErrTooManyChanges) {
		testContext.Errorf("more than %d alerts to push must refuse the whole bundle, got %v", MaxImportedAlerts, planError)
	}
	atTheCap := planOrFail(testContext, fixture, alertsBundle(tooManyAlerts[:MaxImportedAlerts]...), SectionAlerts)
	if len(atTheCap.Alerts) != MaxImportedAlerts {
		testContext.Errorf("exactly %d alerts stay importable, got %d", MaxImportedAlerts, len(atTheCap.Alerts))
	}
	if len(fixture.pushedAlerts) != 0 {
		testContext.Errorf("a refused bundle pushes nothing, got %d", len(fixture.pushedAlerts))
	}
}

func TestAlertImportSkipsKnownAlerts(testContext *testing.T) {
	fixture := newImportFixture()
	knownAlert := importedAlertFrom("203.0.113.20", 0)
	// The engine stored the same alert under another uuid, with sub-second precision dropped.
	storedCopy := knownAlert
	storedCopy.UUID, storedCopy.ID = "engine-regenerated", 3
	fixture.localAlerts = []lapi.Alert{storedCopy}
	sameKeyWithFraction := importedAlertFrom("203.0.113.21", 0)
	sameKeyWithFraction.StartAt = importTestTime.Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z07:00")
	plan := planOrFail(testContext, fixture, alertsBundle(knownAlert, importedAlertFrom("203.0.113.21", 0), sameKeyWithFraction, importedAlertFrom("203.0.113.22", 0)), SectionAlerts)
	if !slices.Equal(plannedAlertValues(plan), []string{"203.0.113.21", "203.0.113.22"}) {
		testContext.Errorf("a stored alert and a repeated key must be skipped, got %v", plannedAlertValues(plan))
	}
	if plan.SkippedCounts[SectionAlerts][ReasonDuplicate] != 2 {
		testContext.Errorf("expected 2 duplicates, got %v", plan.SkippedCounts)
	}
}

func TestAlertImportRefusedNearFlushLimit(testContext *testing.T) {
	configDir := testContext.TempDir()
	writeConfigError := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("db_config:\n  flush:\n    max_items: 20\n    max_age: 7d\n"), 0o600)
	if writeConfigError != nil {
		testContext.Fatal(writeConfigError)
	}
	fixture := newImportFixture()
	fixture.configDir = configDir
	for alertIndex := range 16 {
		fixture.localAlerts = append(fixture.localAlerts, importedAlertFrom(fmt.Sprintf("198.51.100.%d", alertIndex+1), 0))
	}
	// 90 % of 20 is 18: 16 stored plus 2 imported fits, 16 plus 3 would let the flush purge history.
	fitting := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.30", 0), importedAlertFrom("203.0.113.31", 0)), SectionAlerts)
	if len(fitting.Unavailable) != 0 || len(fitting.Alerts) != 2 {
		testContext.Errorf("an import within 90 %% of flush.max_items must be planned, got %+v", fitting)
	}
	overflowing := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.30", 0), importedAlertFrom("203.0.113.31", 0), importedAlertFrom("203.0.113.32", 0)), SectionAlerts)
	if !slices.Equal(overflowing.Unavailable, []string{SectionAlerts}) || overflowing.UnavailableCodes[SectionAlerts] != ErrorCodeFlushLimit {
		testContext.Fatalf("an import beyond 90 %% of flush.max_items must be section_unavailable flush_limit, got %+v", overflowing)
	}
	if _, applyError := Apply(context.Background(), fixture.deps(), overflowing); !errors.Is(applyError, ErrSectionUnavailable) || len(fixture.pushedAlerts) != 0 {
		testContext.Errorf("nothing may be pushed, got %v and %d pushes", applyError, len(fixture.pushedAlerts))
	}
	writeConfigError = os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("db_config: [unterminated\n"), 0o600)
	if writeConfigError != nil {
		testContext.Fatal(writeConfigError)
	}
	unreadable := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.30", 0)), SectionAlerts)
	if unreadable.UnavailableCodes[SectionAlerts] != ErrorCodeFlushConfigUnreadable {
		testContext.Errorf("a config.yaml that does not parse must make the section unavailable, got %+v", unreadable)
	}
}

func TestAlertImportUsesTheDefaultFlushLimitWithoutConfigFile(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.configDir = testContext.TempDir()
	for alertIndex := range 4500 {
		fixture.localAlerts = append(fixture.localAlerts, lapi.Alert{ID: int64(alertIndex)})
	}
	plan := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.33", 0)), SectionAlerts)
	if plan.UnavailableCodes[SectionAlerts] != ErrorCodeFlushLimit {
		testContext.Errorf("4500 stored alerts already reach 90 %% of the default 5000, got %+v", plan)
	}
}

func TestAlertsImportSkipsAllowlistedSources(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.allowlists.read = allowlistOf("203.0.113.0/26")
	countryAlert := importedAlertFrom("ZZ", 0)
	countryAlert.Source.Scope = "Country"
	imported := alertsBundle(importedAlertFrom("203.0.113.40", 0), importedAlertFrom("203.0.113.0/24", 0), importedAlertFrom("203.0.113.200", 0), countryAlert)
	plan := planOrFail(testContext, fixture, imported, SectionAlerts)
	if !slices.Equal(plannedAlertValues(plan), []string{"203.0.113.200"}) {
		testContext.Errorf("only the source outside the allowlist may be planned, got %v", plannedAlertValues(plan))
	}
	if plan.SkippedCounts[SectionAlerts]["allowlisted"] != 2 || skippedReason(plan, "ZZ") != ReasonInvalid {
		testContext.Errorf("expected 2 allowlisted and a non-address source invalid, got %v", plan.SkippedCounts)
	}
	applyOrFail(testContext, fixture, plan)
	if len(fixture.pushedAlerts) != 1 || fixture.pushedAlerts[0].Source.Value != "203.0.113.200" {
		testContext.Errorf("an allowlisted source must never be pushed, got %+v", fixture.pushedAlerts)
	}
}

func TestAlertImportRechecksTheAllowlistBeforeEachPush(testContext *testing.T) {
	fixture := newImportFixture()
	plan := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.41", 0)), SectionAlerts)
	sectionPlan := plan.sectionPlans[SectionAlerts]
	sectionPlan.allowlistGuard = guardOf("203.0.113.41")
	plan.sectionPlans[SectionAlerts] = sectionPlan
	report := applyOrFail(testContext, fixture, plan)
	if len(fixture.pushedAlerts) != 0 || report.Sections[0].SkippedReasons["allowlisted"] != 1 {
		testContext.Errorf("the recheck must skip allowlisted with no push, got %d pushes %+v", len(fixture.pushedAlerts), report.Sections[0])
	}
}

func TestAlertsImportRefusedWhenLocalAllowlistUnavailable(testContext *testing.T) {
	unreadableReads := map[string]*fakeAllowlistReader{
		"read error": {readError: lapi.ErrAllowlistsUnreadable},
		"truncated":  {read: lapi.AllowlistRead{Allowlists: []lapi.Allowlist{}, Truncated: true}},
		"bad entry":  {read: allowlistOf("not-an-address")},
	}
	for caseName, unreadableReader := range unreadableReads {
		fixture := newImportFixture()
		fixture.allowlists = unreadableReader
		plan := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.42", 0)), SectionAlerts)
		if !slices.Equal(plan.Unavailable, []string{SectionAlerts}) || len(plan.Alerts) != 0 || plan.UnavailableCodes[SectionAlerts] != ErrorCodeAllowlistUnavailable {
			testContext.Errorf("%s: the alerts section must be section_unavailable with nothing planned, got %+v", caseName, plan)
		}
		if _, applyError := Apply(context.Background(), fixture.deps(), plan); !errors.Is(applyError, ErrSectionUnavailable) {
			testContext.Errorf("%s: apply must refuse an unavailable section, got %v", caseName, applyError)
		}
		if len(fixture.pushedAlerts) != 0 {
			testContext.Errorf("%s: nothing may be pushed, got %d", caseName, len(fixture.pushedAlerts))
		}
	}
}

func TestAlertImportNeverPushesWhenAllowlistsRouteFails500(testContext *testing.T) {
	// Rule 19: the real allowlist read of the local engine answers 500, so PushImportedAlert is
	// never called. The control case (200) proves the same wiring pushes when the read succeeds.
	pushesByAllowlistStatus := map[int]int32{http.StatusInternalServerError: 0, http.StatusOK: 1}
	for allowlistStatus, expectedPushes := range pushesByAllowlistStatus {
		client, alertWrites := fakeLocalLAPIServer(testContext, allowlistStatus)
		fixture := newImportFixture()
		deps := fixture.deps()
		deps.Allowlists = client
		deps.ReadLocalAlerts = client.ReadAlertsForArchive
		deps.PushImportedAlert = client.PushImportedAlert
		deps.ListAlerts = client.ListAlerts
		deps.DeleteDecision = client.DeleteDecision
		plan, planError := PlanImport(context.Background(), deps, alertsBundle(importedAlertFrom("203.0.113.43", 0)), []string{SectionAlerts})
		if planError != nil {
			testContext.Fatalf("status %d: unexpected plan error %v", allowlistStatus, planError)
		}
		_, applyError := Apply(context.Background(), deps, plan)
		isRefusedAsUnavailable := errors.Is(applyError, ErrSectionUnavailable)
		if (allowlistStatus == http.StatusInternalServerError) != isRefusedAsUnavailable {
			testContext.Errorf("allowlists answering %d: unexpected apply error %v", allowlistStatus, applyError)
		}
		if alertWrites.Load() != expectedPushes {
			testContext.Errorf("allowlists answering %d: expected %d pushes, got %d", allowlistStatus, expectedPushes, alertWrites.Load())
		}
	}
}

func TestAlertImportAbortsAndCleansWhenDecisionAppears(testContext *testing.T) {
	fixture := newImportFixture()
	fixture.decisionOnPush = true
	plan := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.50", 0), importedAlertFrom("203.0.113.51", 0), importedAlertFrom("203.0.113.52", 0)), SectionAlerts)
	report := applyOrFail(testContext, fixture, plan)
	if len(fixture.pushedAlerts) != 1 {
		testContext.Errorf("the import must stop after the first push that produced a decision, got %d pushes", len(fixture.pushedAlerts))
	}
	createdDecisionID := fixture.localAlerts[0].Decisions[1].ID
	if !slices.Equal(fixture.deletedDecisionIDs, []int64{createdDecisionID}) {
		testContext.Errorf("only the decision the LAPI created must be deleted, got %v", fixture.deletedDecisionIDs)
	}
	alertsReport := report.Sections[0]
	if alertsReport.Status != StatusUnavailable || alertsReport.ErrorCode != ErrorCodeAlertImportSideEffect {
		testContext.Errorf("expected section_unavailable alert_import_side_effect, got %+v", alertsReport)
	}
	if !errors.Is(alertsReport.Failure, ErrSectionUnavailable) {
		testContext.Errorf("the failure must stay classified as section_unavailable, got %v", alertsReport.Failure)
	}
}

func TestAlertImportKeepsPreexistingDecisionsOnTheSameSource(testContext *testing.T) {
	// A real ban on the same address under another alert is not a side effect of the import.
	fixture := newImportFixture()
	realAlert := importedAlertFrom("203.0.113.53", -time.Hour)
	realAlert.Decisions = []lapi.Decision{{ID: 5, Origin: "crowdsec", Type: "ban", Duration: "2h0m0s"}}
	fixture.localAlerts = []lapi.Alert{realAlert}
	plan := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.53", 0)), SectionAlerts)
	report := applyOrFail(testContext, fixture, plan)
	if len(fixture.deletedDecisionIDs) != 0 || report.Sections[0].Status != StatusApplied {
		testContext.Errorf("a decision of another alert must never be deleted, got %v %+v", fixture.deletedDecisionIDs, report.Sections[0])
	}
}

func TestAlertImportDisabledReturnsSectionUnavailable(testContext *testing.T) {
	fixture := newImportFixture()
	deps := fixture.deps()
	deps.PushImportedAlert = nil
	plan, planError := PlanImport(context.Background(), deps, alertsBundle(importedAlertFrom("203.0.113.60", 0)), []string{SectionAlerts})
	if planError != nil || !slices.Equal(plan.Unavailable, []string{SectionAlerts}) {
		testContext.Errorf("an engine without the alert push wiring must answer section_unavailable, got %+v %v", plan, planError)
	}
	fixture.localAlertsError = lapi.ErrLAPIUnavailable
	unreadable := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.60", 0)), SectionAlerts)
	if unreadable.UnavailableCodes[SectionAlerts] != ErrorCodeLocalAlertsUnreadable {
		testContext.Errorf("unreadable local alerts must make the section unavailable, got %+v", unreadable)
	}
}

func TestAlertImportReplayIsIdempotent(testContext *testing.T) {
	fixture := newImportFixture()
	imported := alertsBundle(importedAlertFrom("203.0.113.70", 0), importedAlertFrom("203.0.113.71", 0))
	applyOrFail(testContext, fixture, planOrFail(testContext, fixture, imported, SectionAlerts))
	replayPlan := planOrFail(testContext, fixture, imported, SectionAlerts)
	report := applyOrFail(testContext, fixture, replayPlan)
	if len(fixture.pushedAlerts) != 2 || len(replayPlan.Alerts) != 0 || report.Sections[0].Applied != 0 {
		testContext.Errorf("the replay must push nothing, got %d pushes and %+v", len(fixture.pushedAlerts), replayPlan.Alerts)
	}
	if replayPlan.SkippedCounts[SectionAlerts][ReasonDuplicate] != 2 {
		testContext.Errorf("every replayed alert must be a duplicate, got %v", replayPlan.SkippedCounts)
	}
}

func TestAlertImportSkipsInvalidAndRecentAlerts(testContext *testing.T) {
	fixture := newImportFixture()
	withoutScenario := importedAlertFrom("203.0.113.80", 0)
	withoutScenario.Scenario = "\x00"
	badDate := importedAlertFrom("203.0.113.81", 0)
	badDate.StopAt = "yesterday"
	// A stop_at this close to now would leave the 1 s marker decision active for a moment.
	recent := importedAlertFrom("203.0.113.82", 0)
	recent.StopAt = importTestTime.Add(-10 * time.Second).Format(time.RFC3339)
	plan := planOrFail(testContext, fixture, alertsBundle(withoutScenario, badDate, recent, importedAlertFrom("203.0.113.83", 0)), SectionAlerts)
	if !slices.Equal(plannedAlertValues(plan), []string{"203.0.113.83"}) {
		testContext.Errorf("only the valid alert may be planned, got %v", plannedAlertValues(plan))
	}
	if skippedReason(plan, "203.0.113.80") != ReasonInvalid || skippedReason(plan, "203.0.113.81") != ReasonInvalid || skippedReason(plan, "203.0.113.82") != ReasonTooRecent {
		testContext.Errorf("unexpected skip reasons %+v", plan.Skipped)
	}
}

func TestAlertImportSharesTheAllowlistReadWithDecisions(testContext *testing.T) {
	fixture := newImportFixture()
	imported := Bundle{Format: Format, Version: Version, Sections: Sections{
		Decisions: &DecisionsSection{Decisions: []Decision{banUntil("203.0.113.90", time.Hour)}},
		Alerts:    &AlertsSection{Alerts: []lapi.Alert{importedAlertFrom("203.0.113.91", 0)}},
	}}
	plan := planOrFail(testContext, fixture, imported, SectionDecision, SectionAlerts)
	if fixture.allowlists.reads != 1 {
		testContext.Errorf("one preview must read the allowlists once for both sections, got %d reads", fixture.allowlists.reads)
	}
	applyOrFail(testContext, fixture, plan)
	if fixture.allowlists.reads != 1 {
		testContext.Errorf("the apply rechecks on the planned snapshot, got %d reads", fixture.allowlists.reads)
	}
}

func TestAlertImportDigestCoversThePlannedAlerts(testContext *testing.T) {
	fixture := newImportFixture()
	firstPlan := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.95", 0), importedAlertFrom("203.0.113.96", 0)), SectionAlerts)
	reordered := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.96", 0), importedAlertFrom("203.0.113.95", 0)), SectionAlerts)
	if firstPlan.Digest != reordered.Digest {
		testContext.Errorf("the digest must not depend on the bundle order")
	}
	if changed := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.95", 0)), SectionAlerts); changed.Digest == firstPlan.Digest {
		testContext.Errorf("a different set of alerts must change the digest")
	}
}

func TestAlertImportHonoursConfigLocalOverride(testContext *testing.T) {
	configDir := testContext.TempDir()
	writeConfig := func(name, content string) {
		if writeError := os.WriteFile(filepath.Join(configDir, name), []byte(content), 0o600); writeError != nil {
			testContext.Fatal(writeError)
		}
	}
	writeConfig("config.yaml", "db_config:\n  flush:\n    max_items: 1000\n")
	// CrowdSec merges config.yaml.local over config.yaml: its lower value must win.
	writeConfig("config.yaml.local", "db_config:\n  flush:\n    max_items: 20\n")
	fixture := newImportFixture()
	fixture.configDir = configDir
	for alertIndex := range 16 {
		fixture.localAlerts = append(fixture.localAlerts, importedAlertFrom(fmt.Sprintf("198.51.100.%d", alertIndex+1), 0))
	}
	overflowing := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.30", 0), importedAlertFrom("203.0.113.31", 0), importedAlertFrom("203.0.113.32", 0)), SectionAlerts)
	if overflowing.UnavailableCodes[SectionAlerts] != ErrorCodeFlushLimit {
		testContext.Errorf("the .local max_items must lower the threshold, got %+v", overflowing)
	}
	writeConfig("config.yaml.local", "db_config: [unterminated\n")
	unreadable := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.30", 0)), SectionAlerts)
	if unreadable.UnavailableCodes[SectionAlerts] != ErrorCodeFlushConfigUnreadable {
		testContext.Errorf("an unparsable config.yaml.local must make the section unavailable, got %+v", unreadable)
	}
	writeConfig("config.yaml.local", "api:\n  server:\n    log_level: info\n")
	unrelatedOverride := planOrFail(testContext, fixture, alertsBundle(importedAlertFrom("203.0.113.30", 0), importedAlertFrom("203.0.113.31", 0), importedAlertFrom("203.0.113.32", 0)), SectionAlerts)
	if len(unrelatedOverride.Unavailable) != 0 {
		testContext.Errorf("a .local without max_items keeps the config.yaml value, got %+v", unrelatedOverride)
	}
}
