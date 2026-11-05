package bundle

import (
	"context"
	"errors"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// These tests pin the fail-closed behaviour when a caller forgets to wire a
// configuration reader: before the guards a nil ConfigReader panicked.

func TestAlertImportWithoutConfigReaderIsUnavailable(testContext *testing.T) {
	fixture := newImportFixture()
	depsWithoutConfig := fixture.deps()
	depsWithoutConfig.Config = nil

	plan, planError := PlanImport(context.Background(), depsWithoutConfig, alertsBundle(importedAlertFrom("203.0.113.40", 0)), []string{SectionAlerts})

	if planError != nil {
		testContext.Fatalf("expected an unavailable section, got error %v", planError)
	}
	if obtainedCode := plan.UnavailableCodes[SectionAlerts]; obtainedCode != ErrorCodeFlushConfigUnreadable {
		testContext.Errorf("expected %q, got %q (%+v)", ErrorCodeFlushConfigUnreadable, obtainedCode, plan)
	}
	if len(plan.Alerts) != 0 {
		testContext.Errorf("no alert may be planned without the flush limit, got %+v", plan.Alerts)
	}
}

func TestConfigExportWithoutConfigReaderFailsWithAClearError(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{})
	deps.Config = nil

	exported, exportError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionConfig}})

	if !errors.Is(exportError, ErrConfigUnavailable) {
		testContext.Errorf("expected ErrConfigUnavailable, got %v", exportError)
	}
	if exported.Sections.Config != nil {
		testContext.Errorf("no config section may be returned, got %+v", exported.Sections.Config)
	}
}
