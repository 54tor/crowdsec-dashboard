package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/oplock"
)

// newConfigImportFixture enables config import on a temporary acquis.d mount whose
// `crowdsec -t` always fails, so the apply exercises the rollback path end to end.
func newConfigImportFixture(testContext *testing.T, importDirectory string) importFixture {
	testContext.Helper()
	fixture := newImportFixture(testContext, oplock.New())
	services := fixture.environment.services()
	services.Audit = fixture.recorder
	services.OperationLock = fixture.lock
	services.BundleImport = fixture.engine.deps(500)
	services.BundleImport.ConfigImportEnabled = true
	services.BundleImport.Acquisition = bundle.LocalAcquisition(importDirectory, func(context.Context) error {
		return errors.New("level=fatal msg=\"/etc/crowdsec/acquis.d/ssh.yaml: invalid\"")
	})
	fixture.handler = newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, services)
	return fixture
}

func configImportBody(testContext *testing.T, mode, confirm, digest string) string {
	testContext.Helper()
	imported := bundle.Bundle{Format: bundle.Format, Version: bundle.Version, CreatedAt: importTestTime, Sections: bundle.Sections{
		Config: &bundle.ConfigSection{Files: []bundle.ConfigFile{{Name: "acquis.d/ssh.yaml", Content: "source: journalctl\nlabels:\n  type: syslog\n"}}},
	}}
	encodedBundle, encodeError := json.Marshal(imported)
	if encodeError != nil {
		testContext.Fatalf("encode bundle: %v", encodeError)
	}
	envelope := map[string]any{"mode": mode, "bundle": json.RawMessage(encodedBundle), "sections": []string{bundle.SectionConfig}}
	if confirm != "" {
		envelope["confirm"], envelope["digest"] = confirm, digest
	}
	encodedEnvelope, _ := json.Marshal(envelope)
	return string(encodedEnvelope)
}

func TestImportConfigTestFailureAnswersStableCodeWithoutOutput(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	fixture := newConfigImportFixture(testContext, importDirectory)
	previewResponse := fixture.request(configImportBody(testContext, "preview", "", ""), fixture.environment.adminCookie, "")
	var plan bundle.ImportPlan
	if previewResponse.Code != http.StatusOK || json.Unmarshal(previewResponse.Body.Bytes(), &plan) != nil {
		testContext.Fatalf("preview: %d %q", previewResponse.Code, previewResponse.Body.String())
	}

	applyResponse := fixture.request(configImportBody(testContext, "apply", "IMPORT", plan.Digest), fixture.environment.adminCookie, "")

	if applyResponse.Code != http.StatusOK {
		testContext.Fatalf("apply: %d %q", applyResponse.Code, applyResponse.Body.String())
	}
	body := applyResponse.Body.String()
	if !strings.Contains(body, `"error_code":"config_test_failed"`) || strings.Contains(body, "/etc/crowdsec") {
		testContext.Errorf("expected the stable code only, got %s", body)
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, "ssh.yaml")); !errors.Is(statError, os.ErrNotExist) {
		testContext.Error("the created file must be rolled back")
	}
	events, _ := fixture.recorder.recorded()
	if len(events) != 1 || !strings.Contains(events[0].target, "config=0") || strings.Contains(events[0].target, "ssh") {
		testContext.Errorf("audit must count config files without naming them, got %+v", events)
	}
}

func TestSectionErrorCodeMapsConfigInconsistent(testContext *testing.T) {
	if obtainedCode := sectionErrorCode(bundle.ErrConfigInconsistent); obtainedCode != "config_inconsistent" {
		testContext.Errorf("expected config_inconsistent, got %s", obtainedCode)
	}
	if obtainedCode := sectionErrorCode(bundle.ErrConfigTestFailed); obtainedCode != "config_test_failed" {
		testContext.Errorf("expected config_test_failed, got %s", obtainedCode)
	}
	if obtainedCode := sectionErrorCode(bundle.ErrConcurrentChange); obtainedCode != "config_changed_concurrently" {
		testContext.Errorf("expected config_changed_concurrently, got %s", obtainedCode)
	}
	if obtainedCode := sectionErrorCode(bundle.ErrRecoveryPending); obtainedCode != "config_recovery_pending" {
		testContext.Errorf("expected config_recovery_pending, got %s", obtainedCode)
	}
}
