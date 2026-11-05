package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/sidecarapi"
)

var everyBundleSection = []string{bundle.SectionHub, bundle.SectionDecision, bundle.SectionAlerts, bundle.SectionConfig}

const exportEverySectionBody = `{"sections":["hub","decisions","alerts","config"]}`

func decodeApplyReport(testContext *testing.T, fixture remoteBundleFixture, engineName string, sections []string, digest string) bundle.ApplyReport {
	testContext.Helper()
	response := fixture.applyOn(testContext, engineName, sections, digest)
	var applied importApplyResponse
	decodeResponse(testContext, response, &applied)
	return applied.Report
}

func sectionReportOf(testContext *testing.T, report bundle.ApplyReport, sectionName string) bundle.SectionReport {
	testContext.Helper()
	for _, sectionReport := range report.Sections {
		if sectionReport.Section == sectionName {
			return sectionReport
		}
	}
	testContext.Fatalf("no report for section %q in %+v", sectionName, report)
	return bundle.SectionReport{}
}

func expectCallsContain(testContext *testing.T, description string, obtainedCalls, expectedCalls []string) {
	testContext.Helper()
	for _, expectedCall := range expectedCalls {
		if !slices.Contains(obtainedCalls, expectedCall) {
			testContext.Errorf("%s: expected %q among %v", description, expectedCall, obtainedCalls)
		}
	}
}

func lapiCallsOf(fakeLAPI *bundleEngineLAPI) []string {
	calls := []string{}
	for _, recordedRequest := range fakeLAPI.requests() {
		calls = append(calls, recordedRequest.method+" "+recordedRequest.path)
	}
	return calls
}

func TestRemoteExportReadsEverySectionFromTheTarget(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)

	response := fixture.post(withEngine("/api/export", bundlePeerName), exportEverySectionBody)

	expectStatus(testContext, response, http.StatusOK)
	exported := decodeExportedBundle(testContext, response)
	expectCallsContain(testContext, "peer executor", fixture.peer.executor.commandNames(), []string{"hub_list", "version"})
	expectCallsContain(testContext, "peer LAPI", lapiCallsOf(fixture.peer.lapi), []string{"GET /v1/alerts"})
	expectCallsContain(testContext, "peer sidecar", fixture.peer.sidecar.calls(), []string{"GET " + sidecarapi.PathFiles, "GET " + sidecarapi.PathFilePrefix + "acquis.yaml"})
	fixture.expectLocalUntouched(testContext)
	fixture.otherPeer.expectUntouched(testContext, "the other peer")
	exportedFiles := exported.Sections.Config.Files
	if len(exportedFiles) != 1 || exportedFiles[0].Name != "acquis.yaml" || exportedFiles[0].Content != bundlePeerMaskedFile || !exported.Sections.Config.Redacted {
		testContext.Errorf("expected the peer's masked acquis.yaml only, got %+v", exported.Sections.Config)
	}
	if exported.EngineVersion != "v1.6.8" {
		testContext.Errorf("expected the peer's version, got %q", exported.EngineVersion)
	}
	expectedTarget := "engine=peer secrets=false sections=hub,decisions,alerts,config"
	if len(fixture.audit.events) != 1 || fixture.audit.events[0].action != audit.ActionBundleExported || fixture.audit.events[0].target != expectedTarget {
		testContext.Errorf("expected one export audit with %q, got %+v", expectedTarget, fixture.audit.events)
	}
}

func TestRemoteExportRefusesSecrets(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)

	response := fixture.post(withEngine("/api/export", bundlePeerName), `{"sections":["config"],"include_secrets":true,"confirm_secrets":"SECRETS"}`)

	expectError(testContext, response, http.StatusConflict, "remote_secrets_unsupported")
	fixture.peer.expectUntouched(testContext, "the peer")
	fixture.expectLocalUntouched(testContext)
	if len(fixture.audit.events) != 0 {
		testContext.Errorf("a refused export is not audited, got %+v", fixture.audit.events)
	}
	if releasedLock, acquired := fixture.lock.TryAcquire("probe"); acquired {
		releasedLock()
	} else {
		testContext.Errorf("the refusal must not keep the operation lock")
	}
}

// The handler refuses secrets before any read; this pins the second barrier:
// even a caller that skipped the handler never gets unmasked content from a
// sidecar, and the sidecar is not even asked.
func TestRemoteExportNeverReadsUnredactedContent(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	remoteDeps := remoteBundleExportDeps(fixture.peer.target)

	content, readError := remoteDeps.Config.ReadUnredacted(context.Background(), "acquis.yaml")
	_, exportError := bundle.Export(context.Background(), remoteDeps, bundle.ExportRequest{Sections: []string{bundle.SectionConfig}, IncludeSecrets: true})

	if !errors.Is(readError, bundle.ErrUnredactedUnavailable) || content != nil {
		testContext.Errorf("expected ErrUnredactedUnavailable, got %v and %q", readError, content)
	}
	if !errors.Is(exportError, bundle.ErrUnredactedUnavailable) {
		testContext.Errorf("an export asking for secrets must fail, got %v", exportError)
	}
	for _, sidecarCall := range fixture.peer.sidecar.calls() {
		if sidecarCall != "GET "+sidecarapi.PathFiles {
			testContext.Errorf("only the listing may reach the sidecar, got %q", sidecarCall)
		}
	}
}

func TestRemoteImportAppliesOnlyToTheTargetEngine(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	plan := fixture.previewOn(testContext, bundlePeerName, everyBundleSection)
	if len(plan.Unavailable) != 0 || len(plan.Hub) != 1 || len(plan.Decisions) != 1 || len(plan.Alerts) != 1 || len(plan.Config) != 1 {
		testContext.Fatalf("expected one action per section on the peer, got %+v", plan)
	}

	report := decodeApplyReport(testContext, fixture, bundlePeerName, everyBundleSection, plan.Digest)

	for _, sectionName := range everyBundleSection {
		if sectionReport := sectionReportOf(testContext, report, sectionName); sectionReport.Status != bundle.StatusApplied || sectionReport.Applied != 1 {
			testContext.Errorf("section %s: expected 1 applied, got %+v", sectionName, sectionReport)
		}
	}
	peerPushes := fixture.peer.lapi.pushes()
	if len(peerPushes) != 2 || !strings.Contains(peerPushes[0].body+peerPushes[1].body, bundleImportedBan) || !strings.Contains(peerPushes[0].body+peerPushes[1].body, bundleImportedAlertIP) {
		testContext.Errorf("the peer LAPI must receive the ban and the alert, got %+v", peerPushes)
	}
	expectCallsContain(testContext, "peer LAPI", lapiCallsOf(fixture.peer.lapi), []string{"GET /v1/allowlists", "GET /v1/alerts", "GET /v1/alerts/1"})
	expectCallsContain(testContext, "peer executor", fixture.peer.executor.commandNames(), []string{"hub_list", "collections_install"})
	expectCallsContain(testContext, "peer sidecar", fixture.peer.sidecar.calls(), []string{
		"GET " + sidecarapi.PathAcquisitionState, "GET " + sidecarapi.PathAcquisitionFilePrefix + bundleAcquisitionName,
		"GET " + sidecarapi.PathFlushMaxItems, "POST " + sidecarapi.PathConfigApply,
	})
	if appliedBodies := fixture.peer.sidecar.applies(); len(appliedBodies) != 1 || appliedBodies[0].Changes[0].Name != bundleAcquisitionName {
		testContext.Errorf("the peer sidecar must apply %s once, got %+v", bundleAcquisitionName, appliedBodies)
	}
	fixture.expectLocalUntouched(testContext)
	fixture.otherPeer.expectUntouched(testContext, "the other peer")
	expectedTarget := "engine=peer failed=0 hub=1 decisions=1 alerts=1 config=1 skipped=0"
	if len(fixture.audit.events) != 1 || fixture.audit.events[0].target != expectedTarget {
		testContext.Errorf("expected one import audit with %q, got %+v", expectedTarget, fixture.audit.events)
	}
}

func TestRemoteImportSkipsDecisionsWhenTargetAllowlistsAreUnreadable(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	fixture.peer.lapi.setAllowlistsStatus(http.StatusInternalServerError)
	decisionsOnly := []string{bundle.SectionDecision}

	plan := fixture.previewOn(testContext, bundlePeerName, decisionsOnly)
	applyResponse := fixture.applyOn(testContext, bundlePeerName, decisionsOnly, plan.Digest)

	if plan.UnavailableCodes[bundle.SectionDecision] != bundle.ErrorCodeAllowlistUnavailable || len(plan.Decisions) != 0 {
		testContext.Errorf("expected decisions unavailable with allowlist_unavailable, got %+v", plan)
	}
	expectError(testContext, applyResponse, http.StatusConflict, "section_unavailable")
	if peerPushes := fixture.peer.lapi.pushes(); len(peerPushes) != 0 {
		testContext.Errorf("no ban may reach the peer, got %+v", peerPushes)
	}
	fixture.expectLocalUntouched(testContext)
}

// refusedImportCase is one refusal the remote import must give exactly like
// the local one: the same request is sent without engine and with it.
type refusedImportCase struct {
	description string
	body        func(testContext *testing.T, fixture remoteBundleFixture, engineName string) string
	holdLock    bool
}

func TestRemoteImportUsesTheSameDigestAndLock(testContext *testing.T) {
	decisionsOnly := []string{bundle.SectionDecision}
	refusedCases := []refusedImportCase{
		{"missing IMPORT confirmation", func(caseTest *testing.T, _ remoteBundleFixture, _ string) string {
			return remoteImportBody(caseTest, importModeApply, decisionsOnly, "", "0000")
		}, false},
		{"wrong digest", func(caseTest *testing.T, _ remoteBundleFixture, _ string) string {
			return remoteImportBody(caseTest, importModeApply, decisionsOnly, importConfirmation, strings.Repeat("0", 64))
		}, false},
		{"empty digest", func(caseTest *testing.T, _ remoteBundleFixture, _ string) string {
			return remoteImportBody(caseTest, importModeApply, decisionsOnly, importConfirmation, "")
		}, false},
		{"held import lock", func(caseTest *testing.T, _ remoteBundleFixture, _ string) string {
			return remoteImportBody(caseTest, importModePreview, decisionsOnly, "", "")
		}, true},
	}
	for _, refusedCase := range refusedCases {
		testContext.Run(refusedCase.description, func(caseTest *testing.T) {
			localFixture := newRemoteBundleFixture(caseTest)
			remoteFixture := newRemoteBundleFixture(caseTest)
			if refusedCase.holdLock {
				releaseLocal, _ := localFixture.lock.TryAcquire(importLockName)
				defer releaseLocal()
				releaseRemote, _ := remoteFixture.lock.TryAcquire(importLockName)
				defer releaseRemote()
			}

			localResponse := localFixture.post("/api/import", refusedCase.body(caseTest, localFixture, ""))
			remoteResponse := remoteFixture.post(withEngine("/api/import", bundlePeerName), refusedCase.body(caseTest, remoteFixture, bundlePeerName))

			if localResponse.Code == http.StatusOK || remoteResponse.Code != localResponse.Code || remoteResponse.Body.String() != localResponse.Body.String() {
				caseTest.Errorf("expected the local refusal %d %q, got %d %q", localResponse.Code, localResponse.Body.String(), remoteResponse.Code, remoteResponse.Body.String())
			}
			remoteFixture.peer.expectNoWrite(caseTest, "the peer")
			remoteFixture.expectLocalUntouched(caseTest)
		})
	}
}

func TestRemoteImportDigestIsStableOnTheSameSidecar(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	configOnly := []string{bundle.SectionConfig}
	fixture.peer.sidecar.serveCurrentFile(sidecarapi.AcquisitionFileResponse{Exists: true, Digest: strings.Repeat("ab", 32), Content: []byte(bundleAcquisition)})

	firstPlan := fixture.previewOn(testContext, bundlePeerName, configOnly)
	secondPlan := fixture.previewOn(testContext, bundlePeerName, configOnly)
	report := decodeApplyReport(testContext, fixture, bundlePeerName, configOnly, firstPlan.Digest)

	if firstPlan.Digest == "" || firstPlan.Digest != secondPlan.Digest {
		testContext.Errorf("two previews of the same sidecar must give the same digest, got %q and %q", firstPlan.Digest, secondPlan.Digest)
	}
	if configReport := sectionReportOf(testContext, report, bundle.SectionConfig); configReport.Status != bundle.StatusApplied {
		testContext.Errorf("the previewed plan must apply, got %+v", configReport)
	}
}

func TestRemoteImportRefusesAPlanPreviewedOnAnotherEngine(testContext *testing.T) {
	// The hub plan is identical on both peers and on the local engine (the
	// collection is missing everywhere): only the engine binding in the digest
	// tells the previews apart.
	hubOnly := []string{bundle.SectionHub}
	previewEngines := map[string]string{"preview on peer, apply on other-peer": bundlePeerName, "preview locally, apply on other-peer": ""}
	for caseLabel, previewEngine := range previewEngines {
		testContext.Run(caseLabel, func(caseTest *testing.T) {
			fixture := newRemoteBundleFixture(caseTest)
			plan := fixture.previewOn(caseTest, previewEngine, hubOnly)

			response := fixture.applyOn(caseTest, bundleOtherPeerName, hubOnly, plan.Digest)

			expectError(caseTest, response, http.StatusConflict, "import_conflict")
			fixture.peer.expectNoWrite(caseTest, "the previewed peer")
			fixture.otherPeer.expectNoWrite(caseTest, "the other peer")
			if slices.Contains(fixture.localExecutor.commandNames(), "collections_install") {
				caseTest.Errorf("nothing may be installed locally, got %v", fixture.localExecutor.commandNames())
			}
		})
	}
	testContext.Run("preview on peer, apply locally", func(caseTest *testing.T) {
		fixture := newRemoteBundleFixture(caseTest)
		plan := fixture.previewOn(caseTest, bundlePeerName, hubOnly)

		response := fixture.applyOn(caseTest, "", hubOnly, plan.Digest)

		expectError(caseTest, response, http.StatusConflict, "import_conflict")
		fixture.peer.expectNoWrite(caseTest, "the previewed peer")
		if slices.Contains(fixture.localExecutor.commandNames(), "collections_install") {
			caseTest.Errorf("nothing may be installed locally, got %v", fixture.localExecutor.commandNames())
		}
	})
}

func TestRemotePreviewNeverShowsASecretOfTheTargetConfig(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	// A faulty sidecar that forgets to mask: the dashboard masks again.
	unmaskedCurrent := bundleAcquisition + "password: " + bundlePlantedSecret + "\n"
	fixture.peer.sidecar.serveCurrentFile(sidecarapi.AcquisitionFileResponse{Exists: true, Digest: strings.Repeat("ab", 32), Content: []byte(unmaskedCurrent)})

	response := fixture.post(withEngine("/api/import", bundlePeerName), remoteImportBody(testContext, importModePreview, []string{bundle.SectionConfig}, "", ""))

	expectStatus(testContext, response, http.StatusOK)
	previewBody := response.Body.String()
	if strings.Contains(previewBody, bundlePlantedSecret) || strings.Contains(previewBody, bundleImportedSecret) {
		testContext.Errorf("the preview leaked a secret: %s", previewBody)
	}
	if !strings.Contains(previewBody, `"change":"updated"`) {
		testContext.Errorf("an existing remote file is planned as updated, got %s", previewBody)
	}
}

func TestRemoteImportReportsTheConfigFailedWhenTheSidecarIsReadOnly(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	fixture.peer.sidecar.refuseApply(http.StatusForbidden, sidecarapi.ErrorResponse{Code: sidecarapi.CodeReadOnly})
	plan := fixture.previewOn(testContext, bundlePeerName, everyBundleSection)

	report := decodeApplyReport(testContext, fixture, bundlePeerName, everyBundleSection, plan.Digest)

	// Same semantics as a local config failure: the hub section ran before,
	// the config section failed, the later sections did not run.
	expectedStatuses := map[string]string{
		bundle.SectionHub:      bundle.StatusApplied,
		bundle.SectionConfig:   bundle.StatusFailed,
		bundle.SectionDecision: bundle.StatusNotRun,
		bundle.SectionAlerts:   bundle.StatusNotRun,
	}
	for sectionName, expectedStatus := range expectedStatuses {
		if sectionReport := sectionReportOf(testContext, report, sectionName); sectionReport.Status != expectedStatus {
			testContext.Errorf("section %s: expected %s, got %+v", sectionName, expectedStatus, sectionReport)
		}
	}
	if configReport := sectionReportOf(testContext, report, bundle.SectionConfig); configReport.ErrorCode != "sidecar_command_refused" || configReport.Failed != 0 || len(configReport.AffectedFiles) != 0 {
		testContext.Errorf("expected a refused config with nothing written, got %+v", configReport)
	}
	if peerPushes := fixture.peer.lapi.pushes(); len(peerPushes) != 0 {
		testContext.Errorf("no decision or alert may be written after the failure, got %+v", peerPushes)
	}
	fixture.expectLocalUntouched(testContext)
}

func TestRemoteImportReportsTheFilesLeftInconsistentBySidecar(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	fixture.peer.sidecar.refuseApply(http.StatusInternalServerError, sidecarapi.ErrorResponse{
		Code:          sidecarapi.CodeConfigInconsistent,
		Result:        &sidecarapi.ApplyResult{Created: []string{}, Updated: []string{}, Unchanged: []string{}},
		AffectedFiles: []string{bundleAcquisitionName},
	})
	configOnly := []string{bundle.SectionConfig}
	plan := fixture.previewOn(testContext, bundlePeerName, configOnly)

	report := decodeApplyReport(testContext, fixture, bundlePeerName, configOnly, plan.Digest)

	configReport := sectionReportOf(testContext, report, bundle.SectionConfig)
	if configReport.ErrorCode != bundle.ErrorCodeConfigInconsistent || !slices.Equal(configReport.AffectedFiles, []string{bundleAcquisitionName}) {
		testContext.Errorf("expected config_inconsistent naming %s, got %+v", bundleAcquisitionName, configReport)
	}
}

func TestBundleRoutesRefuseARemoteEngineWithoutEveryHandle(testContext *testing.T) {
	incompleteTargets := map[string]func(target engines.Target) engines.Target{
		"no sidecar": func(target engines.Target) engines.Target { target.Sidecar = nil; return target },
		"no client":  func(target engines.Target) engines.Target { target.Client = nil; return target },
	}
	for caseLabel, makeIncomplete := range incompleteTargets {
		testContext.Run(caseLabel, func(caseTest *testing.T) {
			fixture := newRemoteBundleFixture(caseTest)
			fixture.targets.targetsByName[bundlePeerName] = makeIncomplete(fixture.peer.target)

			exportResponse := fixture.post(withEngine("/api/export", bundlePeerName), exportEverySectionBody)
			previewResponse := fixture.post(withEngine("/api/import", bundlePeerName), remoteImportBody(caseTest, importModePreview, everyBundleSection, "", ""))

			expectError(caseTest, exportResponse, http.StatusConflict, "engine_has_no_sidecar")
			expectError(caseTest, previewResponse, http.StatusConflict, "engine_has_no_sidecar")
			fixture.peer.expectUntouched(caseTest, "the peer")
			fixture.expectLocalUntouched(caseTest)
		})
	}
}

func TestBundleRoutesResolveTheEngineLikeTheOtherWrites(testContext *testing.T) {
	refusedEngines := []struct {
		query          string
		expectedStatus int
		expectedCode   string
	}{
		{"?engine=unknown", http.StatusNotFound, "engine_not_found"},
		{"?engine=" + sidecarlessPeerName, http.StatusConflict, "engine_has_no_sidecar"},
		{"?engine=Bad_Name", http.StatusBadRequest, "invalid_request"},
		{"?engine=peer&engine=peer", http.StatusBadRequest, "invalid_request"},
	}
	for _, refusedEngine := range refusedEngines {
		testContext.Run(refusedEngine.query, func(caseTest *testing.T) {
			fixture := newRemoteBundleFixture(caseTest)

			exportResponse := fixture.post("/api/export"+refusedEngine.query, exportEverySectionBody)
			importResponse := fixture.post("/api/import"+refusedEngine.query, remoteImportBody(caseTest, importModePreview, everyBundleSection, "", ""))

			expectError(caseTest, exportResponse, refusedEngine.expectedStatus, refusedEngine.expectedCode)
			expectError(caseTest, importResponse, refusedEngine.expectedStatus, refusedEngine.expectedCode)
			fixture.peer.expectUntouched(caseTest, "the peer")
			fixture.expectLocalUntouched(caseTest)
		})
	}
}

func TestBundleRoutesRefuseATargetNamedAfterAnotherEngine(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)
	fixture.targets.targetsByName[bundlePeerName] = fixture.otherPeer.target

	exportResponse := fixture.post(withEngine("/api/export", bundlePeerName), exportEverySectionBody)
	importResponse := fixture.post(withEngine("/api/import", bundlePeerName), remoteImportBody(testContext, importModePreview, everyBundleSection, "", ""))

	expectError(testContext, exportResponse, http.StatusConflict, "engine_target_mismatch")
	expectError(testContext, importResponse, http.StatusConflict, "engine_target_mismatch")
	fixture.otherPeer.expectUntouched(testContext, "the other peer")
	fixture.expectLocalUntouched(testContext)
}

func TestBundleExportWithLocalEngineNameStaysLocal(testContext *testing.T) {
	fixture := newRemoteBundleFixture(testContext)

	response := fixture.post(withEngine("/api/export", engines.ReservedLocalName), `{"sections":["hub"]}`)

	expectStatus(testContext, response, http.StatusOK)
	if !slices.Contains(fixture.localExecutor.commandNames(), "hub_list") {
		testContext.Errorf("the local engine must be read, got %v", fixture.localExecutor.commandNames())
	}
	fixture.peer.expectUntouched(testContext, "the peer")
	if len(fixture.audit.events) != 1 || strings.Contains(fixture.audit.events[0].target, "engine=") {
		testContext.Errorf("the local audit target keeps its text, got %+v", fixture.audit.events)
	}
}
