package sidecarclient

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/logtail"
	"crowdsec-dashboard/internal/sidecarserver"
)

func startLogSidecar(testContext *testing.T, withAllowedRoot bool) (configSidecar, string) {
	testContext.Helper()
	logsDir := testContext.TempDir()
	logPath := filepath.Join(logsDir, "access.log")
	writeFixtureFile(testContext, logPath, "first\nsecond\nthird\n")
	sidecar := startConfiguredSidecar(testContext, nil, nil, func(config *sidecarserver.Config, confDir string) {
		if withAllowedRoot {
			config.LogsAllowedRoots = []string{logsDir}
		}
		writeFixtureFile(testContext, filepath.Join(confDir, "acquis.yaml"), "filename: "+logPath+"\n")
	})
	return sidecar, logPath
}

func TestRemoteLogs_listentEtLisentLesLignesDUneSource(testContext *testing.T) {
	sidecar, logPath := startLogSidecar(testContext, true)
	ctx := context.Background()

	listing, listError := sidecar.client.ListLogSources(ctx)
	if listError != nil || len(listing.Sources) != 1 || listing.Sources[0].Label != logPath {
		testContext.Fatalf("unexpected listing %+v (%v)", listing, listError)
	}
	lines, readError := sidecar.client.ReadLogSource(ctx, listing.Sources[0].ID, 2)

	if readError != nil || len(lines.Lines) != 2 || lines.Lines[1] != "third" {
		testContext.Errorf("unexpected lines %+v (%v)", lines, readError)
	}
}

func TestRemoteLogs_mappentLesCodesVersLesErreursDeLogtail(testContext *testing.T) {
	disabledSidecar, _ := startLogSidecar(testContext, false)
	enabledSidecar, _ := startLogSidecar(testContext, true)
	ctx := context.Background()

	_, disabledError := disabledSidecar.client.ListLogSources(ctx)
	_, unknownError := enabledSidecar.client.ReadLogSource(ctx, strings.Repeat("0", 32), 5)

	if !errors.Is(disabledError, logtail.ErrLogsDisabled) {
		testContext.Errorf("expected ErrLogsDisabled, got %v", disabledError)
	}
	if !errors.Is(unknownError, logtail.ErrSourceNotFound) {
		testContext.Errorf("expected ErrSourceNotFound, got %v", unknownError)
	}
}

func TestRemoteLogs_refusentUnIdentifiantInvalideAvantEnvoi(testContext *testing.T) {
	sidecar, _ := startLogSidecar(testContext, true)

	_, readError := sidecar.client.ReadLogSource(context.Background(), "../etc", 5)

	if readError == nil {
		testContext.Fatal("expected an error")
	}
}
