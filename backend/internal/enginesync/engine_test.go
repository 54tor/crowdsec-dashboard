package enginesync

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/allowguard"
)

func readEngine(testContext *testing.T, fake *fakeEngineServer) Snapshot {
	testContext.Helper()
	engine := NewLAPIEngine(syncEngineFor("alpha", fake, nil), 5000, fixedNow)
	snapshot, readError := engine.Read(context.Background())
	if readError != nil {
		testContext.Fatalf("Read: %v", readError)
	}
	return snapshot
}

func TestLapiEngineReadAlwaysSetsAllowlistGuard(testContext *testing.T) {
	// Rule 19: the zero Guard lets everything through, so a reader that forgot the allowlist
	// read would leave an open guard. A 500 on the allowlist route must give an unavailable guard,
	// and the runner must then write nothing on that engine.
	fake := newFakeEngineServer(testContext)
	fake.setAllowlistResponse(http.StatusInternalServerError, "boom")
	snapshot := readEngine(testContext, fake)
	if fake.allowlistQueries == 0 {
		testContext.Fatal("Read never asked the engine for its allowlists")
	}
	if snapshot.Allowlist.Available() {
		testContext.Fatal("an allowlist route answering 500 must leave the guard unavailable")
	}
	if snapshot.State != ReadComplete {
		testContext.Errorf("the ban read is independent of the allowlist read, got state %d", snapshot.State)
	}

	source := newFakeEngineServer(testContext)
	source.addNative("203.0.113.10", "4h")
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", fake, nil), syncEngineFor("beta", source, nil))}, false)
	report := runOnce(testContext, runner, RunOptions{})
	if fake.writeCount() != 0 {
		testContext.Errorf("nothing may be written on an engine with unreadable allowlists, got %v", fake.postedValues())
	}
	if report.PerEngine["alpha"].BlockedReason != allowguard.ReasonAllowlistUnavailable {
		testContext.Errorf("expected alpha blocked allowlist_unavailable, got %+v", report.PerEngine["alpha"])
	}
}

func TestReadBuildsGuardFromAllowlists(testContext *testing.T) {
	fake := newFakeEngineServer(testContext)
	fake.allowlist("203.0.113.0/24")
	fake.addNative("198.51.100.7", "2h")
	snapshot := readEngine(testContext, fake)
	if !snapshot.Allowlist.Available() {
		testContext.Fatal("a readable allowlist gives an available guard")
	}
	if snapshot.Allowlist.Check(netip.MustParsePrefix("203.0.113.7/32")).Allowed {
		testContext.Error("an address inside the allowlisted range must be refused")
	}
	if !snapshot.Allowlist.Check(netip.MustParsePrefix("198.51.100.7/32")).Allowed {
		testContext.Error("an address outside the allowlist must be allowed")
	}
	if snapshot.DashboardMachineID != runnerDashboardAccount || len(snapshot.Bans) != 1 || snapshot.Bans[0].Target.String() != "198.51.100.7" {
		testContext.Errorf("unexpected snapshot %+v", snapshot)
	}
}

func TestReadFailsClosedOnAnyAllowlist404(parentTest *testing.T) {
	// Every 404 on /v1/allowlists is unreadable: a LAPI without the route, an empty body and a
	// foreign server alike give an unavailable guard and the engine is blocked, nothing written.
	notFoundBodies := map[string]string{
		"lapi_json_message": `{"message":"not found"}`,
		"empty_body":        "",
		"foreign_404":       "<html>404 page not found</html>",
	}
	for caseName, notFoundBody := range notFoundBodies {
		parentTest.Run(caseName, func(testContext *testing.T) {
			fake := newFakeEngineServer(testContext)
			fake.setAllowlistResponse(http.StatusNotFound, notFoundBody)
			if readEngine(testContext, fake).Allowlist.Available() {
				testContext.Fatal("a 404 on the allowlist route must leave the guard unavailable")
			}
			source := newFakeEngineServer(testContext)
			source.addNative("203.0.113.10", "4h")
			runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", fake, nil), syncEngineFor("beta", source, nil))}, false)
			report := runOnce(testContext, runner, RunOptions{})
			if fake.writeCount() != 0 || report.PerEngine["alpha"].BlockedReason != allowguard.ReasonAllowlistUnavailable {
				testContext.Errorf("expected alpha blocked with no write, got writes=%d report=%+v", fake.writeCount(), report.PerEngine["alpha"])
			}
		})
	}
}

func TestReadFailsClosedOnForeign404(testContext *testing.T) {
	fake := newFakeEngineServer(testContext)
	fake.setAllowlistResponse(http.StatusNotFound, "404 page not found")
	if readEngine(testContext, fake).Allowlist.Available() {
		testContext.Error("a foreign 404 must leave the guard unavailable")
	}
}

func TestReadMarksSnapshotFailedWhenBansUnreadable(testContext *testing.T) {
	fake := newFakeEngineServer(testContext)
	fake.setAlertsStatus(http.StatusInternalServerError)
	engine := NewLAPIEngine(syncEngineFor("alpha", fake, nil), 5000, fixedNow)
	snapshot, readError := engine.Read(context.Background())
	if readError == nil || snapshot.State != ReadFailed {
		testContext.Errorf("expected a failed read, got state=%d error=%v", snapshot.State, readError)
	}
}

func TestLapiEngineFormattingRedactsClient(testContext *testing.T) {
	engine := NewLAPIEngine(syncEngineFor("alpha", newFakeEngineServer(testContext), nil), 5000, fixedNow)
	for _, formatted := range []string{fmt.Sprint(engine), fmt.Sprintf("%+v", engine), fmt.Sprintf("%#v", engine)} {
		if strings.Contains(formatted, peerPassword) || !strings.Contains(formatted, "alpha") {
			testContext.Errorf("formatted engine must name the engine and hide credentials, got %q", formatted)
		}
	}
}
