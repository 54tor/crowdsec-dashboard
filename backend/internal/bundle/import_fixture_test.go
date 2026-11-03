package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/lapi"
)

var importTestTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

var errInstallFailed = errors.New("install failed")

// fakeAllowlistReader stands for the local engine's client; reads counts the calls so a test can
// prove the allowlists were read once per preview and once per apply.
type fakeAllowlistReader struct {
	read      lapi.AllowlistRead
	readError error
	reads     int
}

func (reader *fakeAllowlistReader) ListAllowlists(context.Context) (lapi.AllowlistRead, error) {
	reader.reads++
	return reader.read, reader.readError
}

// importFixture is an in-memory local engine: installs and added decisions become visible to the
// next read, which is what makes a replayed apply observable as a no-op.
type importFixture struct {
	installedItems   []HubItem
	installedNames   []string
	installError     error
	allowlists       *fakeAllowlistReader
	localBans        []lapi.SyncDecision
	localBansPartial bool
	addedDecisions   []lapi.NewDecision
	addError         error
	shareRules       enginesync.Rules
	rulesUnavailable bool
	callerAddress    string
	now              time.Time
}

func newImportFixture() *importFixture {
	return &importFixture{
		installedItems: []HubItem{{Type: "collections", Name: "crowdsecurity/linux", Status: "enabled", Version: "0.4"}},
		allowlists:     &fakeAllowlistReader{read: lapi.AllowlistRead{Allowlists: []lapi.Allowlist{}}},
		shareRules:     enginesync.Rules{MaxChanges: 500, MinRemaining: 5 * time.Minute},
		callerAddress:  "198.51.100.7",
		now:            importTestTime,
	}
}

func (fixture *importFixture) deps() ImportDeps {
	return ImportDeps{
		ReadHub: func(context.Context) ([]HubItem, error) {
			return append([]HubItem(nil), fixture.installedItems...), nil
		},
		InstallCollection: func(_ context.Context, name string) error {
			if fixture.installError != nil {
				return fixture.installError
			}
			fixture.installedNames = append(fixture.installedNames, name)
			fixture.installedItems = append(fixture.installedItems, HubItem{Type: "collections", Name: name, Status: "enabled"})
			return nil
		},
		Allowlists: fixture.allowlists,
		ReadLocalBans: func(context.Context, int) ([]lapi.SyncDecision, bool, error) {
			return append([]lapi.SyncDecision(nil), fixture.localBans...), !fixture.localBansPartial, nil
		},
		AddDecision: func(_ context.Context, newDecision lapi.NewDecision) error {
			if fixture.addError != nil {
				return fixture.addError
			}
			fixture.addedDecisions = append(fixture.addedDecisions, newDecision)
			fixture.localBans = append(fixture.localBans, lapi.SyncDecision{Origin: "cscli", Scope: newDecision.Scope, Value: newDecision.Target, Scenario: newDecision.Scenario, Remaining: time.Hour})
			return nil
		},
		ShareRules: func(context.Context) (enginesync.Rules, bool) {
			return fixture.shareRules, !fixture.rulesUnavailable
		},
		IsCallerAddress: func(target string) bool {
			prefix, prefixError := netip.ParsePrefix(target)
			if prefixError != nil {
				address, addressError := netip.ParseAddr(target)
				return addressError == nil && address.String() == fixture.callerAddress
			}
			return prefix.Contains(netip.MustParseAddr(fixture.callerAddress))
		},
		Now: func() time.Time { return fixture.now },
	}
}

func banUntil(value string, remaining time.Duration) Decision {
	scope := "Ip"
	if strings.Contains(value, "/") {
		scope = "Range"
	}
	return Decision{Origin: "crowdsec", Type: "ban", Scope: scope, Value: value, Scenario: "crowdsecurity/ssh-bf", Until: importTestTime.Add(remaining)}
}

func decisionsBundle(decisions ...Decision) Bundle {
	return Bundle{Format: Format, Version: Version, Sections: Sections{Decisions: &DecisionsSection{Decisions: decisions}}}
}

func hubBundle(collections ...HubCollection) Bundle {
	return Bundle{Format: Format, Version: Version, Sections: Sections{Hub: &HubSection{Collections: collections}}}
}

func allowlistOf(values ...string) lapi.AllowlistRead {
	items := make([]lapi.AllowlistItem, 0, len(values))
	for _, value := range values {
		items = append(items, lapi.AllowlistItem{Value: value})
	}
	return lapi.AllowlistRead{Allowlists: []lapi.Allowlist{{Name: "operators", Items: items}}}
}

func planOrFail(testContext *testing.T, fixture *importFixture, imported Bundle, sections ...string) ImportPlan {
	testContext.Helper()
	plan, planError := PlanImport(context.Background(), fixture.deps(), imported, sections)
	if planError != nil {
		testContext.Fatalf("unexpected plan error %v", planError)
	}
	return plan
}

func skippedReason(plan ImportPlan, target string) string {
	for _, skippedItem := range plan.Skipped {
		if skippedItem.Target == target {
			return skippedItem.Reason
		}
	}
	return ""
}

func plannedValues(plan ImportPlan) []string {
	values := []string{}
	for _, decisionAction := range plan.Decisions {
		values = append(values, decisionAction.Value)
	}
	return values
}

// fakeLocalLAPIServer is a real HTTP LAPI double used with the real lapi.Client, so the rule 19
// tests exercise the actual allowlist read rather than a stub of it. alertWrites counts POSTs.
func fakeLocalLAPIServer(testContext *testing.T, allowlistStatus int) (*lapi.Client, *atomic.Int32) {
	testContext.Helper()
	alertWrites := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/v1/watchers/login":
			_ = json.NewEncoder(responseWriter).Encode(map[string]string{"token": "test-jwt", "expire": "2099-01-01T00:00:00Z"})
		case request.URL.Path == "/v1/allowlists":
			responseWriter.WriteHeader(allowlistStatus)
			_, _ = responseWriter.Write([]byte("[]"))
		case request.URL.Path == "/v1/alerts" && request.Method == http.MethodPost:
			alertWrites.Add(1)
			_, _ = responseWriter.Write([]byte(`["1"]`))
		case request.URL.Path == "/v1/alerts":
			_, _ = responseWriter.Write([]byte("[]"))
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}
	}))
	testContext.Cleanup(server.Close)
	return lapi.NewClient(server.URL, "dashboard", "test-password", nil), alertWrites
}
