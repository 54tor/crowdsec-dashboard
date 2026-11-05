package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	hubReadDelay     time.Duration
	allowlists       *fakeAllowlistReader
	localBans        []lapi.SyncDecision
	localBansPartial bool
	addedDecisions   []lapi.NewDecision
	addError         error
	shareRules       enginesync.Rules
	rulesUnavailable bool
	callerAddress    string
	now              time.Time
	// Alerts section: localAlerts is what the engine stores; a push is echoed into it with a new
	// uuid, as the real LAPI does, so a replay sees its own previous push.
	localAlerts      []lapi.Alert
	localAlertsError error
	pushedAlerts     []lapi.Alert
	pushError        error
	// decisionOnPush stands for a profile: when it answers true the LAPI attaches an active
	// decision (of duration profileDuration) to the stored copy of the pushed alert.
	decisionOnPush     func(alert lapi.Alert) bool
	profileDuration    string
	storedMachineID    string
	getAlertError      error
	getAlertCalls      int
	deleteError        error
	deletedDecisionIDs []int64
	configDir          string
}

func newImportFixture() *importFixture {
	return &importFixture{
		installedItems:  []HubItem{{Type: "collections", Name: "crowdsecurity/linux", Status: "enabled", Version: "0.4"}},
		allowlists:      &fakeAllowlistReader{read: lapi.AllowlistRead{Allowlists: []lapi.Allowlist{}}},
		shareRules:      enginesync.Rules{MaxChanges: 500, MinRemaining: 5 * time.Minute},
		callerAddress:   "198.51.100.7",
		now:             importTestTime,
		profileDuration: "3h59m0s",
		storedMachineID: "dashboard",
	}
}

func (fixture *importFixture) deps() ImportDeps {
	return ImportDeps{
		ReadHub: func(ctx context.Context) ([]HubItem, error) {
			if fixture.hubReadDelay > 0 {
				select {
				case <-time.After(fixture.hubReadDelay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
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
			// The LAPI reports the remaining time at read time: the decision is read back slightly
			// shorter than written, which the replay must still recognise as a duplicate.
			writtenDuration, _ := time.ParseDuration(newDecision.Duration)
			readBackRemaining := writtenDuration - 700*time.Millisecond
			fixture.localBans = append(fixture.localBans, lapi.SyncDecision{Origin: "cscli", Scope: newDecision.Scope, Value: newDecision.Target, Scenario: newDecision.Scenario, Remaining: readBackRemaining})
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
		Now:               func() time.Time { return fixture.now },
		ReadLocalAlerts:   fixture.readLocalAlerts,
		PushImportedAlert: fixture.pushImportedAlert,
		GetAlert:          fixture.getAlert,
		DeleteDecision:    fixture.deleteDecision,
		Config:            LocalConfig(fixture.configDir),
		LocalMachineID:    "dashboard",
	}
}

func (fixture *importFixture) readLocalAlerts(_ context.Context, limit int, _ int64, _ time.Duration) (lapi.ArchiveRead, error) {
	if fixture.localAlertsError != nil {
		return lapi.ArchiveRead{}, fixture.localAlertsError
	}
	returnedAlerts := append([]lapi.Alert(nil), fixture.localAlerts...)
	limitReached := limit > 0 && len(returnedAlerts) >= limit
	if limitReached {
		returnedAlerts = returnedAlerts[:limit]
	}
	return lapi.ArchiveRead{Alerts: returnedAlerts, LimitReached: limitReached}, nil
}

func (fixture *importFixture) pushImportedAlert(_ context.Context, alert lapi.Alert) (int64, error) {
	if fixture.pushError != nil {
		return 0, fixture.pushError
	}
	fixture.pushedAlerts = append(fixture.pushedAlerts, alert)
	storedAlert := alert
	storedAlert.ID = int64(1000 + len(fixture.localAlerts))
	storedAlert.UUID = fmt.Sprintf("regenerated-%d", len(fixture.pushedAlerts))
	storedAlert.MachineID = fixture.storedMachineID
	storedAlert.Decisions = []lapi.Decision{{ID: storedAlert.ID*10 + 1, Origin: "cscli", Type: "ban", Duration: "-23h0m0s"}}
	if fixture.decisionOnPush != nil && fixture.decisionOnPush(alert) {
		storedAlert.Decisions = append(storedAlert.Decisions, lapi.Decision{ID: storedAlert.ID*10 + 2, Origin: "crowdsec", Type: "ban", Duration: fixture.profileDuration, Simulated: true})
	}
	fixture.localAlerts = append(fixture.localAlerts, storedAlert)
	return storedAlert.ID, nil
}

func (fixture *importFixture) getAlert(_ context.Context, alertID int64) (lapi.Alert, error) {
	fixture.getAlertCalls++
	if fixture.getAlertError != nil {
		return lapi.Alert{}, fixture.getAlertError
	}
	for _, localAlert := range fixture.localAlerts {
		if localAlert.ID == alertID {
			return localAlert, nil
		}
	}
	return lapi.Alert{}, lapi.ErrNotFound
}

func (fixture *importFixture) deleteDecision(_ context.Context, decisionID int64) error {
	if fixture.deleteError != nil {
		return fixture.deleteError
	}
	fixture.deletedDecisionIDs = append(fixture.deletedDecisionIDs, decisionID)
	return nil
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
		case request.URL.Path == "/v1/alerts/1":
			_, _ = responseWriter.Write([]byte(`{"id":1,"machine_id":"dashboard","decisions":[]}`))
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}
	}))
	testContext.Cleanup(server.Close)
	return lapi.NewClient(server.URL, "dashboard", "test-password", nil), alertWrites
}
