package allowlists

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

func TestListMarksEntriesWritableOnlyForLocal(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist(permanentItem("203.0.113.7")))

	localListing, localError := fixture.service.List(context.Background(), localEngineName)
	if localError != nil {
		testContext.Fatal(localError)
	}
	remoteListing, remoteError := fixture.service.List(context.Background(), remoteEngineName)
	if remoteError != nil {
		testContext.Fatal(remoteError)
	}

	if !localListing.Writable || remoteListing.Writable {
		testContext.Fatalf("expected local writable and remote read only, got %v %v", localListing.Writable, remoteListing.Writable)
	}
	if localListing.Engine != localEngineName || len(localListing.Allowlists) != 1 {
		testContext.Fatalf("unexpected local listing: %+v", localListing)
	}
	if localListing.Allowlists[0].Entries[0].Value != "203.0.113.7" {
		testContext.Fatalf("unexpected entries: %+v", localListing.Allowlists[0].Entries)
	}
}

func TestEntriesMarkExpiredAgainstNow(testContext *testing.T) {
	expiredItem := lapi.AllowlistItem{Value: "203.0.113.1", Expiration: referenceNow.Add(-time.Second).Format(time.RFC3339Nano)}
	expiringNowItem := lapi.AllowlistItem{Value: "203.0.113.2", Expiration: referenceNow.Format(time.RFC3339Nano)}
	fixture := newServiceFixture(testContext, trustedAllowlist(expiredItem, expiringNowItem))

	listing, listError := fixture.service.List(context.Background(), localEngineName)
	if listError != nil {
		testContext.Fatal(listError)
	}

	entries := listing.Allowlists[0].Entries
	if !entries[0].Expired || entries[1].Expired {
		testContext.Fatalf("expected only the first entry expired, got %+v", entries)
	}
	if entries[1].ExpiresAt == nil || !entries[1].ExpiresAt.Equal(referenceNow) {
		testContext.Fatalf("expected the expiration to be kept, got %+v", entries[1])
	}
}

func TestZeroTimeEntryIsShownPermanent(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist(permanentItem("203.0.113.7")))

	listing, listError := fixture.service.List(context.Background(), localEngineName)
	if listError != nil {
		testContext.Fatal(listError)
	}

	permanentEntry := listing.Allowlists[0].Entries[0]
	if permanentEntry.ExpiresAt != nil || permanentEntry.Expired {
		testContext.Fatalf("a zero-time expiration must read as permanent, got %+v", permanentEntry)
	}
}

func TestForeign404IsNotUnsupported(testContext *testing.T) {
	fixture := newServiceFixture(testContext)
	fixture.localLAPI.setFailure(http.StatusNotFound)

	_, listError := fixture.service.List(context.Background(), localEngineName)

	requireErrorIs(testContext, listError, lapi.ErrAllowlistsUnreadable)
}

func TestUnsupportedEngineRefusesWrites(testContext *testing.T) {
	fixture := newServiceFixture(testContext)
	fixture.localLAPI.setFailure(http.StatusNotFound)

	_, createError := fixture.service.Create(context.Background(), localEngineName, "trusted", "trusted hosts")

	requireErrorIs(testContext, createError, lapi.ErrAllowlistsUnreadable)
	if len(fixture.writer.calls) != 0 {
		testContext.Fatalf("an engine whose allowlists cannot be read must not be written, got %v", fixture.writer.calls)
	}
}

func TestDisabledEngineIsNotFound(testContext *testing.T) {
	_, client := startFakeLAPI(testContext)
	writer := &recordingWriter{}
	knownEngines := fakeEngines{"paused": {Name: "paused", IsLocal: true, Enabled: false}}
	service := NewService(knownEngines, fakeClients{"paused": client}, localOnlyTestWriters(writer), func() time.Time { return referenceNow })

	_, listError := service.List(context.Background(), "paused")
	_, createError := service.Create(context.Background(), "paused", "trusted", "trusted hosts")

	requireErrorIs(testContext, listError, engines.ErrEngineNotFound)
	requireErrorIs(testContext, createError, engines.ErrEngineNotFound)
	if len(writer.calls) != 0 {
		testContext.Fatalf("a disabled engine must not be written, got %v", writer.calls)
	}
}

func TestRemoteEngineIsReadOnly(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist())
	runner := &recordingRunner{}
	fixture.service.writers = localOnlyTestWriters(NewCscliWriter(cscli.NewLocalExecutor(runner)))

	_, addError := fixture.service.AddEntry(context.Background(), remoteEngineName, "trusted", EntryInput{Value: "203.0.113.7"})

	requireErrorIs(testContext, addError, ErrEngineReadOnly)
	if len(runner.argvs) != 0 || fixture.remoteLAPI.reads() != 0 {
		testContext.Fatalf("a read-only engine must stop before any read or cscli call, got %v", runner.argvs)
	}
}

func TestServiceUsesInjectedWriterForAnyEngine(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist())
	remoteWriter := &recordingWriter{applyTo: fixture.remoteLAPI}
	fixture.service.writers = fixedWriters{writer: remoteWriter, engineOK: func(engine engines.Engine) bool { return !engine.IsLocal }}

	result, addError := fixture.service.AddEntry(context.Background(), remoteEngineName, "trusted", EntryInput{Value: "203.0.113.7"})

	if addError != nil {
		testContext.Fatal(addError)
	}
	if len(remoteWriter.calls) != 1 || !result.Refreshed || !result.Listing.Writable {
		testContext.Fatalf("expected the injected writer to serve the remote engine, got %v %+v", remoteWriter.calls, result)
	}
}

func TestConsoleManagedAllowlistIsReadOnly(testContext *testing.T) {
	consoleAllowlist := trustedAllowlist(permanentItem("203.0.113.7"))
	consoleAllowlist.ConsoleManaged = true
	fixture := newServiceFixture(testContext, consoleAllowlist)

	_, addError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "203.0.113.8"})
	_, removeError := fixture.service.RemoveEntry(context.Background(), localEngineName, "trusted", "203.0.113.7")
	_, deleteError := fixture.service.Delete(context.Background(), localEngineName, "trusted")

	requireErrorIs(testContext, addError, ErrConsoleManaged)
	requireErrorIs(testContext, removeError, ErrConsoleManaged)
	requireErrorIs(testContext, deleteError, ErrConsoleManaged)
	if len(fixture.writer.calls) != 0 {
		testContext.Fatalf("a console-managed allowlist must not be written, got %v", fixture.writer.calls)
	}
}

func TestAddEntryRefusesInternetWideRanges(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist())
	for _, internetWideRange := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/7"} {
		entryInput := EntryInput{Value: internetWideRange, Confirm: internetWideRange}

		_, addError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", entryInput)

		requireErrorIs(testContext, addError, ErrPrefixTooWide)
	}
	if len(fixture.writer.calls) != 0 {
		testContext.Fatalf("an internet-wide range must never be written, got %v", fixture.writer.calls)
	}
}

func TestAddEntryWiderThanConfirmFloorNeedsRetypedValue(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist())
	runner := &recordingRunner{afterRun: func(argv []string) { fixture.localLAPI.addItem("trusted", argv[4]) }}
	fixture.service.writers = localOnlyTestWriters(NewCscliWriter(cscli.NewLocalExecutor(runner)))

	_, unconfirmedError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "198.51.100.0/23"})
	requireErrorIs(testContext, unconfirmedError, ErrConfirmationRequired)
	_, wrongConfirmationError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "198.51.100.0/23", Confirm: "198.51.100.0/24"})
	requireErrorIs(testContext, wrongConfirmationError, ErrConfirmationRequired)
	if len(runner.argvs) != 0 {
		testContext.Fatalf("an unconfirmed wide range must not reach cscli, got %v", runner.argvs)
	}

	confirmedInput := EntryInput{Value: "198.51.100.1/23", Confirm: "198.51.100.0/23", Expiration: "7d", Description: "partner range"}
	_, confirmedError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", confirmedInput)

	if confirmedError != nil {
		testContext.Fatal(confirmedError)
	}
	expectedArgv := []string{"cscli", "allowlists", "add", "trusted", "198.51.100.0/23", "--expiration=7d", "--comment=partner range"}
	if len(runner.argvs) != 1 || !slices.Equal(runner.argvs[0], expectedArgv) {
		testContext.Fatalf("expected %v, got %v", expectedArgv, runner.argvs)
	}
}

func TestAddEntryRefusesDuplicate(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist(permanentItem("203.0.113.7")))

	_, addError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "203.0.113.7/32"})

	requireErrorIs(testContext, addError, ErrEntryExists)
	if len(fixture.writer.calls) != 0 {
		testContext.Fatalf("a duplicate must not be written, got %v", fixture.writer.calls)
	}
}

func TestAddEntryRefusesUnknownAllowlist(testContext *testing.T) {
	fixture := newServiceFixture(testContext)

	_, addError := fixture.service.AddEntry(context.Background(), localEngineName, "missing", EntryInput{Value: "203.0.113.7"})

	requireErrorIs(testContext, addError, ErrAllowlistNotFound)
}

func TestAddEntryRefusesInvalidValue(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist())

	_, addError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "not-an-ip"})

	requireErrorIs(testContext, addError, ErrInvalid)
	if len(fixture.writer.calls) != 0 {
		testContext.Fatalf("an invalid value must not be written, got %v", fixture.writer.calls)
	}
}

func TestCreateRefusesExistingName(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist())

	_, createError := fixture.service.Create(context.Background(), localEngineName, "trusted", "again")

	requireErrorIs(testContext, createError, ErrAllowlistExists)
	if len(fixture.writer.calls) != 0 {
		testContext.Fatalf("an existing name must not be created again, got %v", fixture.writer.calls)
	}
}

func TestRemoveEntryRefusesUnknownValue(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist(permanentItem("203.0.113.7")))

	_, removeError := fixture.service.RemoveEntry(context.Background(), localEngineName, "trusted", "203.0.113.8")

	requireErrorIs(testContext, removeError, ErrEntryNotFound)
	if len(fixture.writer.calls) != 0 {
		testContext.Fatalf("an unknown value must not be removed, got %v", fixture.writer.calls)
	}
}

func TestWritesSucceedAndReturnRefreshedListing(testContext *testing.T) {
	fixture := newServiceFixture(testContext, trustedAllowlist(permanentItem("203.0.113.7")))
	backgroundContext := context.Background()

	createResult, createError := fixture.service.Create(backgroundContext, localEngineName, "partners", "partner hosts")
	_, addError := fixture.service.AddEntry(backgroundContext, localEngineName, "partners", EntryInput{Value: "2001:db8::1"})
	_, removeError := fixture.service.RemoveEntry(backgroundContext, localEngineName, "trusted", "203.0.113.7/32")
	deleteResult, deleteError := fixture.service.Delete(backgroundContext, localEngineName, "partners")

	for _, writeError := range []error{createError, addError, removeError, deleteError} {
		if writeError != nil {
			testContext.Fatal(writeError)
		}
	}
	if !createResult.Refreshed || len(createResult.Listing.Allowlists) != 2 {
		testContext.Fatalf("expected the created allowlist in the refreshed listing, got %+v", createResult)
	}
	if !deleteResult.Refreshed || len(deleteResult.Listing.Allowlists) != 1 || len(deleteResult.Listing.Allowlists[0].Entries) != 0 {
		testContext.Fatalf("unexpected listing after delete: %+v", deleteResult)
	}
}

// The probe showed cscli exits 0 on a duplicate value, an invalid IP and the
// removal of a missing value: the service must notice from its re-read that
// nothing changed. The writer below records the call but never applies it.
func silentFixture(testContext *testing.T, allowlists ...lapi.Allowlist) serviceFixture {
	testContext.Helper()
	fixture := newServiceFixture(testContext, allowlists...)
	fixture.writer.applyTo = nil
	return fixture
}

func TestAddEntryDetectsSilentCscliNoOp(testContext *testing.T) {
	fixture := silentFixture(testContext, trustedAllowlist())

	_, addError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "203.0.113.7"})

	requireErrorIs(testContext, addError, ErrWriteFailed)
}

func TestRemoveEntryDetectsSilentCscliNoOp(testContext *testing.T) {
	fixture := silentFixture(testContext, trustedAllowlist(permanentItem("203.0.113.7")))

	_, removeError := fixture.service.RemoveEntry(context.Background(), localEngineName, "trusted", "203.0.113.7")

	requireErrorIs(testContext, removeError, ErrWriteFailed)
}

func TestCreateDetectsSilentCscliNoOp(testContext *testing.T) {
	fixture := silentFixture(testContext)

	_, createError := fixture.service.Create(context.Background(), localEngineName, "trusted", "trusted hosts")

	requireErrorIs(testContext, createError, ErrWriteFailed)
}

func TestDeleteDetectsSilentCscliNoOp(testContext *testing.T) {
	fixture := silentFixture(testContext, trustedAllowlist())

	_, deleteError := fixture.service.Delete(context.Background(), localEngineName, "trusted")

	requireErrorIs(testContext, deleteError, ErrWriteFailed)
}

func TestAddEntrySucceedsWhenRefreshFails(testContext *testing.T) {
	fixture := silentFixture(testContext, trustedAllowlist())
	fixture.writer.afterWrite = func() { fixture.localLAPI.setFailure(http.StatusInternalServerError) }

	result, addError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "203.0.113.7"})

	if addError != nil {
		testContext.Fatalf("a failed re-read after a successful write is not an error, got %v", addError)
	}
	if result.Refreshed || len(fixture.writer.calls) != 1 {
		testContext.Fatalf("expected Refreshed=false after one write, got %+v %v", result, fixture.writer.calls)
	}
}

// oversizedAllowlist holds two entries more than the LAPI client keeps, so
// every read of it stays Truncated even after one removal, and the last entry
// is always cut off.
func oversizedAllowlist(lastValue string) lapi.Allowlist {
	const entriesKeptByClient = 10000
	items := make([]lapi.AllowlistItem, 0, entriesKeptByClient+2)
	for entryIndex := range entriesKeptByClient + 1 {
		filler := fmt.Sprintf("10.%d.%d.%d", entryIndex/65536, (entryIndex/256)%256, entryIndex%256)
		items = append(items, permanentItem(filler))
	}
	items = append(items, permanentItem(lastValue))
	return trustedAllowlist(items...)
}

func TestTruncatedReReadIsNotReportedVerified(testContext *testing.T) {
	addFixture := newServiceFixture(testContext, oversizedAllowlist("198.51.100.9"))
	removeFixture := newServiceFixture(testContext, oversizedAllowlist("203.0.113.7"))

	addResult, addError := addFixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "203.0.113.8"})
	removeResult, removeError := removeFixture.service.RemoveEntry(context.Background(), localEngineName, "trusted", "10.0.0.1")

	if addError != nil || removeError != nil {
		testContext.Fatalf("an unverifiable write is not an error, got %v %v", addError, removeError)
	}
	if addResult.Refreshed || removeResult.Refreshed {
		testContext.Fatalf("a truncated re-read must not be reported verified, got %v %v", addResult.Refreshed, removeResult.Refreshed)
	}
}

func TestRemoveEntryOnTruncatedReadLetsCscliDecide(testContext *testing.T) {
	fixture := newServiceFixture(testContext, oversizedAllowlist("203.0.113.7"))

	result, removeError := fixture.service.RemoveEntry(context.Background(), localEngineName, "trusted", "203.0.113.7")

	if removeError != nil {
		testContext.Fatalf("a value hidden by truncation must not be refused as unknown, got %v", removeError)
	}
	if len(fixture.writer.calls) != 1 || result.Refreshed {
		testContext.Fatalf("expected one cscli removal and an unverified result, got %v refreshed=%v", fixture.writer.calls, result.Refreshed)
	}
}

// A read over 4 MiB lists nothing: the allowlist named by a write may well
// exist, so the write is refused as unreadable, never as an unknown
// allowlist, and cscli is not called.
func TestWritesOnOversizedReadAreUnreadableNotNotFound(testContext *testing.T) {
	oversizedBody := "[" + strings.Repeat(" ", 4<<20+10) + "]"
	writesByName := map[string]func(service *Service) error{
		"delete": func(service *Service) error {
			_, writeError := service.Delete(context.Background(), localEngineName, "trusted")
			return writeError
		},
		"add entry": func(service *Service) error {
			_, writeError := service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "203.0.113.7"})
			return writeError
		},
		"remove entry": func(service *Service) error {
			_, writeError := service.RemoveEntry(context.Background(), localEngineName, "trusted", "203.0.113.7")
			return writeError
		},
	}
	for writeName, runWrite := range writesByName {
		fixture := newServiceFixture(testContext, trustedAllowlist())
		fixture.localLAPI.serveRawBody(oversizedBody)

		writeError := runWrite(fixture.service)

		if !errors.Is(writeError, lapi.ErrAllowlistsUnreadable) || errors.Is(writeError, ErrAllowlistNotFound) {
			testContext.Errorf("%s: expected an unreadable refusal, got %v", writeName, writeError)
		}
		if len(fixture.writer.calls) != 0 {
			testContext.Errorf("%s: cscli must not run, got %v", writeName, fixture.writer.calls)
		}
	}
}

func TestNewServiceDefaultsNilClockToNow(testContext *testing.T) {
	service := NewService(fakeEngines{}, fakeClients{}, localOnlyTestWriters(&recordingWriter{}), nil)

	if service.now == nil || time.Since(service.now()) > time.Minute {
		testContext.Fatal("a nil clock must default to time.Now")
	}
}

// failingEngineLookup stands for an engine repository whose database is down.
type failingEngineLookup struct{ failure error }

func (lookup failingEngineLookup) Get(_ context.Context, _ string) (engines.Engine, error) {
	return engines.Engine{}, lookup.failure
}

func TestEngineLookupFailureIsWrappedAndNeverWrites(testContext *testing.T) {
	databaseFailure := errors.New("database connection refused")
	writer := &recordingWriter{}
	service := NewService(failingEngineLookup{failure: databaseFailure}, fakeClients{}, localOnlyTestWriters(writer), func() time.Time { return referenceNow })

	_, listError := service.List(context.Background(), "local")
	_, addError := service.AddEntry(context.Background(), "local", "trusted", EntryInput{Value: "203.0.113.7"})

	for _, obtainedError := range []error{listError, addError} {
		requireErrorIs(testContext, obtainedError, ErrEngineLookupFailed)
		requireErrorIs(testContext, obtainedError, databaseFailure)
		if errors.Is(obtainedError, engines.ErrEngineNotFound) {
			testContext.Errorf("a lookup failure must not read as engine not found: %v", obtainedError)
		}
	}
	if len(writer.calls) != 0 {
		testContext.Fatalf("a failed engine lookup must not write, got %v", writer.calls)
	}
}
