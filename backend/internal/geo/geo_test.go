package geo

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type testClock struct {
	currentNanos atomic.Int64
}

func newTestClock() *testClock {
	clock := &testClock{}
	clock.currentNanos.Store(time.Now().UnixNano())
	return clock
}

func (clock *testClock) Now() time.Time { return time.Unix(0, clock.currentNanos.Load()) }

func (clock *testClock) Advance(duration time.Duration) {
	clock.currentNanos.Add(int64(duration))
}

func buildDatabase(testContext *testing.T, countryByPrefix map[string]string) []byte {
	testContext.Helper()
	writer, newError := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "GeoLite2-Country",
		IncludeReservedNetworks: true,
	})
	if newError != nil {
		testContext.Fatalf("mmdbwriter.New: %v", newError)
	}
	for prefix, countryCode := range countryByPrefix {
		_, network, parseError := net.ParseCIDR(prefix)
		if parseError != nil {
			testContext.Fatalf("parse %s: %v", prefix, parseError)
		}
		record := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(countryCode)}}
		if insertError := writer.Insert(network, record); insertError != nil {
			testContext.Fatalf("insert %s: %v", prefix, insertError)
		}
	}
	var buffer bytes.Buffer
	if _, writeError := writer.WriteTo(&buffer); writeError != nil {
		testContext.Fatalf("write database: %v", writeError)
	}
	return buffer.Bytes()
}

func replaceFileAtomically(testContext *testing.T, targetPath string, content []byte) {
	testContext.Helper()
	temporaryPath := targetPath + ".incoming"
	if writeError := os.WriteFile(temporaryPath, content, 0o600); writeError != nil {
		testContext.Fatalf("write incoming file: %v", writeError)
	}
	if renameError := os.Rename(temporaryPath, targetPath); renameError != nil {
		testContext.Fatalf("rename incoming file: %v", renameError)
	}
}

func newTestDatabase(testContext *testing.T) (string, *testClock, *MaxMindFile) {
	testContext.Helper()
	databasePath := filepath.Join(testContext.TempDir(), "country.mmdb")
	replaceFileAtomically(testContext, databasePath, buildDatabase(testContext, map[string]string{
		"192.0.2.0/24":  "FR",
		"2001:db8::/32": "DE",
	}))
	clock := newTestClock()
	return databasePath, clock, NewMaxMindFile(databasePath, clock.Now)
}

func TestCountryCodeReturnsISOCode(testContext *testing.T) {
	_, _, database := newTestDatabase(testContext)
	testCases := map[string]string{
		"192.0.2.1":        "FR",
		"2001:db8::1":      "DE",
		"::ffff:192.0.2.1": "FR",
	}
	for rawAddress, expectedCountry := range testCases {
		obtainedCountry, lookupError := database.CountryCode(context.Background(), netip.MustParseAddr(rawAddress))
		if lookupError != nil || obtainedCountry != expectedCountry {
			testContext.Errorf("%s: got %q, %v, want %q", rawAddress, obtainedCountry, lookupError, expectedCountry)
		}
	}
}

func TestCountryCodeReturnsUnknownForAddressOutsideDatabase(testContext *testing.T) {
	_, _, database := newTestDatabase(testContext)

	_, lookupError := database.CountryCode(context.Background(), netip.MustParseAddr("198.51.100.1"))

	if !errors.Is(lookupError, ErrCountryUnknown) {
		testContext.Fatalf("want ErrCountryUnknown, got %v", lookupError)
	}
}

func TestCountryCodeReturnsUnavailableWhenFileMissing(testContext *testing.T) {
	missingPath := filepath.Join(testContext.TempDir(), "absent.mmdb")
	clock := newTestClock()
	database := NewMaxMindFile(missingPath, clock.Now)

	_, lookupError := database.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))

	if !errors.Is(lookupError, ErrGeolocationUnavailable) {
		testContext.Fatalf("want ErrGeolocationUnavailable, got %v", lookupError)
	}
	if database.Available() {
		testContext.Error("a missing file must not be reported as available")
	}
	if _, hasAge := database.DatabaseAge(); hasAge {
		testContext.Error("a missing file has no age")
	}

	replaceFileAtomically(testContext, missingPath, buildDatabase(testContext, map[string]string{"192.0.2.0/24": "FR"}))
	clock.Advance(61 * time.Second)
	obtainedCountry, lookupError := database.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))
	if lookupError != nil || obtainedCountry != "FR" {
		testContext.Fatalf("file appearing later must be picked up, got %q, %v", obtainedCountry, lookupError)
	}
}

func TestUnavailableAlwaysRefuses(testContext *testing.T) {
	_, lookupError := Unavailable{}.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))

	if !errors.Is(lookupError, ErrGeolocationUnavailable) {
		testContext.Fatalf("want ErrGeolocationUnavailable, got %v", lookupError)
	}
}

func TestReaderPicksUpReplacedFile(testContext *testing.T) {
	databasePath, clock, database := newTestDatabase(testContext)
	replaceFileAtomically(testContext, databasePath, buildDatabase(testContext, map[string]string{
		"192.0.2.0/24":  "BE",
		"2001:db8::/32": "DE",
	}))

	stillCachedCountry, _ := database.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))
	if stillCachedCountry != "FR" {
		testContext.Fatalf("file must not be re-statted before one minute, got %q", stillCachedCountry)
	}

	clock.Advance(61 * time.Second)
	obtainedCountry, lookupError := database.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))
	if lookupError != nil || obtainedCountry != "BE" {
		testContext.Fatalf("want BE after replacement, got %q, %v", obtainedCountry, lookupError)
	}
}

func TestReaderKeepsServingWhenReplacementIsCorrupt(testContext *testing.T) {
	validContent := buildDatabase(testContext, map[string]string{"192.0.2.0/24": "FR"})
	corruptReplacements := map[string][]byte{
		"garbage":   []byte("this is not a maxmind database"),
		"truncated": validContent[:len(validContent)/2],
	}
	for replacementName, replacementContent := range corruptReplacements {
		databasePath, clock, database := newTestDatabase(testContext)
		replaceFileAtomically(testContext, databasePath, replacementContent)
		clock.Advance(61 * time.Second)

		obtainedCountry, lookupError := database.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))

		if lookupError != nil || obtainedCountry != "FR" {
			testContext.Errorf("%s: previous reader must keep serving, got %q, %v", replacementName, obtainedCountry, lookupError)
		}
	}
}

func TestConcurrentLookupsDuringReloadNeverCrash(testContext *testing.T) {
	databasePath, clock, database := newTestDatabase(testContext)
	stopLookups := make(chan struct{})
	var lookupGroup sync.WaitGroup
	for range 50 {
		lookupGroup.Add(1)
		go func() {
			defer lookupGroup.Done()
			for {
				select {
				case <-stopLookups:
					return
				default:
					database.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))
				}
			}
		}()
	}

	for replacementIndex := range 20 {
		countryCode := "BE"
		if replacementIndex%2 == 0 {
			countryCode = "FR"
		}
		replaceFileAtomically(testContext, databasePath, buildDatabase(testContext, map[string]string{"192.0.2.0/24": countryCode}))
		clock.Advance(61 * time.Second)
		time.Sleep(2 * time.Millisecond)
	}
	close(stopLookups)
	lookupGroup.Wait()

	if !database.Available() {
		testContext.Fatal("database must stay available")
	}
}

func TestDatabaseAgeReportsFileModTime(testContext *testing.T) {
	databasePath, clock, database := newTestDatabase(testContext)
	modificationTime := clock.Now().Add(-50 * 24 * time.Hour)
	if chtimesError := os.Chtimes(databasePath, modificationTime, modificationTime); chtimesError != nil {
		testContext.Fatalf("chtimes: %v", chtimesError)
	}
	clock.Advance(61 * time.Second)
	database.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))

	age, hasAge := database.DatabaseAge()

	expectedAge := 50*24*time.Hour + 61*time.Second
	if !hasAge || age != expectedAge {
		testContext.Fatalf("want %v, got %v (known=%v)", expectedAge, age, hasAge)
	}
}

type stubGeolocator struct {
	countryCode string
	lookupError error
	delay       time.Duration
	callCount   atomic.Int32
}

func (stub *stubGeolocator) CountryCode(ctx context.Context, _ netip.Addr) (string, error) {
	stub.callCount.Add(1)
	if stub.delay > 0 {
		select {
		case <-time.After(stub.delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return stub.countryCode, stub.lookupError
}

func TestChainFallsBackOnlyOnUnknown(testContext *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	testCases := map[string]struct {
		primaryError     error
		primaryCountry   string
		expectedFallback int32
		expectedCountry  string
		expectedError    error
	}{
		"unknown falls back":     {primaryError: ErrCountryUnknown, expectedFallback: 1, expectedCountry: "ES"},
		"found does not":         {primaryCountry: "FR", expectedFallback: 0, expectedCountry: "FR"},
		"unavailable is refused": {primaryError: ErrGeolocationUnavailable, expectedFallback: 0, expectedError: ErrGeolocationUnavailable},
	}
	for caseName, testCase := range testCases {
		primary := &stubGeolocator{countryCode: testCase.primaryCountry, lookupError: testCase.primaryError}
		fallback := &stubGeolocator{countryCode: "ES"}
		geolocator := NewChain(time.Second, primary, fallback)

		obtainedCountry, lookupError := geolocator.CountryCode(context.Background(), address)

		if obtainedCountry != testCase.expectedCountry || !errors.Is(lookupError, testCase.expectedError) {
			testContext.Errorf("%s: got %q, %v", caseName, obtainedCountry, lookupError)
		}
		if fallback.callCount.Load() != testCase.expectedFallback {
			testContext.Errorf("%s: fallback called %d times", caseName, fallback.callCount.Load())
		}
	}
}

func TestChainStopsSlowFallbackAfterTimeout(testContext *testing.T) {
	primary := &stubGeolocator{lookupError: ErrCountryUnknown}
	slowFallback := &stubGeolocator{countryCode: "ES", delay: 50 * time.Millisecond}
	geolocator := NewChain(5*time.Millisecond, primary, slowFallback)

	_, lookupError := geolocator.CountryCode(context.Background(), netip.MustParseAddr("192.0.2.1"))

	if !errors.Is(lookupError, ErrCountryUnknown) {
		testContext.Fatalf("a timed-out fallback must leave the country unknown, got %v", lookupError)
	}
}
