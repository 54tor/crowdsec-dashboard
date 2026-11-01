package archive

import (
	"testing"
	"time"
)

// Upstream timestamps come in two shapes: RFC 3339 (created_at, start_at, stop_at)
// and Go's time.String() layout for event timestamps ("2026-10-30 17:34:06 +0000
// UTC", captured from a real LAPI). Anything else, the zero time, and years outside
// 1..9999 once converted to UTC become NULL instead of failing the alert. A date in
// the future is kept as it is: engine clocks drift, the archive does not judge.
func TestParseUpstreamTimestamp(testContext *testing.T) {
	casesDeTest := []struct {
		name          string
		raw           string
		expectedValue *time.Time
	}{
		{name: "rfc3339", raw: "2026-10-30T17:34:06Z", expectedValue: timePointer(time.Date(2026, 10, 30, 17, 34, 6, 0, time.UTC))},
		{name: "rfc3339 with offset", raw: "2026-10-30T19:34:06+02:00", expectedValue: timePointer(time.Date(2026, 10, 30, 17, 34, 6, 0, time.UTC))},
		{name: "rfc3339 with nanoseconds", raw: "2026-10-30T17:34:06.123456789Z", expectedValue: timePointer(time.Date(2026, 10, 30, 17, 34, 6, 123456789, time.UTC))},
		{name: "go time string layout", raw: "2026-10-30 17:34:06 +0000 UTC", expectedValue: timePointer(time.Date(2026, 10, 30, 17, 34, 6, 0, time.UTC))},
		{name: "go layout with fraction", raw: "2026-10-30 17:34:06.5 +0000 UTC", expectedValue: timePointer(time.Date(2026, 10, 30, 17, 34, 6, 500000000, time.UTC))},
		{name: "future date kept", raw: "2099-01-01T00:00:00Z", expectedValue: timePointer(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))},
		{name: "empty", raw: "", expectedValue: nil},
		{name: "garbage", raw: "not a date", expectedValue: nil},
		{name: "zero time", raw: "0001-01-01T00:00:00Z", expectedValue: nil},
		{name: "year zero", raw: "0000-06-01T00:00:00Z", expectedValue: nil},
		{name: "offset pushes past year 9999", raw: "9999-12-31T23:00:00-05:00", expectedValue: nil},
		{name: "offset pulls before year 1", raw: "0001-01-01T01:00:00+02:00", expectedValue: nil},
	}
	for _, casDeTestCourant := range casesDeTest {
		testContext.Run(casDeTestCourant.name, func(subTest *testing.T) {
			obtainedValue := parseUpstreamTimestamp(casDeTestCourant.raw)
			if (obtainedValue == nil) != (casDeTestCourant.expectedValue == nil) {
				subTest.Fatalf("got %v, want %v", obtainedValue, casDeTestCourant.expectedValue)
			}
			if obtainedValue != nil && !obtainedValue.Equal(*casDeTestCourant.expectedValue) {
				subTest.Errorf("got %v, want %v", *obtainedValue, *casDeTestCourant.expectedValue)
			}
		})
	}
}

// decision_until is the dashboard clock at collection plus the remaining duration
// the LAPI reports; an expired (negative or zero) duration pins it to the collection
// time, an unreadable one leaves it NULL.
func TestDecisionUntil(testContext *testing.T) {
	collectedAt := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	casesDeTest := []struct {
		name          string
		rawDuration   string
		expectedValue *time.Time
	}{
		{name: "remaining duration", rawDuration: "27h59m59s", expectedValue: timePointer(collectedAt.Add(27*time.Hour + 59*time.Minute + 59*time.Second))},
		{name: "fractional seconds", rawDuration: "1.5s", expectedValue: timePointer(collectedAt.Add(1500 * time.Millisecond))},
		{name: "expired duration", rawDuration: "-3h0m0s", expectedValue: timePointer(collectedAt)},
		{name: "zero duration", rawDuration: "0s", expectedValue: timePointer(collectedAt)},
		{name: "unreadable duration", rawDuration: "forever", expectedValue: nil},
		{name: "overflowing duration", rawDuration: "99999999999h", expectedValue: nil},
	}
	for _, casDeTestCourant := range casesDeTest {
		testContext.Run(casDeTestCourant.name, func(subTest *testing.T) {
			obtainedValue := decisionUntil(casDeTestCourant.rawDuration, collectedAt)
			if (obtainedValue == nil) != (casDeTestCourant.expectedValue == nil) {
				subTest.Fatalf("got %v, want %v", obtainedValue, casDeTestCourant.expectedValue)
			}
			if obtainedValue != nil && !obtainedValue.Equal(*casDeTestCourant.expectedValue) {
				subTest.Errorf("got %v, want %v", *obtainedValue, *casDeTestCourant.expectedValue)
			}
		})
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}
