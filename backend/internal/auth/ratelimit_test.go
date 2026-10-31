package auth

import "testing"

func TestLoginLimiterBlocksSixthAttemptInOneMinute(testContext *testing.T) {
	limiter := NewLoginLimiter(5)

	for attemptNumber := 1; attemptNumber <= 5; attemptNumber++ {
		if !limiter.Allow("198.51.100.1") {
			testContext.Fatalf("attempt %d should be allowed", attemptNumber)
		}
	}
	if limiter.Allow("198.51.100.1") {
		testContext.Error("sixth attempt should be blocked")
	}
}

func TestLoginLimiterTracksIPsIndependently(testContext *testing.T) {
	limiter := NewLoginLimiter(1)

	limiter.Allow("198.51.100.1")

	if !limiter.Allow("198.51.100.2") {
		testContext.Error("another IP must have its own budget")
	}
}
