package auth

import "testing"

func TestLoginLimiterBlocksSixthAttemptInOneMinute(testContext *testing.T) {
	limiter := NewLoginLimiter(5, 1000)

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
	limiter := NewLoginLimiter(1, 1000)

	limiter.Allow("198.51.100.1")

	if !limiter.Allow("198.51.100.2") {
		testContext.Error("another IP must have its own budget")
	}
}

func TestLoginLimiterGroupsIPv6By64(testContext *testing.T) {
	limiter := NewLoginLimiter(1, 1000)

	limiter.Allow("2001:db8:1:2::1")

	if limiter.Allow("2001:db8:1:2:ffff::9") {
		testContext.Error("same /64 must share a budget")
	}
	if !limiter.Allow("2001:db8:1:3::1") {
		testContext.Error("another /64 must have its own budget")
	}
}

func TestLoginLimiterTreatsMappedIPv4AsIPv4(testContext *testing.T) {
	limiter := NewLoginLimiter(1, 1000)

	limiter.Allow("198.51.100.1")

	if limiter.Allow("::ffff:198.51.100.1") {
		testContext.Error("mapped IPv4 must share the IPv4 budget")
	}
}

func TestGlobalLoginLimiterBlocksAcrossIPs(testContext *testing.T) {
	limiter := NewLoginLimiter(5, 3)

	for _, clientIP := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if !limiter.Allow(clientIP) {
			testContext.Fatalf("%s should be allowed", clientIP)
		}
	}
	if limiter.Allow("198.51.100.4") {
		testContext.Error("global budget must block a fourth distinct IP")
	}
}
