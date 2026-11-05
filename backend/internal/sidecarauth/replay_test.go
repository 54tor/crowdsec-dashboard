package sidecarauth

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// movableClock lets a test advance time between claims while the cache reads
// it through the injected now function.
type movableClock struct {
	mutex  sync.Mutex
	moment time.Time
}

func (clock *movableClock) now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	return clock.moment
}

func (clock *movableClock) set(moment time.Time) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.moment = moment
}

func TestReplayCacheForgetsExpiredTokens(testContext *testing.T) {
	clock := &movableClock{moment: signingTime}
	cache := NewReplayCache(DefaultReplayCapacity, clock.now)
	entryExpiry := signingTime.Add(60 * time.Second)

	expectAccepted(testContext, cache.Claim("a", entryExpiry))
	expectRefusal(testContext, cache.Claim("a", entryExpiry), CodeReplayed)

	// Still remembered at the exact expiry instant: the entry lives until it.
	clock.set(entryExpiry)
	expectRefusal(testContext, cache.Claim("a", entryExpiry), CodeReplayed)

	clock.set(signingTime.Add(61 * time.Second))
	expectAccepted(testContext, cache.Claim("a", signingTime.Add(121*time.Second)))
}

func TestReplayCacheRefusesWhenFull(testContext *testing.T) {
	clock := &movableClock{moment: signingTime}
	cache := NewReplayCache(2, clock.now)
	entryExpiry := signingTime.Add(60 * time.Second)

	expectAccepted(testContext, cache.Claim("a", entryExpiry))
	expectAccepted(testContext, cache.Claim("b", entryExpiry))
	expectRefusal(testContext, cache.Claim("c", entryExpiry), CodeReplayCacheFull)

	// Fail closed: the refusal of "c" must not have evicted an unexpired entry,
	// otherwise a captured "a" or "b" could be replayed.
	expectRefusal(testContext, cache.Claim("a", entryExpiry), CodeReplayed)
	expectRefusal(testContext, cache.Claim("b", entryExpiry), CodeReplayed)

	clock.set(entryExpiry.Add(time.Second))
	expectAccepted(testContext, cache.Claim("c", entryExpiry.Add(time.Minute)))
}

func TestReplayCacheWithoutCapacityRefusesEveryToken(testContext *testing.T) {
	cache := NewReplayCache(0, fixedClock(signingTime))

	expectRefusal(testContext, cache.Claim("a", signingTime.Add(time.Minute)), CodeReplayCacheFull)
}

// newReplayCacheVerifier wires the real ReplayCache behind the Verifier, so the
// tests below observe the cache only through what Verify feeds it.
func newReplayCacheVerifier(trustedKey SigningKey, cache *ReplayCache) *Verifier {
	return NewVerifier(VerifierSettings{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Keys:      staticKeys{trustedKey.KeyID: trustedKey.secret.Public()},
		Replay:    cache,
		StartedAt: signingTime.Add(-time.Minute),
		Now:       fixedClock(signingTime),
	})
}

func TestVerifierFeedsTheReplayCacheOnlyAfterTheSignatureIsVerified(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	attackerKey := mustGenerateSigningKey(testContext)
	// The attacker signs with its own secret but announces the trusted kid.
	attackerKey.KeyID = trustedKey.KeyID
	cache := NewReplayCache(1, fixedClock(signingTime))
	verifier := newReplayCacheVerifier(trustedKey, cache)

	forgedToken := mustSign(testContext, newTestSigner(attackerKey), testMethod, testRequestURI, testBody)
	for attemptNumber := 0; attemptNumber < 3; attemptNumber++ {
		_, forgedError := verifier.Verify(AuthorizationPrefix+forgedToken, testMethod, testRequestURI)
		expectRefusal(testContext, forgedError, CodeInvalidToken)
	}

	// With a capacity of one, any forged jti stored above would make this
	// genuine token fail with replay_cache_full.
	genuineToken := mustSign(testContext, newTestSigner(trustedKey), testMethod, testRequestURI, testBody)
	_, genuineError := verifier.Verify(AuthorizationPrefix+genuineToken, testMethod, testRequestURI)
	expectAccepted(testContext, genuineError)

	_, replayError := verifier.Verify(AuthorizationPrefix+genuineToken, testMethod, testRequestURI)
	expectRefusal(testContext, replayError, CodeReplayed)
}

func TestVerifierReportsAFullReplayCache(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	cache := NewReplayCache(1, fixedClock(signingTime))
	verifier := newReplayCacheVerifier(trustedKey, cache)
	signer := newTestSigner(trustedKey)

	_, firstError := verifier.Verify(AuthorizationPrefix+mustSign(testContext, signer, testMethod, testRequestURI, testBody), testMethod, testRequestURI)
	expectAccepted(testContext, firstError)

	_, secondError := verifier.Verify(AuthorizationPrefix+mustSign(testContext, signer, testMethod, testRequestURI, testBody), testMethod, testRequestURI)
	expectRefusal(testContext, secondError, CodeReplayCacheFull)
}

func TestReplayCacheAcceptsExactlyOneOfConcurrentPresentations(testContext *testing.T) {
	const presentationCount = 64
	trustedKey := mustGenerateSigningKey(testContext)
	verifier := newReplayCacheVerifier(trustedKey, NewReplayCache(DefaultReplayCapacity, fixedClock(signingTime)))
	sharedToken := mustSign(testContext, newTestSigner(trustedKey), testMethod, testRequestURI, testBody)

	presentationErrors := make([]error, presentationCount)
	startSignal := make(chan struct{})
	var presenters sync.WaitGroup
	for presenterIndex := range presentationCount {
		presenters.Add(1)
		go func() {
			defer presenters.Done()
			<-startSignal
			_, presentationErrors[presenterIndex] = verifier.Verify(AuthorizationPrefix+sharedToken, testMethod, testRequestURI)
		}()
	}
	close(startSignal)
	presenters.Wait()

	acceptedCount := 0
	for _, presentationError := range presentationErrors {
		if presentationError == nil {
			acceptedCount++
			continue
		}
		var refusal *RefusalError
		if !errors.As(presentationError, &refusal) || refusal.Code != CodeReplayed {
			testContext.Fatalf("expected token_replayed for a concurrent replay, got %v", presentationError)
		}
	}
	if acceptedCount != 1 {
		testContext.Fatalf("expected exactly one accepted presentation, got %d", acceptedCount)
	}
}

func TestNewReplayCacheFallsBackToTheSystemClockWhenNoClockIsGiven(testContext *testing.T) {
	replayCache := NewReplayCache(1, nil)

	claimError := replayCache.Claim("token-1", time.Now().Add(time.Minute))

	if claimError != nil {
		testContext.Fatalf("Claim with the default clock: %v", claimError)
	}
}
