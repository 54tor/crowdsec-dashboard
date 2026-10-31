package login

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	clientAddress = netip.MustParseAddr("192.0.2.10")
	otherAddress  = netip.MustParseAddr("192.0.2.99")
)

type testClock struct {
	mutex   sync.Mutex
	current time.Time
}

func newTestClock() *testClock {
	return &testClock{current: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
}

func (clock *testClock) Now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	return clock.current
}

func (clock *testClock) Advance(duration time.Duration) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.current = clock.current.Add(duration)
}

func createPendingOrFail(testContext *testing.T, store *PendingStore, accountID int64) string {
	testContext.Helper()
	pendingID, createError := store.Create(Pending{AccountID: accountID, AccountName: "alice", Stage: StageSecondFactor, ClientIP: clientAddress})
	if createError != nil {
		testContext.Fatal(createError)
	}
	return pendingID
}

func TestPendingLoginExpiresAfterTTL(testContext *testing.T) {
	clock := newTestClock()
	store := NewPendingStore(5*time.Minute, 10, clock.Now)
	pendingID := createPendingOrFail(testContext, store, 1)

	clock.Advance(5*time.Minute - time.Second)
	lease, beforeExpiryError := store.Acquire(pendingID, clientAddress)
	if beforeExpiryError != nil {
		testContext.Fatalf("expected the entry to be valid before the TTL, got %v", beforeExpiryError)
	}
	lease.Release()
	clock.Advance(time.Second)
	_, afterExpiryError := store.Acquire(pendingID, clientAddress)

	if !errors.Is(afterExpiryError, ErrPendingLoginInvalid) {
		testContext.Errorf("expected ErrPendingLoginInvalid after the TTL, got %v", afterExpiryError)
	}
}

func TestPendingLoginIsBoundToClientIP(testContext *testing.T) {
	store := NewPendingStore(5*time.Minute, 10, newTestClock().Now)
	pendingID := createPendingOrFail(testContext, store, 1)

	_, otherAddressError := store.Acquire(pendingID, otherAddress)
	_, unknownIDError := store.Acquire("unknown", clientAddress)
	lease, sameAddressError := store.Acquire(pendingID, netip.MustParseAddr("::ffff:192.0.2.10"))

	if !errors.Is(otherAddressError, ErrPendingLoginInvalid) || !errors.Is(unknownIDError, ErrPendingLoginInvalid) {
		testContext.Errorf("expected ErrPendingLoginInvalid for another address and an unknown id, got %v / %v", otherAddressError, unknownIDError)
	}
	if sameAddressError != nil {
		testContext.Fatalf("the IPv4-mapped form of the same address must match, got %v", sameAddressError)
	}
	lease.Release()
}

func TestPendingLoginIsSingleUseUnderConcurrency(testContext *testing.T) {
	store := NewPendingStore(5*time.Minute, 10, newTestClock().Now)
	pendingID := createPendingOrFail(testContext, store, 1)
	const concurrentClaims = 10

	var waitGroup sync.WaitGroup
	var resultMutex sync.Mutex
	startSignal := make(chan struct{})
	leaseCount, invalidCount := 0, 0
	for goroutineNumber := 0; goroutineNumber < concurrentClaims; goroutineNumber++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-startSignal
			lease, acquireError := store.Acquire(pendingID, clientAddress)
			resultMutex.Lock()
			defer resultMutex.Unlock()
			if acquireError != nil {
				if errors.Is(acquireError, ErrPendingLoginInvalid) {
					invalidCount++
				}
				return
			}
			leaseCount++
			lease.Consume()
		}()
	}
	close(startSignal)
	waitGroup.Wait()

	if leaseCount != 1 || invalidCount != concurrentClaims-1 {
		testContext.Errorf("expected 1 lease and %d refusals, got %d leases and %d refusals", concurrentClaims-1, leaseCount, invalidCount)
	}
}

func TestSlowHolderDoesNotBlockOtherPendingLogins(testContext *testing.T) {
	store := NewPendingStore(5*time.Minute, 10, newTestClock().Now)
	heldID := createPendingOrFail(testContext, store, 1)
	otherID := createPendingOrFail(testContext, store, 2)
	heldLease, heldError := store.Acquire(heldID, clientAddress)
	if heldError != nil {
		testContext.Fatal(heldError)
	}
	defer heldLease.Release()

	completed := make(chan error, 1)
	go func() {
		otherLease, otherError := store.Acquire(otherID, clientAddress)
		if otherError != nil {
			completed <- otherError
			return
		}
		otherLease.Release()
		_, createError := store.Create(Pending{AccountID: 3, Stage: StageSecondFactor, ClientIP: clientAddress})
		completed <- createError
	}()

	select {
	case otherError := <-completed:
		if otherError != nil {
			testContext.Fatal(otherError)
		}
	case <-time.After(50 * time.Millisecond):
		testContext.Fatal("a held lease on one entry blocked another entry or Create")
	}
}

func TestPendingStoreRefusesBeyondCapacity(testContext *testing.T) {
	clock := newTestClock()
	store := NewPendingStore(5*time.Minute, 2, clock.Now)
	createPendingOrFail(testContext, store, 1)
	createPendingOrFail(testContext, store, 2)

	_, fullError := store.Create(Pending{AccountID: 3, ClientIP: clientAddress})
	clock.Advance(5 * time.Minute)
	_, afterPruneError := store.Create(Pending{AccountID: 3, ClientIP: clientAddress})

	if !errors.Is(fullError, ErrPendingStoreFull) {
		testContext.Errorf("expected ErrPendingStoreFull, got %v", fullError)
	}
	if afterPruneError != nil {
		testContext.Errorf("expired entries must be pruned on Create, got %v", afterPruneError)
	}
}

func TestReleasedLeaseCanBeAcquiredAgainButConsumedCannot(testContext *testing.T) {
	store := NewPendingStore(5*time.Minute, 10, newTestClock().Now)
	pendingID := createPendingOrFail(testContext, store, 1)

	firstLease, firstError := store.Acquire(pendingID, clientAddress)
	if firstError != nil {
		testContext.Fatal(firstError)
	}
	firstLease.Pending().Attempts++
	firstLease.Release()
	secondLease, secondError := store.Acquire(pendingID, clientAddress)
	if secondError != nil {
		testContext.Fatal(secondError)
	}
	attemptsSeen := secondLease.Pending().Attempts
	secondLease.Consume()
	_, consumedError := store.Acquire(pendingID, clientAddress)

	if attemptsSeen != 1 {
		testContext.Errorf("changes made under a lease must persist, got %d attempts", attemptsSeen)
	}
	if !errors.Is(consumedError, ErrPendingLoginInvalid) {
		testContext.Errorf("a consumed entry must be invalid, got %v", consumedError)
	}
}
