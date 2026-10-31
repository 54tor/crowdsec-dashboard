package oplock

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestLockSecondAcquireFailsUntilRelease(testContext *testing.T) {
	operationLock := New()

	releaseFirst, firstAcquired := operationLock.TryAcquire("sync")
	if !firstAcquired {
		testContext.Fatal("first acquire must succeed")
	}
	if holder := operationLock.Holder(); holder != "sync" {
		testContext.Fatalf("expected holder sync, got %q", holder)
	}
	_, secondAcquired := operationLock.TryAcquire("import")
	if secondAcquired {
		testContext.Fatal("second acquire must fail while the lock is held")
	}

	releaseFirst()

	if holder := operationLock.Holder(); holder != "" {
		testContext.Fatalf("expected no holder after release, got %q", holder)
	}
	releaseSecond, thirdAcquired := operationLock.TryAcquire("import")
	if !thirdAcquired {
		testContext.Fatal("acquire must succeed after release")
	}
	releaseSecond()
}

func TestLockReleaseIsIdempotent(testContext *testing.T) {
	operationLock := New()
	releaseFirst, _ := operationLock.TryAcquire("sync")
	releaseFirst()
	releaseSecond, secondAcquired := operationLock.TryAcquire("import")
	if !secondAcquired {
		testContext.Fatal("acquire after release must succeed")
	}

	releaseFirst()

	if holder := operationLock.Holder(); holder != "import" {
		testContext.Fatalf("stale release must not free the new holder, got %q", holder)
	}
	releaseSecond()
}

func TestLockConcurrentAcquireHasSingleWinner(testContext *testing.T) {
	operationLock := New()
	const contenderCount = 64
	var winnerCount atomic.Int32
	var startSignal sync.WaitGroup
	var finished sync.WaitGroup
	startSignal.Add(1)

	for contenderIndex := 0; contenderIndex < contenderCount; contenderIndex++ {
		finished.Add(1)
		go func() {
			defer finished.Done()
			startSignal.Wait()
			_, acquired := operationLock.TryAcquire("contender")
			if acquired {
				winnerCount.Add(1)
			}
		}()
	}
	startSignal.Done()
	finished.Wait()

	if winnerCount.Load() != 1 {
		testContext.Fatalf("expected exactly one winner, got %d", winnerCount.Load())
	}
}

func TestLockEmptyNameStillHolds(testContext *testing.T) {
	operationLock := New()

	releaseFirst, firstAcquired := operationLock.TryAcquire("")
	if !firstAcquired {
		testContext.Fatal("first acquire must succeed")
	}
	_, secondAcquired := operationLock.TryAcquire("import")
	if secondAcquired {
		testContext.Fatal("an empty name must still hold the lock")
	}

	releaseFirst()
	releaseSecond, thirdAcquired := operationLock.TryAcquire("")
	if !thirdAcquired {
		testContext.Fatal("acquire after release must succeed")
	}
	releaseFirst()
	_, fourthAcquired := operationLock.TryAcquire("import")
	if fourthAcquired {
		testContext.Fatal("a stale release must not free a later holder")
	}
	releaseSecond()
}
