package accounts

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

// testClock is a settable clock shared by a repository and its test, so
// deadlines (setup window, lock end) can be crossed without sleeping.
type testClock struct {
	mutex   sync.Mutex
	current time.Time
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

func newRepositoryWithClock(testContext *testing.T) (*Repository, *testClock) {
	testContext.Helper()
	clock := &testClock{current: referenceInstant}
	return NewRepositoryWithClock(storetest.New(testContext), clock.Now), clock
}

func newRepositoryWithClockAndAccount(testContext *testing.T) (*Repository, *testClock) {
	testContext.Helper()
	repository, clock := newRepositoryWithClock(testContext)
	// Seeded through the insert helper directly: the setup window is left
	// NULL so each test opens the window it needs.
	createError := repository.database.RunInTx(context.Background(), nil, func(ctx context.Context, transaction bun.Tx) error {
		_, insertError := insertPasswordAccount(ctx, transaction, validAccountName, "unused password hash", roleAdmin)
		return insertError
	})
	if createError != nil {
		testContext.Fatal(createError)
	}
	return repository, clock
}
