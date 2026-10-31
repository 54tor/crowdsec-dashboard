package accounts

import (
	"context"
	"sync"
	"testing"
	"time"
)

var referenceInstant = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func accountIDOf(testContext *testing.T, repository *Repository, accountName string) int64 {
	testContext.Helper()
	var accountID int64
	if queryError := repository.database.NewRaw(`SELECT account_id FROM account WHERE account_name = ?`, accountName).
		Scan(context.Background(), &accountID); queryError != nil {
		testContext.Fatal(queryError)
	}
	return accountID
}

func reserveOrFail(testContext *testing.T, repository *Repository, accountID int64, now time.Time) SecondFactorReservation {
	testContext.Helper()
	reservation, reserveError := repository.ReserveSecondFactorAttempt(context.Background(), accountID, now)
	if reserveError != nil {
		testContext.Fatal(reserveError)
	}
	return reservation
}

func TestReserveSecondFactorAttemptLocksOnFifthReservation(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	accountID := accountIDOf(testContext, repository, validAccountName)

	for reservationNumber := 1; reservationNumber <= 4; reservationNumber++ {
		reservation := reserveOrFail(testContext, repository, accountID, referenceInstant)
		if !reservation.Reserved || reservation.LocksOnFailure {
			testContext.Fatalf("reservation %d: expected an unlocking reservation, got %+v", reservationNumber, reservation)
		}
	}
	fifthReservation := reserveOrFail(testContext, repository, accountID, referenceInstant)
	sixthReservation := reserveOrFail(testContext, repository, accountID, referenceInstant)

	expectedLockEnd := referenceInstant.Add(15 * time.Minute)
	if !fifthReservation.Reserved || !fifthReservation.LocksOnFailure || !fifthReservation.LockedUntil.Equal(expectedLockEnd) {
		testContext.Errorf("fifth reservation must be granted and lock until %v, got %+v", expectedLockEnd, fifthReservation)
	}
	if sixthReservation.Reserved || !sixthReservation.LockedUntil.Equal(expectedLockEnd) {
		testContext.Errorf("sixth reservation must be refused with the lock end, got %+v", sixthReservation)
	}
	lockedUntil, lockedError := repository.LockedUntil(context.Background(), accountID)
	if lockedError != nil || !lockedUntil.Equal(expectedLockEnd) {
		testContext.Errorf("LockedUntil: expected %v, got %v (%v)", expectedLockEnd, lockedUntil, lockedError)
	}
}

func TestReserveRefusesWhileLockedAndRestartsAfterExpiry(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	accountID := accountIDOf(testContext, repository, validAccountName)
	for reservationNumber := 1; reservationNumber <= 5; reservationNumber++ {
		reserveOrFail(testContext, repository, accountID, referenceInstant)
	}

	justBeforeExpiry := reserveOrFail(testContext, repository, accountID, referenceInstant.Add(15*time.Minute-time.Second))
	afterExpiry := reserveOrFail(testContext, repository, accountID, referenceInstant.Add(15*time.Minute))

	if justBeforeExpiry.Reserved {
		testContext.Errorf("a reservation inside the lock window must be refused, got %+v", justBeforeExpiry)
	}
	if !afterExpiry.Reserved || afterExpiry.LocksOnFailure {
		testContext.Fatalf("an expired lock must restart from zero, got %+v", afterExpiry)
	}
	var failedCount int
	if queryError := repository.database.NewRaw(`SELECT account_failed_second_factor_count FROM account WHERE account_id = ?`, accountID).
		Scan(context.Background(), &failedCount); queryError != nil {
		testContext.Fatal(queryError)
	}
	if failedCount != 1 {
		testContext.Errorf("expected the counter to restart at 1, got %d", failedCount)
	}
}

func TestReserveSecondFactorAttemptIsAtomicUnderConcurrency(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	accountID := accountIDOf(testContext, repository, validAccountName)
	const concurrentReservations = 20

	var waitGroup sync.WaitGroup
	var resultMutex sync.Mutex
	startSignal := make(chan struct{})
	grantedCount := 0
	for goroutineNumber := 0; goroutineNumber < concurrentReservations; goroutineNumber++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-startSignal
			reservation, reserveError := repository.ReserveSecondFactorAttempt(context.Background(), accountID, referenceInstant)
			if reserveError != nil {
				testContext.Error(reserveError)
				return
			}
			if reservation.Reserved {
				resultMutex.Lock()
				grantedCount++
				resultMutex.Unlock()
			}
		}()
	}
	close(startSignal)
	waitGroup.Wait()

	if grantedCount != 5 {
		testContext.Errorf("expected exactly 5 reservations out of %d, got %d", concurrentReservations, grantedCount)
	}
}

func TestResetSecondFactorFailuresClearsCountAndLock(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	accountID := accountIDOf(testContext, repository, validAccountName)
	for reservationNumber := 1; reservationNumber <= 5; reservationNumber++ {
		reserveOrFail(testContext, repository, accountID, referenceInstant)
	}

	if resetError := repository.ResetSecondFactorFailures(context.Background(), accountID); resetError != nil {
		testContext.Fatal(resetError)
	}

	lockedUntil, lockedError := repository.LockedUntil(context.Background(), accountID)
	if lockedError != nil || !lockedUntil.IsZero() {
		testContext.Errorf("expected no lock after reset, got %v (%v)", lockedUntil, lockedError)
	}
	for reservationNumber := 1; reservationNumber <= 4; reservationNumber++ {
		if reservation := reserveOrFail(testContext, repository, accountID, referenceInstant); !reservation.Reserved || reservation.LocksOnFailure {
			testContext.Fatalf("after a reset reservation %d must start a new count, got %+v", reservationNumber, reservation)
		}
	}
}

func TestSecondFactorSetupAllowedHonoursWindow(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	accountID := accountIDOf(testContext, repository, validAccountName)
	ctx := context.Background()
	windowCases := []struct {
		description   string
		columnValue   any
		expectAllowed bool
	}{
		{"no window", nil, false},
		{"window in the past", referenceInstant.Add(-time.Second), false},
		{"window in the future", referenceInstant.Add(time.Minute), true},
		{"window without end", "infinity", true},
	}
	for _, windowCase := range windowCases {
		if _, updateError := repository.database.ExecContext(ctx,
			`UPDATE account SET account_second_factor_setup_until = ?::timestamptz WHERE account_id = ?`, windowCase.columnValue, accountID); updateError != nil {
			testContext.Fatal(updateError)
		}

		isAllowed, allowedError := repository.SecondFactorSetupAllowed(ctx, accountID, referenceInstant)

		if allowedError != nil || isAllowed != windowCase.expectAllowed {
			testContext.Errorf("%s: expected %v, got %v (%v)", windowCase.description, windowCase.expectAllowed, isAllowed, allowedError)
		}
	}
}

func TestOpenSecondFactorSetupAllowsSetupUntilDeadline(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	accountID := accountIDOf(testContext, repository, validAccountName)
	ctx := context.Background()
	deadline := referenceInstant.Add(time.Hour)

	if openError := repository.OpenSecondFactorSetup(ctx, repository.database, accountID, deadline); openError != nil {
		testContext.Fatal(openError)
	}

	beforeDeadline, beforeError := repository.SecondFactorSetupAllowed(ctx, accountID, deadline.Add(-time.Second))
	atDeadline, atError := repository.SecondFactorSetupAllowed(ctx, accountID, deadline)
	if beforeError != nil || atError != nil || !beforeDeadline || atDeadline {
		testContext.Errorf("expected allowed before and refused at the deadline, got %v/%v (%v, %v)", beforeDeadline, atDeadline, beforeError, atError)
	}
}

func TestCloseSecondFactorSetupClearsWindowOnce(testContext *testing.T) {
	repository := newRepositoryWithAccount(testContext)
	accountID := accountIDOf(testContext, repository, validAccountName)
	ctx := context.Background()
	if openError := repository.OpenSecondFactorSetup(ctx, repository.database, accountID, referenceInstant.Add(time.Hour)); openError != nil {
		testContext.Fatal(openError)
	}

	firstCloseError := repository.CloseSecondFactorSetup(ctx, repository.database, accountID)
	secondCloseError := repository.CloseSecondFactorSetup(ctx, repository.database, accountID)

	if firstCloseError != nil {
		testContext.Fatalf("expected the open window to close, got %v", firstCloseError)
	}
	if secondCloseError != ErrSecondFactorSetupClosed {
		testContext.Errorf("a second close must report ErrSecondFactorSetupClosed, got %v", secondCloseError)
	}
	if isAllowed, _ := repository.SecondFactorSetupAllowed(ctx, accountID, referenceInstant); isAllowed {
		testContext.Error("the window must be closed")
	}
}
