package search

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A search ends as a timeout when its context deadline passed (even wrapped) or
// when PostgreSQL cancelled the statement (SQLSTATE 57014, query_canceled); a
// lost connection or any other failure stays a plain database error.
func TestIsTimeoutRecognisesDeadlineAndCancelledStatement(testContext *testing.T) {
	timeoutCases := []struct {
		name            string
		queryError      error
		expectedTimeout bool
	}{
		{name: "wrapped deadline", queryError: fmt.Errorf("list: %w", context.DeadlineExceeded), expectedTimeout: true},
		{name: "cancelled statement", queryError: fmt.Errorf("q: %w", &pgconn.PgError{Code: "57014"}), expectedTimeout: true},
		{name: "connection failure", queryError: &pgconn.PgError{Code: "08006"}, expectedTimeout: false},
		{name: "other error", queryError: errors.New("other"), expectedTimeout: false},
		{name: "no error", queryError: nil, expectedTimeout: false},
	}
	for _, timeoutCase := range timeoutCases {
		if obtainedTimeout := IsTimeout(timeoutCase.queryError); obtainedTimeout != timeoutCase.expectedTimeout {
			testContext.Errorf("%s: IsTimeout(%v) = %v, want %v",
				timeoutCase.name, timeoutCase.queryError, obtainedTimeout, timeoutCase.expectedTimeout)
		}
	}
}
