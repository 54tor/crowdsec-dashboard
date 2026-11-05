package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestWriteArchiveErrorMapsQueryCancellationToSearchTimeout(testContext *testing.T) {
	casesByName := map[string]struct {
		archiveError error
		expectedCode string
	}{
		"context deadline":       {archiveError: fmt.Errorf("list: %w", context.DeadlineExceeded), expectedCode: "search_timeout"},
		"statement cancelled":    {archiveError: fmt.Errorf("list: %w", &pgconn.PgError{Code: "57014"}), expectedCode: "search_timeout"},
		"other database failure": {archiveError: errors.New("broken"), expectedCode: "database_unavailable"},
	}

	for caseName, currentCase := range casesByName {
		testContext.Run(caseName, func(subtestContext *testing.T) {
			recorder := httptest.NewRecorder()

			writeArchiveError(recorder, "list archived alerts", currentCase.archiveError)

			expectError(subtestContext, recorder, http.StatusServiceUnavailable, currentCase.expectedCode)
		})
	}
}
