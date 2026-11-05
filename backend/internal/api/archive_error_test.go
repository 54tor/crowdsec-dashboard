package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
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

// A client that went away cancels the request context: nothing is written and
// nothing is logged, since nobody reads the answer.
func TestWriteArchiveErrorIgnoresAClientCancelledRequest(testContext *testing.T) {
	var capturedLog bytes.Buffer
	log.SetOutput(&capturedLog)
	testContext.Cleanup(func() { log.SetOutput(os.Stderr) })
	recorder := httptest.NewRecorder()

	writeArchiveError(recorder, "list archived alerts", fmt.Errorf("list: %w", context.Canceled))

	if recorder.Body.Len() != 0 || capturedLog.Len() != 0 {
		testContext.Errorf("a cancelled request writes and logs nothing, got body %q log %q", recorder.Body.String(), capturedLog.String())
	}
}
