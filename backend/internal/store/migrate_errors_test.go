package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A refused CREATE EXTENSION must stop startup with a message an operator can
// act on, while any other migration failure keeps its original error untouched.
func TestMigrateExplainsARefusedTrigramExtension(testContext *testing.T) {
	refusedError := fmt.Errorf("goose: %w", &pgconn.PgError{Code: "42501", Message: `permission denied to create extension "pg_trgm"`})

	describedError := describeMigrationError(refusedError)

	if !errors.Is(describedError, ErrTrigramExtensionUnavailable) {
		testContext.Errorf("described error = %v, want ErrTrigramExtensionUnavailable", describedError)
	}
	for _, expectedFragment := range []string{"pg_trgm", "docs/operations.md"} {
		if !strings.Contains(describedError.Error(), expectedFragment) {
			testContext.Errorf("described error = %q, want it to contain %q", describedError.Error(), expectedFragment)
		}
	}

	unrelatedError := fmt.Errorf("goose: %w", &pgconn.PgError{Code: "42P07", Message: "relation already exists"})
	if obtainedError := describeMigrationError(unrelatedError); obtainedError != unrelatedError {
		testContext.Errorf("unrelated error = %v, want the same error value unchanged", obtainedError)
	}
}
