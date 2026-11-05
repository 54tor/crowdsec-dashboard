package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A refused or missing pg_trgm extension must stop startup with a message an
// operator can act on: a privilege refusal only needs an owner to run CREATE
// EXTENSION, while a missing control file (0A000, 58P01) needs the contrib
// package installed first.
func TestMigrateExplainsARefusedTrigramExtension(testContext *testing.T) {
	describedCases := []struct {
		caseName          string
		postgresError     *pgconn.PgError
		expectedFragments []string
	}{
		{
			caseName:          "privilege refused",
			postgresError:     &pgconn.PgError{Code: "42501", Message: `permission denied to create extension "pg_trgm"`},
			expectedFragments: []string{"pg_trgm", "docs/operations.md", "CREATE EXTENSION pg_trgm;"},
		},
		{
			caseName:          "extension not available",
			postgresError:     &pgconn.PgError{Code: "0A000", Message: `extension "pg_trgm" is not available`},
			expectedFragments: []string{"pg_trgm", "docs/operations.md", "contrib package"},
		},
		{
			caseName:          "control file missing",
			postgresError:     &pgconn.PgError{Code: "58P01", Message: `could not open extension control file "/usr/share/postgresql/extension/pg_trgm.control"`},
			expectedFragments: []string{"pg_trgm", "docs/operations.md", "contrib package"},
		},
	}
	for _, describedCase := range describedCases {
		testContext.Run(describedCase.caseName, func(caseContext *testing.T) {
			describedError := describeMigrationError(fmt.Errorf("goose: %w", describedCase.postgresError))

			if !errors.Is(describedError, ErrTrigramExtensionUnavailable) {
				caseContext.Errorf("described error = %v, want ErrTrigramExtensionUnavailable", describedError)
			}
			for _, expectedFragment := range describedCase.expectedFragments {
				if !strings.Contains(describedError.Error(), expectedFragment) {
					caseContext.Errorf("described error = %q, want it to contain %q", describedError.Error(), expectedFragment)
				}
			}
		})
	}
}

// Any failure that is not about pg_trgm, including a privilege refusal on
// something else, must come back as the very same error value.
func TestMigrateKeepsUnrelatedErrorsUnchanged(testContext *testing.T) {
	unrelatedCases := []struct {
		caseName      string
		postgresError *pgconn.PgError
	}{
		{caseName: "relation already exists", postgresError: &pgconn.PgError{Code: "42P07", Message: "relation already exists"}},
		{caseName: "privilege refused elsewhere", postgresError: &pgconn.PgError{Code: "42501", Message: "permission denied for schema public"}},
	}
	for _, unrelatedCase := range unrelatedCases {
		testContext.Run(unrelatedCase.caseName, func(caseContext *testing.T) {
			unrelatedError := fmt.Errorf("goose: %w", unrelatedCase.postgresError)

			if obtainedError := describeMigrationError(unrelatedError); obtainedError != unrelatedError {
				caseContext.Errorf("unrelated error = %v, want the same error value unchanged", obtainedError)
			}
		})
	}
}
