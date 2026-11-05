package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

var ErrTrigramExtensionUnavailable = errors.New("pg_trgm extension unavailable")

var extensionRefusalCodes = map[string]bool{
	"42501": true,
	"0A000": true,
	"58P01": true,
}

func describeMigrationError(upError error) error {
	if !isTrigramExtensionRefusal(upError) {
		return upError
	}
	return fmt.Errorf("%w: run CREATE EXTENSION pg_trgm; once as a database owner, see docs/operations.md: %w", ErrTrigramExtensionUnavailable, upError)
}

func isTrigramExtensionRefusal(upError error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(upError, &postgresError) {
		return false
	}
	return extensionRefusalCodes[postgresError.Code] && strings.Contains(postgresError.Message, "pg_trgm")
}
