package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

var ErrTrigramExtensionUnavailable = errors.New("pg_trgm extension unavailable")

const (
	insufficientPrivilegeCode = "42501"
	featureNotSupportedCode   = "0A000"
	undefinedFileCode         = "58P01"
)

var remedyByRefusalCode = map[string]string{
	insufficientPrivilegeCode: "run CREATE EXTENSION pg_trgm; once in the dashboard database as an owner",
	featureNotSupportedCode:   "install the PostgreSQL contrib package that ships pg_trgm, then run CREATE EXTENSION pg_trgm; as an owner",
	undefinedFileCode:         "install the PostgreSQL contrib package that ships pg_trgm, then run CREATE EXTENSION pg_trgm; as an owner",
}

func describeMigrationError(upError error) error {
	var postgresError *pgconn.PgError
	if !errors.As(upError, &postgresError) {
		return upError
	}
	remedy, isRefusalCode := remedyByRefusalCode[postgresError.Code]
	mentionsTrigramExtension := strings.Contains(postgresError.Message, "pg_trgm")
	if !isRefusalCode || !mentionsTrigramExtension {
		return upError
	}
	return fmt.Errorf("%w: %s, see docs/operations.md: %w", ErrTrigramExtensionUnavailable, remedy, upError)
}
