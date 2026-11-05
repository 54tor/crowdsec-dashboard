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
	undefinedObjectCode       = "42704"
	trigramExtensionMarker    = "pg_trgm"
	trigramOperatorMarker     = "gin_trgm_ops"
	installContribRemedy      = "install the PostgreSQL contrib package that ships pg_trgm, then run CREATE EXTENSION pg_trgm; as an owner"
)

type trigramRefusal struct {
	messageMarker string
	remedy        string
}

var trigramRefusalByCode = map[string]trigramRefusal{
	insufficientPrivilegeCode: {messageMarker: trigramExtensionMarker, remedy: "run CREATE EXTENSION pg_trgm; once in the dashboard database as an owner"},
	featureNotSupportedCode:   {messageMarker: trigramExtensionMarker, remedy: installContribRemedy},
	undefinedFileCode:         {messageMarker: trigramExtensionMarker, remedy: installContribRemedy},
	undefinedObjectCode:       {messageMarker: trigramOperatorMarker, remedy: "pg_trgm must be installed in a schema on the search_path, e.g. public (ALTER EXTENSION pg_trgm SET SCHEMA public;)"},
}

func describeMigrationError(upError error) error {
	var postgresError *pgconn.PgError
	if !errors.As(upError, &postgresError) {
		return upError
	}
	refusal, isRefusalCode := trigramRefusalByCode[postgresError.Code]
	if !isRefusalCode || !strings.Contains(postgresError.Message, refusal.messageMarker) {
		return upError
	}
	return fmt.Errorf("%w: %s, see docs/operations.md: %w", ErrTrigramExtensionUnavailable, refusal.remedy, upError)
}
