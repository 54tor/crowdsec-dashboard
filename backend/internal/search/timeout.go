package search

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	QueryTimeout            = 5 * time.Second
	queryCanceledStatusCode = "57014"
)

func IsTimeout(queryError error) bool {
	if errors.Is(queryError, context.DeadlineExceeded) {
		return true
	}
	var postgresError *pgconn.PgError
	return errors.As(queryError, &postgresError) && postgresError.Code == queryCanceledStatusCode
}
