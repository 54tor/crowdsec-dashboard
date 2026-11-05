package api

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/search"
)

func searchContext(parent context.Context, term string, timeout time.Duration) (context.Context, context.CancelFunc) {
	if term == "" {
		return parent, func() {}
	}
	if timeout <= 0 {
		timeout = search.QueryTimeout
	}
	return context.WithTimeout(parent, timeout)
}
