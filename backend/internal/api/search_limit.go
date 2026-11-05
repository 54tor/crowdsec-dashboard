package api

import "net/http"

const (
	maxConcurrentSearches       = 4
	searchBusyRetryAfterSeconds = "1"
)

type searchLimiter struct {
	slots chan struct{}
}

func newSearchLimiter(capacity int) searchLimiter {
	return searchLimiter{slots: make(chan struct{}, capacity)}
}

func (limiter searchLimiter) tryAcquire() (func(), bool) {
	if limiter.slots == nil {
		return func() {}, true
	}
	select {
	case limiter.slots <- struct{}{}:
		return func() { <-limiter.slots }, true
	default:
		return nil, false
	}
}

func (limiter searchLimiter) admitSearch(responseWriter http.ResponseWriter, term string) (func(), bool) {
	if term == "" {
		return func() {}, true
	}
	releaseSlot, acquired := limiter.tryAcquire()
	if !acquired {
		responseWriter.Header().Set("Retry-After", searchBusyRetryAfterSeconds)
		writeError(responseWriter, http.StatusTooManyRequests, "search_busy")
		return nil, false
	}
	return releaseSlot, true
}
