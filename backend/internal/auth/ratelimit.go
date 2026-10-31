package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const pruneThreshold = 4096

type LoginLimiter struct {
	mutex       sync.Mutex
	limit       rate.Limit
	burst       int
	limiterByIP map[string]*rate.Limiter
}

func NewLoginLimiter(attemptsPerMinute int) *LoginLimiter {
	return &LoginLimiter{
		limit:       rate.Every(time.Minute / time.Duration(attemptsPerMinute)),
		burst:       attemptsPerMinute,
		limiterByIP: make(map[string]*rate.Limiter),
	}
}

func (limiter *LoginLimiter) Allow(ip string) bool {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	if len(limiter.limiterByIP) > pruneThreshold {
		limiter.pruneRefilled()
	}
	ipLimiter, found := limiter.limiterByIP[ip]
	if !found {
		ipLimiter = rate.NewLimiter(limiter.limit, limiter.burst)
		limiter.limiterByIP[ip] = ipLimiter
	}
	return ipLimiter.Allow()
}

func (limiter *LoginLimiter) pruneRefilled() {
	for ip, ipLimiter := range limiter.limiterByIP {
		if ipLimiter.Tokens() >= float64(limiter.burst) {
			delete(limiter.limiterByIP, ip)
		}
	}
}
