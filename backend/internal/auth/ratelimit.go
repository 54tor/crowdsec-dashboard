package auth

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxTrackedClients = 10000
	sweepInterval     = time.Minute
	ipv6PrefixBits    = 64
)

type LoginLimiter struct {
	mutex       sync.Mutex
	limit       rate.Limit
	burst       int
	limiterByIP map[string]*rate.Limiter
	global      *rate.Limiter
	lastSweep   time.Time
}

func NewLoginLimiter(attemptsPerMinutePerIP, attemptsPerMinuteGlobal int) *LoginLimiter {
	return &LoginLimiter{
		limit:       rate.Every(time.Minute / time.Duration(attemptsPerMinutePerIP)),
		burst:       attemptsPerMinutePerIP,
		limiterByIP: make(map[string]*rate.Limiter),
		global:      rate.NewLimiter(rate.Every(time.Minute/time.Duration(attemptsPerMinuteGlobal)), attemptsPerMinuteGlobal),
		lastSweep:   time.Now(),
	}
}

func (limiter *LoginLimiter) Allow(ip string) bool {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	limiter.sweepIfDue()
	clientKey := limiterKey(ip)
	clientLimiter, found := limiter.limiterByIP[clientKey]
	if !found {
		if len(limiter.limiterByIP) >= maxTrackedClients {
			return false
		}
		clientLimiter = rate.NewLimiter(limiter.limit, limiter.burst)
		limiter.limiterByIP[clientKey] = clientLimiter
	}
	if !clientLimiter.Allow() {
		return false
	}
	return limiter.global.Allow()
}

func (limiter *LoginLimiter) sweepIfDue() {
	if time.Since(limiter.lastSweep) < sweepInterval {
		return
	}
	limiter.lastSweep = time.Now()
	for clientKey, clientLimiter := range limiter.limiterByIP {
		if clientLimiter.Tokens() >= float64(limiter.burst) {
			delete(limiter.limiterByIP, clientKey)
		}
	}
}

func limiterKey(ip string) string {
	address, parseError := netip.ParseAddr(ip)
	if parseError != nil {
		return ip
	}
	address = address.Unmap()
	if address.Is6() {
		return netip.PrefixFrom(address, ipv6PrefixBits).Masked().String()
	}
	return address.String()
}
