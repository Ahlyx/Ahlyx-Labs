package shared

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const limiterEntryTTL = 15 * time.Minute

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter holds bounded-lifetime per-client token buckets. Forwarding
// headers are considered only when the socket peer is an explicit trusted proxy.
type RateLimiter struct {
	mu          sync.Mutex
	ips         map[string]*ipLimiter
	limit       rate.Limit
	burst       int
	global      *rate.Limiter
	lastCleanup time.Time
}

func NewRateLimiter(r rate.Limit, burst int, global *rate.Limiter) *RateLimiter {
	return &RateLimiter{ips: make(map[string]*ipLimiter), limit: r, burst: burst, global: global}
}

func (rl *RateLimiter) get(ip string, now time.Time) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if now.Sub(rl.lastCleanup) >= time.Minute {
		for key, entry := range rl.ips {
			if now.Sub(entry.lastSeen) >= limiterEntryTTL {
				delete(rl.ips, key)
			}
		}
		rl.lastCleanup = now
	}
	if entry, ok := rl.ips[ip]; ok {
		entry.lastSeen = now
		return entry.limiter
	}
	limiter := rate.NewLimiter(rl.limit, rl.burst)
	rl.ips[ip] = &ipLimiter{limiter: limiter, lastSeen: now}
	return limiter
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rl.global != nil && !rl.global.Allow() {
			writeError(w, http.StatusTooManyRequests, "service is busy")
			return
		}
		ip := ClientIP(r)
		if !rl.get(ip, time.Now()).Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP accepts CF-Connecting-IP only after origin verification. A direct
// request, including one with a spoofed forwarding header, is keyed by its
// socket peer instead.
func ClientIP(r *http.Request) string {
	peer := remoteIP(r.RemoteAddr)
	if !OriginVerified(r) {
		if peer != nil {
			return peer.String()
		}
		return r.RemoteAddr
	}
	if client := net.ParseIP(r.Header.Get("CF-Connecting-IP")); client != nil {
		return client.String()
	}
	if peer == nil {
		return r.RemoteAddr
	}
	return peer.String()
}

func remoteIP(address string) net.IP {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	return net.ParseIP(host)
}
