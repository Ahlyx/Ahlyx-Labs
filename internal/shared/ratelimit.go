package shared

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter *rate.Limiter
}

// RateLimiter holds per-IP token buckets.
type RateLimiter struct {
	mu      sync.Mutex
	ips     map[string]*ipLimiter
	limit   rate.Limit
	burst   int
}

// NewRateLimiter creates a RateLimiter with the given rate and burst.
func NewRateLimiter(r rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		ips:   make(map[string]*ipLimiter),
		limit: r,
		burst: burst,
	}
}

func (rl *RateLimiter) get(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if v, ok := rl.ips[ip]; ok {
		return v.limiter
	}
	l := rate.NewLimiter(rl.limit, rl.burst)
	rl.ips[ip] = &ipLimiter{limiter: l}
	return l
}

// Middleware returns an http.Handler wrapper that enforces the rate limit.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.get(ip).Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the real client IP, respecting X-Forwarded-For for Render's proxy.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may be a comma-separated list; the first entry is the client.
		if idx := strings.Index(xff, ","); idx != -1 {
			xff = xff[:idx]
		}
		xff = strings.TrimSpace(xff)
		if xff != "" {
			return xff
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
