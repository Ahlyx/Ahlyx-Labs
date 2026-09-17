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
	mu             sync.Mutex
	ips            map[string]*ipLimiter
	limit          rate.Limit
	burst          int
	trustedProxies []*net.IPNet
	global         *rate.Limiter
	lastCleanup    time.Time
}

func NewRateLimiter(r rate.Limit, burst int, trustedProxies []*net.IPNet, global *rate.Limiter) *RateLimiter {
	return &RateLimiter{ips: make(map[string]*ipLimiter), limit: r, burst: burst, trustedProxies: trustedProxies, global: global}
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
		ip := ClientIP(r, rl.trustedProxies)
		if !rl.get(ip, time.Now()).Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP returns the socket peer unless it belongs to a configured trusted
// proxy CIDR. Only then is CF-Connecting-IP accepted as the client identity.
func ClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	peer := remoteIP(r.RemoteAddr)
	if peer == nil || !isTrustedProxy(peer, trustedProxies) {
		if peer != nil {
			return peer.String()
		}
		return r.RemoteAddr
	}
	if client := net.ParseIP(r.Header.Get("CF-Connecting-IP")); client != nil {
		return client.String()
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

func isTrustedProxy(ip net.IP, proxies []*net.IPNet) bool {
	for _, proxy := range proxies {
		if proxy.Contains(ip) {
			return true
		}
	}
	return false
}
