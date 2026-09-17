package shared

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientIPIgnoresForwardedHeadersFromDirectPeer(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.test", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	req.Header.Set("CF-Connecting-IP", "9.10.11.12")
	if got := ClientIP(req, nil); got != "198.51.100.10" {
		t.Fatalf("ClientIP() = %q; want direct peer", got)
	}
}

func TestClientIPUsesCFHeaderOnlyForTrustedProxy(t *testing.T) {
	_, proxy, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.test", nil)
	req.RemoteAddr = "203.0.113.10:443"
	req.Header.Set("CF-Connecting-IP", "2001:4860:4860::8888")
	if got := ClientIP(req, []*net.IPNet{proxy}); got != "2001:4860:4860::8888" {
		t.Fatalf("ClientIP() = %q", got)
	}
}

func TestRateLimiterEvictsStaleEntries(t *testing.T) {
	rl := NewRateLimiter(1, 1, nil, nil)
	then := time.Now().Add(-limiterEntryTTL - time.Minute)
	rl.get("198.51.100.1", then)
	rl.get("198.51.100.2", time.Now())
	if _, ok := rl.ips["198.51.100.1"]; ok {
		t.Fatal("stale limiter entry was retained")
	}
}
