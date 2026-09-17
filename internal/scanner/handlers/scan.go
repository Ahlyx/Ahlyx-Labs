package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/scanner"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// NewScanHandler returns an http.HandlerFunc for GET /api/v1/scanner/scan.
// Rate limiting is applied in main.go via middleware; no caching — results are live.
func NewScanHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subnet := r.URL.Query().Get("subnet")
		if subnet == "" {
			writeError(w, http.StatusBadRequest, "missing required query parameter: subnet")
			return
		}

		if err := validateInput(subnet); err != nil {
			if errors.Is(err, scanner.ErrOutOfScope) {
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		start := time.Now()

		result, err := scanner.Scan(subnet)
		if err != nil {
			if errors.Is(err, scanner.ErrSubnetTooLarge) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if errors.Is(err, scanner.ErrOutOfScope) {
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, result)
		openPorts := 0
		for _, h := range result.Hosts {
			openPorts += len(h.Ports)
		}
		shared.LogQuery("scanner", "tcp", "", false, 0, int(time.Since(start).Milliseconds()), result.HostsFound, openPorts)
	}
}

// validateInput checks that the input is a valid CIDR or single IP, that
// CIDR ranges are not larger than /24, and that the target is within an
// authorized (private/loopback/link-local) range.
func validateInput(input string) error {
	// Try CIDR.
	if _, network, err := net.ParseCIDR(input); err == nil {
		ones, _ := network.Mask.Size()
		if ones < 24 {
			return scanner.ErrSubnetTooLarge
		}
		if !scanner.InScope(network.IP) {
			return scanner.ErrOutOfScope
		}
		return nil
	}

	// Try single IP.
	if ip := net.ParseIP(input); ip != nil {
		if !scanner.InScope(ip) {
			return scanner.ErrOutOfScope
		}
		return nil
	}

	return errors.New("invalid input: must be a valid IP address or CIDR range (e.g. 192.168.1.0/24)")
}

// NewScanHandlerWithRL wraps NewScanHandler with per-IP rate limiting. It is
// retained for local callers; public deployments should use
// NewControlledScanHandler.
func NewScanHandlerWithRL(rl *shared.RateLimiter) http.Handler {
	return rl.Middleware(NewScanHandler())
}

// NewControlledScanHandler exposes scanning only to an isolated lab with a
// fixed, owner-supplied private CIDR allowlist. Special-use and non-private
// targets remain denied even if an allowlist is accidentally too broad.
func NewControlledScanHandler(rl *shared.RateLimiter, allowed []*net.IPNet) http.Handler {
	return rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subnet := r.URL.Query().Get("subnet")
		if subnet == "" {
			writeError(w, http.StatusBadRequest, "missing required query parameter: subnet")
			return
		}
		if err := validateControlledTarget(subnet, allowed); err != nil {
			writeError(w, http.StatusForbidden, "target is not available in this scanner lab")
			return
		}

		start := time.Now()
		result, err := scanner.Scan(subnet)
		if err != nil {
			writeError(w, http.StatusBadRequest, "scan request could not be processed")
			return
		}
		writeJSON(w, http.StatusOK, result)
		openPorts := 0
		for _, h := range result.Hosts {
			openPorts += len(h.Ports)
		}
		shared.LogQuery("scanner", "tcp", "", false, 0, int(time.Since(start).Milliseconds()), result.HostsFound, openPorts)
	}))
}

func validateControlledTarget(input string, allowed []*net.IPNet) error {
	if _, network, err := net.ParseCIDR(input); err == nil {
		ones, bits := network.Mask.Size()
		if bits != 32 || ones < 24 || !isPrivateLabIP(network.IP) {
			return scanner.ErrOutOfScope
		}
		last := lastIPv4(network)
		if !isPrivateLabIP(last) || !withinAllowed(network.IP, allowed) || !withinAllowed(last, allowed) {
			return scanner.ErrOutOfScope
		}
		return nil
	}

	ip := net.ParseIP(input)
	if ip == nil || !isPrivateLabIP(ip) || !withinAllowed(ip, allowed) {
		return scanner.ErrOutOfScope
	}
	return nil
}

func isPrivateLabIP(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4.IsPrivate() && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() && !ip4.IsUnspecified() && !ip4.IsMulticast()
}

func withinAllowed(ip net.IP, allowed []*net.IPNet) bool {
	for _, block := range allowed {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func lastIPv4(network *net.IPNet) net.IP {
	first := network.IP.To4()
	if first == nil {
		return nil
	}
	last := make(net.IP, net.IPv4len)
	for i := range last {
		last[i] = first[i] | ^network.Mask[i]
	}
	return last
}
