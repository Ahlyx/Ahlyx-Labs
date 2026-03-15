package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

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
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		result, err := scanner.Scan(subnet)
		if err != nil {
			if errors.Is(err, scanner.ErrSubnetTooLarge) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}

// validateInput checks that the input is a valid CIDR or single IP and that
// CIDR ranges are not larger than /24.
func validateInput(input string) error {
	// Try CIDR.
	if _, network, err := net.ParseCIDR(input); err == nil {
		ones, _ := network.Mask.Size()
		if ones < 24 {
			return scanner.ErrSubnetTooLarge
		}
		return nil
	}

	// Try single IP.
	if net.ParseIP(input) != nil {
		return nil
	}

	return errors.New("invalid input: must be a valid IP address or CIDR range (e.g. 192.168.1.0/24)")
}

// NewScanHandlerWithRL wraps NewScanHandler with per-IP rate limiting.
// Convenience constructor used in main.go so rate limit config stays centralised.
func NewScanHandlerWithRL(rl *shared.RateLimiter) http.Handler {
	return rl.Middleware(NewScanHandler())
}
