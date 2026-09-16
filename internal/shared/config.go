package shared

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all environment-sourced configuration for the whole server.
type Config struct {
	Port                  string
	AbuseIPDBKey          string
	VirusTotalKey         string
	IPInfoKey             string
	OTXKey                string
	GoogleSafeBrowsingKey string
	URLScanKey            string
	// ServerScannerEnabled is deliberately opt-in. A public backend must not
	// connect to visitor-selected network targets unless it is an isolated,
	// owner-controlled lab deployment.
	ServerScannerEnabled bool
	// ServerScannerAllowedTargets is a comma-separated allowlist of the lab's
	// fixed private CIDRs. An enabled scanner without this list is still off.
	ServerScannerAllowedTargets []*net.IPNet
	CacheTTLSeconds             int
}

// Load reads a .env file (if present) and then populates Config from env vars.
// Calling Load multiple times is safe; it returns a fresh Config each time.
func Load() (*Config, error) {
	// godotenv.Load is a no-op when .env is absent — that's fine for production.
	_ = godotenv.Load()

	ttl := 3600
	if raw := os.Getenv("CACHE_TTL_SECONDS"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			ttl = v
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	allowedTargets, err := parseCIDRList(os.Getenv("SERVER_SCANNER_ALLOWED_TARGETS"))
	if err != nil {
		return nil, err
	}

	return &Config{
		Port:                        port,
		AbuseIPDBKey:                os.Getenv("ABUSEIPDB_API_KEY"),
		VirusTotalKey:               os.Getenv("VIRUSTOTAL_API_KEY"),
		IPInfoKey:                   os.Getenv("IPINFO_API_KEY"),
		OTXKey:                      os.Getenv("OTX_API_KEY"),
		GoogleSafeBrowsingKey:       os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY"),
		URLScanKey:                  os.Getenv("URLSCAN_API_KEY"),
		ServerScannerEnabled:        os.Getenv("SERVER_SCANNER_ENABLED") == "true",
		ServerScannerAllowedTargets: allowedTargets,
		CacheTTLSeconds:             ttl,
	}, nil
}

func parseCIDRList(raw string) ([]*net.IPNet, error) {
	if raw == "" {
		return nil, nil
	}

	values := strings.Split(raw, ",")
	blocks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("SERVER_SCANNER_ALLOWED_TARGETS contains an empty entry")
		}
		_, block, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid SERVER_SCANNER_ALLOWED_TARGETS entry %q: %w", value, err)
		}
		if block.IP.To4() == nil {
			return nil, fmt.Errorf("SERVER_SCANNER_ALLOWED_TARGETS entry %q is not an IPv4 CIDR", value)
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}
