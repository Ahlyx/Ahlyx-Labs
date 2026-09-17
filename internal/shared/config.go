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
	Port                        string
	AbuseIPDBKey                string
	VirusTotalKey               string
	IPInfoKey                   string
	OTXKey                      string
	GoogleSafeBrowsingKey       string
	URLScanKey                  string
	URLScanActiveSubmission     bool
	URLScanVisibility           string
	ServerScannerEnabled        bool
	ServerScannerAllowedTargets []*net.IPNet
	TrustedProxyCIDRs           []*net.IPNet
	CacheTTLSeconds             int
}

// Load reads a .env file (if present) and then populates Config from env vars.
func Load() (*Config, error) {
	_ = godotenv.Load()

	ttl := 3600
	if raw := os.Getenv("CACHE_TTL_SECONDS"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			ttl = value
		}
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	visibility := os.Getenv("URLSCAN_VISIBILITY")
	if visibility == "" {
		visibility = "unlisted"
	}
	if visibility != "unlisted" && visibility != "private" {
		return nil, fmt.Errorf("URLSCAN_VISIBILITY must be unlisted or private")
	}
	allowedTargets, err := parseCIDRList(os.Getenv("SERVER_SCANNER_ALLOWED_TARGETS"), "SERVER_SCANNER_ALLOWED_TARGETS", true)
	if err != nil {
		return nil, err
	}
	trustedProxies, err := parseCIDRList(os.Getenv("TRUSTED_PROXY_CIDRS"), "TRUSTED_PROXY_CIDRS", false)
	if err != nil {
		return nil, err
	}

	return &Config{
		Port: port, AbuseIPDBKey: os.Getenv("ABUSEIPDB_API_KEY"), VirusTotalKey: os.Getenv("VIRUSTOTAL_API_KEY"), IPInfoKey: os.Getenv("IPINFO_API_KEY"), OTXKey: os.Getenv("OTX_API_KEY"),
		GoogleSafeBrowsingKey: os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY"), URLScanKey: os.Getenv("URLSCAN_API_KEY"), URLScanActiveSubmission: os.Getenv("URLSCAN_ACTIVE_SUBMISSION") == "true", URLScanVisibility: visibility,
		ServerScannerEnabled: os.Getenv("SERVER_SCANNER_ENABLED") == "true", ServerScannerAllowedTargets: allowedTargets, TrustedProxyCIDRs: trustedProxies, CacheTTLSeconds: ttl,
	}, nil
}

func parseCIDRList(raw, variable string, ipv4Only bool) ([]*net.IPNet, error) {
	if raw == "" {
		return nil, nil
	}
	values := strings.Split(raw, ",")
	blocks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("%s contains an empty entry", variable)
		}
		_, block, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s entry %q: %w", variable, value, err)
		}
		if ipv4Only && block.IP.To4() == nil {
			return nil, fmt.Errorf("%s entry %q is not an IPv4 CIDR", variable, value)
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}
