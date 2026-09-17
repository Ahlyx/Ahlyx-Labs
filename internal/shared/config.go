package shared

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

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
	CacheTTLSeconds             int
}

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
	allowedTargets, err := parseCIDRList(os.Getenv("SERVER_SCANNER_ALLOWED_TARGETS"))
	if err != nil {
		return nil, err
	}
	return &Config{
		Port: port, AbuseIPDBKey: os.Getenv("ABUSEIPDB_API_KEY"), VirusTotalKey: os.Getenv("VIRUSTOTAL_API_KEY"), IPInfoKey: os.Getenv("IPINFO_API_KEY"), OTXKey: os.Getenv("OTX_API_KEY"),
		GoogleSafeBrowsingKey: os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY"), URLScanKey: os.Getenv("URLSCAN_API_KEY"), URLScanActiveSubmission: os.Getenv("URLSCAN_ACTIVE_SUBMISSION") == "true", URLScanVisibility: visibility,
		ServerScannerEnabled: os.Getenv("SERVER_SCANNER_ENABLED") == "true", ServerScannerAllowedTargets: allowedTargets, CacheTTLSeconds: ttl,
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
