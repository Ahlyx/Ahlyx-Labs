package shared

import (
	"os"
	"strconv"

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
	CacheTTLSeconds       int
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

	return &Config{
		Port:                  port,
		AbuseIPDBKey:          os.Getenv("ABUSEIPDB_API_KEY"),
		VirusTotalKey:         os.Getenv("VIRUSTOTAL_API_KEY"),
		IPInfoKey:             os.Getenv("IPINFO_API_KEY"),
		OTXKey:                os.Getenv("OTX_API_KEY"),
		GoogleSafeBrowsingKey: os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY"),
		URLScanKey:            os.Getenv("URLSCAN_API_KEY"),
		CacheTTLSeconds:       ttl,
	}, nil
}
