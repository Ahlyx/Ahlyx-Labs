package models

import (
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

// SourceMetadata is an alias for shared.SourceMetadata so enrichment code
// can reference it without importing shared directly.
type SourceMetadata = shared.SourceMetadata

// BaseResponse is embedded in every query response.
type BaseResponse struct {
	Query     string           `json:"query"`
	QueryType string           `json:"query_type"`
	Timestamp string           `json:"timestamp"`
	Sources   []SourceMetadata `json:"sources"`
}

// ---------------------------------------------------------------------------
// IP response types
// ---------------------------------------------------------------------------

// GeoLocation holds IPInfo geolocation data.
type GeoLocation struct {
	Country     *string  `json:"country"`
	CountryCode *string  `json:"country_code"`
	Region      *string  `json:"region"`
	City        *string  `json:"city"`
	Latitude    *float64 `json:"latitude"`
	Longitude   *float64 `json:"longitude"`
}

// AbuseData holds AbuseIPDB report data.
type AbuseData struct {
	AbuseScore   *int    `json:"abuse_score"`
	TotalReports *int    `json:"total_reports"`
	LastReported *string `json:"last_reported"`
	ISP          *string `json:"isp"`
	UsageType    *string `json:"usage_type"`
	IsTor        *bool   `json:"is_tor"`
}

// VTIPData holds VirusTotal analysis stats for an IP address.
type VTIPData struct {
	MaliciousVotes   *int     `json:"malicious_votes"`
	HarmlessVotes    *int     `json:"harmless_votes"`
	SuspiciousVotes  *int     `json:"suspicious_votes"`
	LastAnalysisDate *int64   `json:"last_analysis_date"`
	AssociatedMalware []string `json:"associated_malware"`
}

// IPResponse is the top-level JSON envelope for /api/v1/ip/{address}.
type IPResponse struct {
	BaseResponse
	IP          *string      `json:"ip"`
	Geolocation *GeoLocation `json:"geolocation"`
	Abuse       *AbuseData   `json:"abuse"`
	VirusTotal  *VTIPData    `json:"virustotal"`
	IsBogon     *bool        `json:"is_bogon"`
	IsTor       *bool        `json:"is_tor"`
}

// ---------------------------------------------------------------------------
// Domain response types
// ---------------------------------------------------------------------------

// WhoisData holds parsed WHOIS registration data.
type WhoisData struct {
	Registrar         *string `json:"registrar"`
	CreationDate      *string `json:"creation_date"`
	ExpirationDate    *string `json:"expiration_date"`
	LastUpdated       *string `json:"last_updated"`
	DomainAgeDays     *int    `json:"domain_age_days"`
	IsNewlyRegistered *bool   `json:"is_newly_registered"`
}

// DNSData holds resolved DNS records for a domain.
type DNSData struct {
	ARecords    []string `json:"a"`
	AAAARecords []string `json:"aaaa"`
	MXRecords   []string `json:"mx"`
	NSRecords   []string `json:"ns"`
	TXTRecords  []string `json:"txt"`
}

// SSLData holds TLS certificate details.
type SSLData struct {
	IsValid         *bool   `json:"is_valid"`
	Issuer          *string `json:"issuer"`
	Subject         *string `json:"subject"`
	ExpiresAt       *string `json:"expires_at"`
	DaysUntilExpiry *int    `json:"days_until_expiry"`
	IsExpiringSoon  *bool   `json:"is_expiring_soon"`
	TLSVersion      *string `json:"tls_version"`
	IsSelfSigned    *bool   `json:"is_self_signed"`
}

// DomainVTData holds VirusTotal analysis stats for a domain.
type DomainVTData struct {
	MaliciousVotes  *int     `json:"malicious_votes"`
	HarmlessVotes   *int     `json:"harmless_votes"`
	SuspiciousVotes *int     `json:"suspicious_votes"`
	LastAnalysisDate *int64  `json:"last_analysis_date"`
	Categories      []string `json:"categories"`
}

// OTXData holds AlienVault OTX pulse data, populated by the handler.
type OTXData struct {
	PulseCount *int     `json:"pulse_count"`
	Pulses     []string `json:"pulses"`
}

// DomainResponse is the top-level JSON envelope for /api/v1/domain/{name}.
type DomainResponse struct {
	BaseResponse
	Domain     *string       `json:"domain"`
	WHOIS      *WhoisData    `json:"whois"`
	DNS        *DNSData      `json:"dns"`
	SSL        *SSLData      `json:"ssl"`
	VirusTotal *DomainVTData `json:"virustotal"`
	OTX        *OTXData      `json:"otx"`
}

// ---------------------------------------------------------------------------
// URL response types
// ---------------------------------------------------------------------------

// SafeBrowsingData holds Google Safe Browsing threat data.
type SafeBrowsingData struct {
	IsSafe  *bool    `json:"is_safe"`
	Threats []string `json:"threats"`
}

// URLScanData holds urlscan.io scan result data.
type URLScanData struct {
	Verdict       *string  `json:"verdict"`
	Score         *int     `json:"score"`
	Malicious     *bool    `json:"malicious"`
	Categories    []string `json:"categories"`
	ScreenshotURL *string  `json:"screenshot_url"`
}

// URLVTData holds VirusTotal analysis stats for a URL.
type URLVTData struct {
	MaliciousVotes  *int   `json:"malicious_votes"`
	HarmlessVotes   *int   `json:"harmless_votes"`
	SuspiciousVotes *int   `json:"suspicious_votes"`
	LastAnalysisDate *int64 `json:"last_analysis_date"`
}

// URLResponse is the top-level JSON envelope for /api/v1/url.
type URLResponse struct {
	BaseResponse
	URL          *string           `json:"url"`
	SafeBrowsing *SafeBrowsingData `json:"safe_browsing"`
	URLScan      *URLScanData      `json:"urlscan"`
	VirusTotal   *URLVTData        `json:"virustotal"`
	IsMalicious  *bool             `json:"is_malicious"`
}

// ---------------------------------------------------------------------------
// Hash response types
// ---------------------------------------------------------------------------

// HashVTData holds VirusTotal analysis stats for a file hash.
type HashVTData struct {
	MaliciousVotes  *int    `json:"malicious_votes"`
	HarmlessVotes   *int    `json:"harmless_votes"`
	SuspiciousVotes *int    `json:"suspicious_votes"`
	LastAnalysisDate *int64 `json:"last_analysis_date"`
	FileType        *string `json:"file_type"`
	FileSize        *int64  `json:"file_size"`
	MeaningfulName  *string `json:"meaningful_name"`
	ThreatLabel     *string `json:"threat_label"`
}

// MalwareBazaarData holds MalwareBazaar file intelligence data.
type MalwareBazaarData struct {
	FileName  *string  `json:"file_name"`
	FileType  *string  `json:"file_type"`
	FileSize  *int64   `json:"file_size"`
	Signature *string  `json:"signature"`
	Tags      []string `json:"tags"`
	FirstSeen *string  `json:"first_seen"`
	LastSeen  *string  `json:"last_seen"`
}

// CIRCLData holds CIRCL hashlookup data.
type CIRCLData struct {
	Found      *bool   `json:"found"`
	FileName   *string `json:"file_name"`
	FileSize   *string `json:"file_size"`
	TrustLevel *int    `json:"trust_level"`
	KnownGood  *bool   `json:"known_good"`
}

// HashResponse is the top-level JSON envelope for /api/v1/hash/{hash}.
type HashResponse struct {
	BaseResponse
	HashValue     *string            `json:"hash_value"`
	HashType      *string            `json:"hash_type"`
	VirusTotal    *HashVTData        `json:"virustotal"`
	MalwareBazaar *MalwareBazaarData `json:"malware_bazaar"`
	CIRCL         *CIRCLData         `json:"circl"`
	IsMalicious   *bool              `json:"is_malicious"`
	IsKnownGood   *bool              `json:"is_known_good"`
}
