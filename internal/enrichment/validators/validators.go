package validators

import (
	"net"
	"regexp"
	"strings"
)

// domainRegex matches valid hostnames with at least one dot and a TLD.
// It rejects bare labels, numeric-only labels (caught separately), and
// labels that start or end with a hyphen.
var domainRegex = regexp.MustCompile(
	`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`,
)

// IsValidIP returns true if s is a valid IPv4 or IPv6 address.
func IsValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// IsBogonIP returns true if s is an IP address in a bogon/reserved range:
// RFC1918 private, loopback, link-local, CGNAT, documentation, multicast, or
// otherwise reserved space.
func IsBogonIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}

	bogonCIDRs := []string{
		// IPv4
		"0.0.0.0/8",          // "This" network
		"10.0.0.0/8",         // RFC1918 private
		"100.64.0.0/10",      // CGNAT shared address space
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link-local
		"172.16.0.0/12",      // RFC1918 private
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // TEST-NET-1 (documentation)
		"192.168.0.0/16",     // RFC1918 private
		"198.18.0.0/15",      // Benchmark testing
		"198.51.100.0/24",    // TEST-NET-2 (documentation)
		"203.0.113.0/24",     // TEST-NET-3 (documentation)
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved (future use)
		"255.255.255.255/32", // Broadcast
		// IPv6
		"::1/128",        // Loopback
		"fc00::/7",       // Unique local (ULA)
		"fe80::/10",      // Link-local
		"ff00::/8",       // Multicast
		"100::/64",       // Discard prefix
		"2001:db8::/32",  // Documentation
		"::/128",         // Unspecified
	}

	for _, cidr := range bogonCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsValidDomain returns true if s looks like a valid domain name.
// Bare IP addresses (IPv4 or IPv6) are rejected.
func IsValidDomain(s string) bool {
	if net.ParseIP(s) != nil {
		return false
	}
	// Strip a single trailing dot (FQDN form).
	s = strings.TrimSuffix(s, ".")
	return domainRegex.MatchString(s)
}

// IsValidURL returns true if s starts with "http://" or "https://".
func IsValidURL(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// IsValidHash returns true if s is a hex-encoded MD5 (32), SHA-1 (40), or
// SHA-256 (64) hash.
func IsValidHash(s string) bool {
	l := len(s)
	if l != 32 && l != 40 && l != 64 {
		return false
	}
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// DetectHashType returns "md5", "sha1", or "sha256" based on the length of s.
// Returns an empty string if the length does not match a known hash type.
func DetectHashType(s string) string {
	switch len(s) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return ""
	}
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}
