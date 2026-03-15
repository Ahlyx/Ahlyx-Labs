package services

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)

func FetchSSL(domain string) (*models.SSLData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "ssl", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp",
		net.JoinHostPort(domain, "443"),
		&tls.Config{ServerName: domain})

	if err != nil {
		// Distinguish cert verification failures (is_valid=false) from
		// connectivity failures (source error), mirroring Python's
		// ssl.SSLCertVerificationError branch.
		if isCertVerificationErr(err) {
			meta.Success = true
			return &models.SSLData{IsValid: ptr(false)}, meta
		}
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		meta.Error = ptr("no peer certificates")
		return nil, meta
	}

	cert := certs[0]
	tlsVer := tlsVersionString(conn.ConnectionState().Version)

	expiresAt := cert.NotAfter.UTC()
	expiresAtStr := expiresAt.Format(time.RFC3339)
	daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)
	isExpiringSoon := daysUntilExpiry <= 30

	issuerOrg := "Unknown"
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}
	subjectCN := domain
	if cert.Subject.CommonName != "" {
		subjectCN = cert.Subject.CommonName
	}

	// Self-signed: issuer org == subject org
	subjectOrg := ""
	if len(cert.Subject.Organization) > 0 {
		subjectOrg = cert.Subject.Organization[0]
	}
	isSelfSigned := issuerOrg == subjectOrg && issuerOrg != "Unknown"

	meta.Success = true
	return &models.SSLData{
		IsValid:         ptr(true),
		Issuer:          ptr(issuerOrg),
		Subject:         ptr(subjectCN),
		ExpiresAt:       ptr(expiresAtStr),
		DaysUntilExpiry: ptr(daysUntilExpiry),
		IsExpiringSoon:  ptr(isExpiringSoon),
		TLSVersion:      ptr(tlsVer),
		IsSelfSigned:    ptr(isSelfSigned),
	}, meta
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// isCertVerificationErr returns true for any TLS certificate validation error.
func isCertVerificationErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "certificate") ||
		strings.Contains(s, "x509") ||
		strings.Contains(s, "tls:")
}
