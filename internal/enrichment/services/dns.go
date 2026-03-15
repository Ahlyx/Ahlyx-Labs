package services

import (
	"context"
	"net"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)


// resolver uses Google's public DNS with a 5s timeout, matching the Python
// dnspython resolver.timeout = 5 / resolver.lifetime = 5 configuration.
var dnsResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "udp", "8.8.8.8:53")
	},
}

func FetchDNS(domain string) (*models.DNSData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "dns", RetrievedAt: time.Now().UTC()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	aRecords := []string{}
	aaaaRecords := []string{}
	mxRecords := []string{}
	nsRecords := []string{}
	txtRecords := []string{}

	// Each record type is fetched independently; individual failures don't
	// abort the overall DNS lookup (mirrors Python's per-type try/except).
	if addrs, err := dnsResolver.LookupHost(ctx, domain); err == nil {
		for _, addr := range addrs {
			if net.ParseIP(addr).To4() != nil {
				aRecords = append(aRecords, addr)
			} else {
				aaaaRecords = append(aaaaRecords, addr)
			}
		}
	}

	if mxs, err := dnsResolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			mxRecords = append(mxRecords, mx.Host)
		}
	}

	if nss, err := dnsResolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			nsRecords = append(nsRecords, ns.Host)
		}
	}

	if txts, err := dnsResolver.LookupTXT(ctx, domain); err == nil {
		txtRecords = txts
	}

	meta.Success = true
	return &models.DNSData{
		ARecords:    aRecords,
		AAAARecords: aaaaRecords,
		MXRecords:   mxRecords,
		NSRecords:   nsRecords,
		TXTRecords:  txtRecords,
	}, meta
}
