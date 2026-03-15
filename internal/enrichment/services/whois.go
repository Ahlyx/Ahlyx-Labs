package services

import (
	"strings"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

func FetchWHOIS(domain string) (*models.WhoisData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "whois", RetrievedAt: time.Now().UTC()}

	// WHOIS is a blocking network call; run within the semaphore.
	acquireSem()
	raw, err := whois.Whois(domain)
	releaseSem()

	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	result, err := whoisparser.Parse(raw)
	if err != nil {
		// whois-parser returns an error for unparseable responses.
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	if result.Domain == nil {
		meta.Error = ptr("no domain data in WHOIS response")
		return nil, meta
	}

	created := normalizeDate(result.Domain.CreatedDate)
	expired := normalizeDate(result.Domain.ExpirationDate)
	updated := normalizeDate(result.Domain.UpdatedDate)

	ageDays := calcAgeDays(created)

	var isNew *bool
	if ageDays != nil {
		v := *ageDays < 30
		isNew = &v
	}

	var registrar *string
	if result.Registrar != nil && result.Registrar.Name != "" {
		registrar = ptr(result.Registrar.Name)
	}

	meta.Success = true
	return &models.WhoisData{
		Registrar:         registrar,
		CreationDate:      created,
		ExpirationDate:    expired,
		LastUpdated:       updated,
		DomainAgeDays:     ageDays,
		IsNewlyRegistered: isNew,
	}, meta
}

// normalizeDate returns the date string as-is if non-empty, else nil.
func normalizeDate(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return ptr(s)
}

func calcAgeDays(dateStr *string) *int {
	if dateStr == nil {
		return nil
	}

	layouts := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
		time.RFC3339,
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, *dateStr); err == nil {
			days := int(time.Since(t).Hours() / 24)
			return ptr(days)
		}
	}
	return nil
}
