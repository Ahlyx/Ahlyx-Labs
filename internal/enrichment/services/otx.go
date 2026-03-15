package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)

const (
	otxIPURL     = "https://otx.alienvault.com/api/v1/indicators/IPv4"
	otxDomainURL = "https://otx.alienvault.com/api/v1/indicators/domain"
)

// otxRaw is the subset of OTX response we parse (data isn't surfaced in the
// response models but the SourceMetadata is included in sources[]).
type otxRaw struct {
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name string `json:"name"`
		} `json:"pulses"`
	} `json:"pulse_info"`
}

func otxGet(apiKey, url string) ([]byte, error, int) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err, 0
	}
	req.Header.Set("X-OTX-API-KEY", apiKey)
	req.Header.Set("Accept", "application/json")

	// OTX has a 5s timeout in the Python version.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err, 0
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, err, resp.StatusCode
}

// FetchOTXIP fetches AlienVault OTX data for an IP. The returned struct is
// ignored by the IP handler (OTX data isn't in IPResponse fields); only the
// SourceMetadata is used.
func FetchOTXIP(apiKey, ip string) (interface{}, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "alienvault_otx", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	body, err, status := otxGet(apiKey, fmt.Sprintf("%s/%s/general", otxIPURL, ip))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	if status != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", status))
		return nil, meta
	}

	var raw otxRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	meta.Success = true
	return &raw, meta
}

// FetchOTXDomain fetches AlienVault OTX data for a domain. Similarly, only
// SourceMetadata is used in DomainResponse.
func FetchOTXDomain(apiKey, domain string) (interface{}, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "alienvault_otx", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	body, err, status := otxGet(apiKey, fmt.Sprintf("%s/%s/general", otxDomainURL, domain))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	if status != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", status))
		return nil, meta
	}

	var raw otxRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	meta.Success = true
	return &raw, meta
}
