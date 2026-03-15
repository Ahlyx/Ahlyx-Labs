package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)

const abuseIPDBURL = "https://api.abuseipdb.com/api/v2/check"

func FetchAbuseIPDB(apiKey, ip string) (*models.AbuseData, models.SourceMetadata) {
	meta := models.SourceMetadata{
		Source:      "abuseipdb",
		RetrievedAt: time.Now().UTC(),
	}

	acquireSem()
	defer releaseSem()

	req, err := http.NewRequest(http.MethodGet, abuseIPDBURL, nil)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()

	resp, err := httpClient.Do(req)
	if err != nil {
		errStr := "Request timed out"
		if err != http.ErrHandlerTimeout {
			errStr = err.Error()
		}
		meta.Error = ptr(errStr)
		return nil, meta
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, meta
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var raw struct {
		Data struct {
			AbuseConfidenceScore int     `json:"abuseConfidenceScore"`
			TotalReports         int     `json:"totalReports"`
			LastReportedAt       *string `json:"lastReportedAt"`
			ISP                  *string `json:"isp"`
			UsageType            *string `json:"usageType"`
			IsTor                bool    `json:"isTor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	meta.Success = true
	return &models.AbuseData{
		AbuseScore:   ptr(raw.Data.AbuseConfidenceScore),
		TotalReports: ptr(raw.Data.TotalReports),
		LastReported: raw.Data.LastReportedAt,
		ISP:          raw.Data.ISP,
		UsageType:    raw.Data.UsageType,
		IsTor:        ptr(raw.Data.IsTor),
	}, meta
}
