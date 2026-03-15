package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)

const safeBrowsingURL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

func FetchSafeBrowsing(apiKey, targetURL string) (*models.SafeBrowsingData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "google_safe_browsing", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	payload := map[string]interface{}{
		"client": map[string]string{
			"clientId":      "security-enrichment-api",
			"clientVersion": "0.1.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes": []string{
				"MALWARE",
				"SOCIAL_ENGINEERING",
				"UNWANTED_SOFTWARE",
				"POTENTIALLY_HARMFUL_APPLICATION",
			},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []map[string]string{{"url": targetURL}},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s?key=%s", safeBrowsingURL, apiKey),
		bytes.NewReader(body))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, meta
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var raw struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(respBody, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	threats := []string{}
	for _, m := range raw.Matches {
		if m.ThreatType != "" {
			threats = append(threats, m.ThreatType)
		}
	}

	meta.Success = true
	return &models.SafeBrowsingData{
		IsSafe:  ptr(len(threats) == 0),
		Threats: threats,
	}, meta
}
