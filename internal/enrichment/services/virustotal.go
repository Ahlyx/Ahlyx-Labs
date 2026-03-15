package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)

const (
	vtIPURL     = "https://www.virustotal.com/api/v3/ip_addresses"
	vtDomainURL = "https://www.virustotal.com/api/v3/domains"
	vtURLURL    = "https://www.virustotal.com/api/v3/urls"
	vtFileURL   = "https://www.virustotal.com/api/v3/files"
)

func vtGet(apiKey, url string) ([]byte, error, int) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err, 0
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err, 0
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, err, resp.StatusCode
}

func FetchVirusTotalIP(apiKey, ip string) (*models.VTIPData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "virustotal", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	body, err, status := vtGet(apiKey, fmt.Sprintf("%s/%s", vtIPURL, ip))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	if status != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", status))
		return nil, meta
	}

	var raw struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  *int `json:"malicious"`
					Harmless   *int `json:"harmless"`
					Suspicious *int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate         *int64 `json:"last_analysis_date"`
				PopularThreatClassification struct {
					SuggestedThreatLabel *string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	attrs := raw.Data.Attributes
	malware := []string{}
	if attrs.PopularThreatClassification.SuggestedThreatLabel != nil {
		malware = []string{*attrs.PopularThreatClassification.SuggestedThreatLabel}
	}

	meta.Success = true
	return &models.VTIPData{
		MaliciousVotes:    attrs.LastAnalysisStats.Malicious,
		HarmlessVotes:     attrs.LastAnalysisStats.Harmless,
		SuspiciousVotes:   attrs.LastAnalysisStats.Suspicious,
		LastAnalysisDate:  attrs.LastAnalysisDate,
		AssociatedMalware: malware,
	}, meta
}

func FetchVirusTotalDomain(apiKey, domain string) (*models.DomainVTData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "virustotal", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	body, err, status := vtGet(apiKey, fmt.Sprintf("%s/%s", vtDomainURL, domain))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	if status != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", status))
		return nil, meta
	}

	var raw struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  *int `json:"malicious"`
					Harmless   *int `json:"harmless"`
					Suspicious *int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate *int64            `json:"last_analysis_date"`
				Categories       map[string]string `json:"categories"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	cats := []string{}
	for _, v := range raw.Data.Attributes.Categories {
		cats = append(cats, v)
	}

	meta.Success = true
	return &models.DomainVTData{
		MaliciousVotes:   raw.Data.Attributes.LastAnalysisStats.Malicious,
		HarmlessVotes:    raw.Data.Attributes.LastAnalysisStats.Harmless,
		SuspiciousVotes:  raw.Data.Attributes.LastAnalysisStats.Suspicious,
		LastAnalysisDate: raw.Data.Attributes.LastAnalysisDate,
		Categories:       cats,
	}, meta
}

func FetchVirusTotalURL(apiKey, targetURL string) (*models.URLVTData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "virustotal", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	// VT URL lookup: base64url-encode the URL (no padding), same as Python.
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(targetURL))
	encoded = strings.TrimRight(encoded, "=")

	body, err, status := vtGet(apiKey, fmt.Sprintf("%s/%s", vtURLURL, encoded))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	if status != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", status))
		return nil, meta
	}

	var raw struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  *int `json:"malicious"`
					Harmless   *int `json:"harmless"`
					Suspicious *int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate *int64 `json:"last_analysis_date"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	meta.Success = true
	return &models.URLVTData{
		MaliciousVotes:   raw.Data.Attributes.LastAnalysisStats.Malicious,
		HarmlessVotes:    raw.Data.Attributes.LastAnalysisStats.Harmless,
		SuspiciousVotes:  raw.Data.Attributes.LastAnalysisStats.Suspicious,
		LastAnalysisDate: raw.Data.Attributes.LastAnalysisDate,
	}, meta
}

func FetchVirusTotalHash(apiKey, hash string) (*models.HashVTData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "virustotal", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	body, err, status := vtGet(apiKey, fmt.Sprintf("%s/%s", vtFileURL, hash))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	if status != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", status))
		return nil, meta
	}

	var raw struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  *int `json:"malicious"`
					Harmless   *int `json:"harmless"`
					Suspicious *int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate            *int64  `json:"last_analysis_date"`
				TypeDescription             *string `json:"type_description"`
				Size                        *int64  `json:"size"`
				MeaningfulName              *string `json:"meaningful_name"`
				PopularThreatClassification struct {
					SuggestedThreatLabel *string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	attrs := raw.Data.Attributes
	meta.Success = true
	return &models.HashVTData{
		MaliciousVotes:   attrs.LastAnalysisStats.Malicious,
		HarmlessVotes:    attrs.LastAnalysisStats.Harmless,
		SuspiciousVotes:  attrs.LastAnalysisStats.Suspicious,
		LastAnalysisDate: attrs.LastAnalysisDate,
		FileType:         attrs.TypeDescription,
		FileSize:         attrs.Size,
		MeaningfulName:   attrs.MeaningfulName,
		ThreatLabel:      attrs.PopularThreatClassification.SuggestedThreatLabel,
	}, meta
}
