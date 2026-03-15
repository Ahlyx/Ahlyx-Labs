package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)

const circlURL = "https://hashlookup.circl.lu/lookup"

func FetchCIRCL(hash, hashType string) (*models.CIRCLData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "circl_hashlookup", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/%s/%s", circlURL, hashType, hash), nil)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	req.Header.Set("User-Agent", "security-enrichment-api/0.1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	defer resp.Body.Close()

	// 404 means not found — return a clean "not found" result, not an error.
	if resp.StatusCode == http.StatusNotFound {
		meta.Success = true
		return &models.CIRCLData{
			Found:     ptr(false),
			KnownGood: ptr(false),
		}, meta
	}

	if resp.StatusCode != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, meta
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	getStr := func(keys ...string) *string {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				var s string
				if json.Unmarshal(v, &s) == nil && s != "" {
					return &s
				}
			}
		}
		return nil
	}

	var trustLevel *int
	var knownGood bool
	if v, ok := raw["hashlookup:trust"]; ok {
		var t int
		if json.Unmarshal(v, &t) == nil {
			trustLevel = ptr(t)
			knownGood = t >= 75
		}
	}

	meta.Success = true
	return &models.CIRCLData{
		Found:      ptr(true),
		FileName:   getStr("FileName", "file_name"),
		FileSize:   getStr("FileSize", "file_size"),
		TrustLevel: trustLevel,
		KnownGood:  ptr(knownGood),
	}, meta
}
