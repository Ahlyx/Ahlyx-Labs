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

const (
	urlscanSubmitURL = "https://urlscan.io/api/v1/scan/"
	urlscanResultURL = "https://urlscan.io/api/v1/result/"
)

func FetchURLScan(apiKey, targetURL string) (*models.URLScanData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "urlscan", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	// Submit scan
	payload, _ := json.Marshal(map[string]string{
		"url":        targetURL,
		"visibility": "public",
	})

	submitReq, err := http.NewRequest(http.MethodPost, urlscanSubmitURL, bytes.NewReader(payload))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	submitReq.Header.Set("API-Key", apiKey)
	submitReq.Header.Set("Content-Type", "application/json")

	submitResp, err := httpClient.Do(submitReq)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	defer submitResp.Body.Close()

	if submitResp.StatusCode != http.StatusOK && submitResp.StatusCode != 400 {
		// 400 can indicate already-queued scan; treat non-200/400 as errors.
		if submitResp.StatusCode >= 400 {
			meta.Error = ptr(fmt.Sprintf("HTTP %d", submitResp.StatusCode))
			return nil, meta
		}
	}

	submitBody, err := io.ReadAll(submitResp.Body)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var submitData struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(submitBody, &submitData); err != nil || submitData.UUID == "" {
		errMsg := "no scan UUID returned"
		if err != nil {
			errMsg = err.Error()
		}
		meta.Error = ptr(errMsg)
		return nil, meta
	}

	// Poll for result — check every 2 seconds, give up after 8 seconds.
	deadline := time.Now().Add(8 * time.Second)
	var resultBody []byte
	for {
		time.Sleep(2 * time.Second)

		resultReq, err := http.NewRequest(http.MethodGet,
			fmt.Sprintf("%s%s/", urlscanResultURL, submitData.UUID), nil)
		if err != nil {
			meta.Error = ptr(err.Error())
			return nil, meta
		}

		resultResp, err := httpClient.Do(resultReq)
		if err != nil {
			meta.Error = ptr(err.Error())
			return nil, meta
		}

		if resultResp.StatusCode == http.StatusOK {
			resultBody, err = io.ReadAll(resultResp.Body)
			resultResp.Body.Close()
			if err != nil {
				meta.Error = ptr(err.Error())
				return nil, meta
			}
			break
		}
		resultResp.Body.Close()

		if time.Now().After(deadline) {
			meta.Error = ptr("scan result not ready within 8 seconds")
			return nil, meta
		}
	}

	var raw struct {
		Verdicts struct {
			Overall struct {
				Malicious bool `json:"malicious"`
				Score     int  `json:"score"`
			} `json:"overall"`
			URLScan struct {
				Categories []string `json:"categories"`
			} `json:"urlscan"`
		} `json:"verdicts"`
		Task struct {
			ScreenshotURL *string `json:"screenshotURL"`
		} `json:"task"`
	}
	if err := json.Unmarshal(resultBody, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	verdict := "clean"
	if raw.Verdicts.Overall.Malicious {
		verdict = "malicious"
	}

	cats := raw.Verdicts.URLScan.Categories
	if cats == nil {
		cats = []string{}
	}

	meta.Success = true
	return &models.URLScanData{
		Verdict:       ptr(verdict),
		Score:         ptr(raw.Verdicts.Overall.Score),
		Malicious:     ptr(raw.Verdicts.Overall.Malicious),
		Categories:    cats,
		ScreenshotURL: raw.Task.ScreenshotURL,
	}, meta
}
