package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
)

func FetchIPInfo(apiKey, ip string) (*models.GeoLocation, models.SourceMetadata) {
	meta := models.SourceMetadata{
		Source:      "ipinfo",
		RetrievedAt: time.Now().UTC(),
	}

	acquireSem()
	defer releaseSem()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://ipinfo.io/%s/json", ip), nil)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var raw struct {
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
		Loc     string `json:"loc"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var lat, lon *float64
	parts := strings.SplitN(raw.Loc, ",", 2)
	if len(parts) == 2 {
		if la, err := strconv.ParseFloat(parts[0], 64); err == nil {
			lat = ptr(la)
		}
		if lo, err := strconv.ParseFloat(parts[1], 64); err == nil {
			lon = ptr(lo)
		}
	}

	meta.Success = true
	return &models.GeoLocation{
		Country:     ptrStr(raw.Country),
		CountryCode: ptrStr(raw.Country), // mirrors Python: country_code = country
		Region:      ptrStr(raw.Region),
		City:        ptrStr(raw.City),
		Latitude:    lat,
		Longitude:   lon,
	}, meta
}

func ptrStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
