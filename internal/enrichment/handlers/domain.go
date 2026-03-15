package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/services"
	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/validators"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

func NewDomainHandler(cfg *shared.Config, cache *shared.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		if !validators.IsValidDomain(name) {
			writeError(w, http.StatusBadRequest, "invalid domain name")
			return
		}

		cacheKey := "domain:" + name
		if cached, ok := cache.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cached)
			return
		}

		start := time.Now()

		var (
			mu      sync.Mutex
			wg      sync.WaitGroup
			whois   *models.WhoisData
			dns     *models.DNSData
			ssl     *models.SSLData
			vt      *models.DomainVTData
			otxRaw  interface{}
			sources []models.SourceMetadata
		)

		wg.Add(5)

		go func() {
			defer wg.Done()
			result, meta := services.FetchWHOIS(name)
			mu.Lock()
			whois = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			result, meta := services.FetchDNS(name)
			mu.Lock()
			dns = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			result, meta := services.FetchSSL(name)
			mu.Lock()
			ssl = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			result, meta := services.FetchVirusTotalDomain(cfg.VirusTotalKey, name)
			mu.Lock()
			vt = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			result, meta := services.FetchOTXDomain(cfg.OTXKey, name)
			mu.Lock()
			otxRaw = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		wg.Wait()

		// FetchOTXDomain returns interface{} (unexported otxRaw type).
		// Round-trip through JSON to extract the fields we need.
		var otxData *models.OTXData
		if otxRaw != nil {
			if b, err := json.Marshal(otxRaw); err == nil {
				var parsed struct {
					PulseInfo struct {
						Count  int `json:"count"`
						Pulses []struct {
							Name string `json:"name"`
						} `json:"pulses"`
					} `json:"pulse_info"`
				}
				if json.Unmarshal(b, &parsed) == nil {
					names := make([]string, 0, len(parsed.PulseInfo.Pulses))
					for _, p := range parsed.PulseInfo.Pulses {
						if p.Name != "" {
							names = append(names, p.Name)
						}
					}
					otxData = &models.OTXData{
						PulseCount: ptr(parsed.PulseInfo.Count),
						Pulses:     names,
					}
				}
			}
		}

		resp := models.DomainResponse{
			BaseResponse: models.BaseResponse{
				Query:     name,
				QueryType: "domain",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Sources:   sources,
			},
			Domain:     ptr(name),
			WHOIS:      whois,
			DNS:        dns,
			SSL:        ssl,
			VirusTotal: vt,
			OTX:        otxData,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encode response")
			return
		}
		cache.Set(cacheKey, data, sources)
		isMalicious := false
		if resp.VirusTotal != nil && resp.VirusTotal.MaliciousVotes != nil && *resp.VirusTotal.MaliciousVotes > 0 {
			isMalicious = true
		}
		verdict := "clean"
		if isMalicious {
			verdict = "threat"
		}
		shared.LogQuery("enrichment", "domain", verdict, isMalicious, len(sources), int(time.Since(start).Milliseconds()), 0, 0)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}
