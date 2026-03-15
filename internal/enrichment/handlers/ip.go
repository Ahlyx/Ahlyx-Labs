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

func NewIPHandler(cfg *shared.Config, cache *shared.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		address := chi.URLParam(r, "address")

		if !validators.IsValidIP(address) {
			writeError(w, http.StatusBadRequest, "invalid IP address")
			return
		}

		if validators.IsBogonIP(address) {
			writeError(w, http.StatusUnprocessableEntity, "Private and reserved IP addresses are not supported")
			return
		}

		cacheKey := "ip:" + address
		if cached, ok := cache.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cached)
			return
		}

		var (
			mu      sync.Mutex
			wg      sync.WaitGroup
			geo     *models.GeoLocation
			abuse   *models.AbuseData
			vt      *models.VTIPData
			sources []models.SourceMetadata
		)

		wg.Add(3)

		go func() {
			defer wg.Done()
			result, meta := services.FetchIPInfo(cfg.IPInfoKey, address)
			mu.Lock()
			geo = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			result, meta := services.FetchAbuseIPDB(cfg.AbuseIPDBKey, address)
			mu.Lock()
			abuse = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			result, meta := services.FetchVirusTotalIP(cfg.VirusTotalKey, address)
			mu.Lock()
			vt = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		wg.Wait()

		// IsTor is reported by AbuseIPDB; propagate to the top-level field.
		var isTor *bool
		if abuse != nil {
			isTor = abuse.IsTor
		}

		resp := models.IPResponse{
			BaseResponse: models.BaseResponse{
				Query:     address,
				QueryType: "ip",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Sources:   sources,
			},
			IP:          ptr(address),
			Geolocation: geo,
			Abuse:       abuse,
			VirusTotal:  vt,
			IsBogon:     ptr(false),
			IsTor:       isTor,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encode response")
			return
		}
		cache.Set(cacheKey, data, sources)
		isMalicious := resp.IsTor != nil && *resp.IsTor
		if resp.Abuse != nil && resp.Abuse.AbuseScore != nil && *resp.Abuse.AbuseScore >= 80 {
			isMalicious = true
		}
		if resp.VirusTotal != nil && resp.VirusTotal.MaliciousVotes != nil && *resp.VirusTotal.MaliciousVotes > 0 {
			isMalicious = true
		}
		verdict := "clean"
		if isMalicious {
			verdict = "threat"
		}
		shared.LogQuery("enrichment", "ip", verdict, isMalicious, len(sources), 0, 0, 0)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}
