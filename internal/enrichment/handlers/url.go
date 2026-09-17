package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/services"
	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/validators"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

const maxURLRequestBodyBytes = 16 << 10

type urlRequest struct {
	URL           string `json:"url"`
	SubmitURLScan bool   `json:"submit_urlscan"`
}

func NewURLHandler(cfg *shared.Config, cache *shared.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, maxURLRequestBodyBytes)
		var request urlRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "request body must be valid JSON")
			return
		}
		targetURL := request.URL
		if targetURL == "" {
			writeError(w, http.StatusBadRequest, "missing required field: url")
			return
		}
		if !validators.IsValidURL(targetURL) {
			writeError(w, http.StatusBadRequest, "invalid URL: must begin with http:// or https://")
			return
		}

		cacheKey := "url:" + targetURL
		if cached, ok := cache.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cached)
			return
		}

		start := time.Now()

		var (
			mu      sync.Mutex
			wg      sync.WaitGroup
			sb      *models.SafeBrowsingData
			urlscan *models.URLScanData
			vt      *models.URLVTData
			sources []models.SourceMetadata
		)

		wg.Add(2)

		go func() {
			defer wg.Done()
			result, meta := services.FetchSafeBrowsing(cfg.GoogleSafeBrowsingKey, targetURL)
			mu.Lock()
			sb = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		if cfg.URLScanActiveSubmission && request.SubmitURLScan {
			wg.Add(1)
			go func() {
				defer wg.Done()
				result, meta := services.FetchURLScan(cfg.URLScanKey, targetURL, cfg.URLScanVisibility)
				mu.Lock()
				urlscan = result
				sources = append(sources, meta)
				mu.Unlock()
			}()
		}

		go func() {
			defer wg.Done()
			result, meta := services.FetchVirusTotalURL(cfg.VirusTotalKey, targetURL)
			mu.Lock()
			vt = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		wg.Wait()

		// IsMalicious: any source reporting a threat sets the flag.
		isMalicious := false
		if sb != nil && sb.IsSafe != nil && !*sb.IsSafe {
			isMalicious = true
		}
		if urlscan != nil && urlscan.Malicious != nil && *urlscan.Malicious {
			isMalicious = true
		}
		if vt != nil && vt.MaliciousVotes != nil && *vt.MaliciousVotes > 0 {
			isMalicious = true
		}

		resp := models.URLResponse{
			BaseResponse: models.BaseResponse{
				Query:     targetURL,
				QueryType: "url",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Sources:   sources,
			},
			URL:          ptr(targetURL),
			SafeBrowsing: sb,
			URLScan:      urlscan,
			VirusTotal:   vt,
			IsMalicious:  ptr(isMalicious),
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encode response")
			return
		}
		cache.Set(cacheKey, data, sources)
		verdict := "clean"
		if isMalicious {
			verdict = "threat"
		}
		shared.LogQuery("enrichment", "url", verdict, isMalicious, len(sources), int(time.Since(start).Milliseconds()), 0, 0)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}

// DeprecatedURLHandler deliberately never reads URL query parameters. Full
// URLs can contain credentials or bearer material and must travel in a POST
// JSON body instead of browser history and intermediary request URLs.
func DeprecatedURLHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeError(w, http.StatusGone, "URL enrichment now requires POST /api/v1/url with a JSON body")
}
