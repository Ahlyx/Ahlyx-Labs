package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/models"
	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/services"
	"github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/validators"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

func NewHashHandler(cfg *shared.Config, cache *shared.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := strings.ToLower(chi.URLParam(r, "hash"))

		if !validators.IsValidHash(hash) {
			writeError(w, http.StatusBadRequest, "invalid hash: must be hex-encoded MD5, SHA-1, or SHA-256")
			return
		}
		hashType := validators.DetectHashType(hash)

		cacheKey := "hash:" + hash
		if cached, ok := cache.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cached)
			return
		}

		var (
			mu      sync.Mutex
			wg      sync.WaitGroup
			vt      *models.HashVTData
			mb      *models.MalwareBazaarData
			circl   *models.CIRCLData
			sources []models.SourceMetadata
		)

		wg.Add(3)

		go func() {
			defer wg.Done()
			result, meta := services.FetchVirusTotalHash(cfg.VirusTotalKey, hash)
			mu.Lock()
			vt = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			// MalwareBazaar key is optional; pass empty string if not configured.
			result, meta := services.FetchMalwareBazaar("", hash)
			mu.Lock()
			mb = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		go func() {
			defer wg.Done()
			result, meta := services.FetchCIRCL(hash, hashType)
			mu.Lock()
			circl = result
			sources = append(sources, meta)
			mu.Unlock()
		}()

		wg.Wait()

		// IsMalicious: VT has detections OR MalwareBazaar returned a known sample.
		isMalicious := false
		if vt != nil && vt.MaliciousVotes != nil && *vt.MaliciousVotes > 0 {
			isMalicious = true
		}
		if mb != nil && mb.FileName != nil {
			// MalwareBazaar only returns file data for confirmed malware samples.
			isMalicious = true
		}

		// IsKnownGood: CIRCL found the hash and its trust level marks it good.
		isKnownGood := false
		if circl != nil &&
			circl.Found != nil && *circl.Found &&
			circl.KnownGood != nil && *circl.KnownGood {
			isKnownGood = true
		}

		resp := models.HashResponse{
			BaseResponse: models.BaseResponse{
				Query:     hash,
				QueryType: "hash",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Sources:   sources,
			},
			HashValue:     ptr(hash),
			HashType:      ptr(hashType),
			VirusTotal:    vt,
			MalwareBazaar: mb,
			CIRCL:         circl,
			IsMalicious:   ptr(isMalicious),
			IsKnownGood:   ptr(isKnownGood),
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
		shared.LogQuery("enrichment", "hash", verdict, isMalicious, len(sources), 0, 0, 0)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}
