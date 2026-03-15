package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	enrichhandlers "github.com/Ahlyx/Ahlyx-Labs/internal/enrichment/handlers"
	hwhandlers "github.com/Ahlyx/Ahlyx-Labs/internal/hardware/handlers"
	scanhandlers "github.com/Ahlyx/Ahlyx-Labs/internal/scanner/handlers"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

func main() {
	cfg, err := shared.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cache := shared.NewCache()

	r := chi.NewRouter()
	shared.ApplyGlobalMiddleware(r)

	// Rate limiters per CLAUDE.md:
	//   IP / domain / hash : 30 req/min, burst 30
	//   URL               : 10 req/min, burst 10
	stdRL  := shared.NewRateLimiter(rate.Every(2*time.Second), 30)  // 30/min
	urlRL  := shared.NewRateLimiter(rate.Every(6*time.Second), 10)  // 10/min
	scanRL := shared.NewRateLimiter(rate.Every(12*time.Second), 5)  // 5/min
	hwRL   := shared.NewRateLimiter(rate.Every(2*time.Second), 30)  // 30/min

	// -----------------------------------------------------------------------
	// Health check
	// -----------------------------------------------------------------------
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// -----------------------------------------------------------------------
	// Enrichment routes
	// -----------------------------------------------------------------------
	r.Group(func(r chi.Router) {
		r.Use(stdRL.Middleware)
		r.Get("/api/v1/ip/{address}", enrichhandlers.NewIPHandler(cfg, cache))
		r.Get("/api/v1/domain/{name}", enrichhandlers.NewDomainHandler(cfg, cache))
		r.Get("/api/v1/hash/{hash}", enrichhandlers.NewHashHandler(cfg, cache))
	})

	r.With(urlRL.Middleware).Get("/api/v1/url", enrichhandlers.NewURLHandler(cfg, cache))

	// -----------------------------------------------------------------------
	// Scanner routes
	// -----------------------------------------------------------------------
	r.Method(http.MethodGet, "/api/v1/scanner/scan", scanhandlers.NewScanHandlerWithRL(scanRL))

	// -----------------------------------------------------------------------
	// Hardware routes
	// -----------------------------------------------------------------------
	r.Group(func(r chi.Router) {
		r.Use(hwRL.Middleware)
		r.Get("/api/v1/hardware/system",  hwhandlers.HandleSystem)
		r.Get("/api/v1/hardware/cpu",     hwhandlers.HandleCPU)
		r.Get("/api/v1/hardware/ram",     hwhandlers.HandleRAM)
		r.Get("/api/v1/hardware/disk",    hwhandlers.HandleDisk)
		r.Get("/api/v1/hardware/network", hwhandlers.HandleNetwork)
	})

	addr := ":" + cfg.Port
	log.Printf("ahlyx-labs listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
