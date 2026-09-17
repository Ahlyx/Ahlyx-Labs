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
	pcaphandlers "github.com/Ahlyx/Ahlyx-Labs/internal/pcap/handlers"
	scanhandlers "github.com/Ahlyx/Ahlyx-Labs/internal/scanner/handlers"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

func main() {
	cfg, err := shared.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	shared.InitDB()

	cache := shared.NewCache()

	r := newRouter(cfg, cache)

	addr := ":" + cfg.Port
	log.Printf("ahlyx-labs listening on %s", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// newRouter registers only the features explicitly enabled for this
// deployment. Keeping this separate from main makes the public route surface
// straightforward to verify in tests.
func newRouter(cfg *shared.Config, cache *shared.Cache) http.Handler {
	r := chi.NewRouter()
	shared.ApplyGlobalMiddleware(r)

	// Rate limiters per CLAUDE.md:
	//   IP / domain / hash : 30 req/min, burst 30
	//   URL               : 10 req/min, burst 10
	globalRL := rate.NewLimiter(rate.Every(100*time.Millisecond), 120)
	stdRL := shared.NewRateLimiter(rate.Every(2*time.Second), 30, globalRL)  // 30/min
	urlRL := shared.NewRateLimiter(rate.Every(6*time.Second), 10, globalRL)  // 10/min
	hwRL := shared.NewRateLimiter(rate.Every(2*time.Second), 30, globalRL)   // 30/min
	pcapRL := shared.NewRateLimiter(rate.Every(6*time.Second), 10, globalRL) // 10/min

	// -----------------------------------------------------------------------
	// Health check
	// -----------------------------------------------------------------------
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	r.Group(func(protected chi.Router) {
		protected.Use(shared.OriginVerification(cfg.CloudflareOriginSecret))

		// Enrichment routes
		protected.Group(func(r chi.Router) {
			r.Use(stdRL.Middleware)
			r.Get("/api/v1/ip/{address}", enrichhandlers.NewIPHandler(cfg, cache))
			r.Get("/api/v1/domain/{name}", enrichhandlers.NewDomainHandler(cfg, cache))
			r.Get("/api/v1/hash/{hash}", enrichhandlers.NewHashHandler(cfg, cache))
		})

		protected.With(urlRL.Middleware).Post("/api/v1/url", enrichhandlers.NewURLHandler(cfg, cache))
		protected.With(urlRL.Middleware).Get("/api/v1/url", enrichhandlers.DeprecatedURLHandler)

		// The hosted service never scans visitor-supplied targets by default.
		if cfg.ServerScannerEnabled && len(cfg.ServerScannerAllowedTargets) > 0 {
			scanRL := shared.NewRateLimiter(rate.Every(12*time.Second), 5, globalRL) // 5/min
			protected.Method(http.MethodGet, "/api/v1/scanner/scan", scanhandlers.NewControlledScanHandler(scanRL, cfg.ServerScannerAllowedTargets))
		}

		protected.Group(func(r chi.Router) {
			r.Use(hwRL.Middleware)
			r.Get("/api/v1/hardware/system", hwhandlers.HandleSystem)
			r.Get("/api/v1/hardware/cpu", hwhandlers.HandleCPU)
			r.Get("/api/v1/hardware/ram", hwhandlers.HandleRAM)
			r.Get("/api/v1/hardware/disk", hwhandlers.HandleDisk)
			r.Get("/api/v1/hardware/network", hwhandlers.HandleNetwork)
		})

		protected.With(pcapRL.Middleware).Get("/api/v1/pcap/session", pcaphandlers.NewSession)
		protected.With(pcapRL.Middleware).Get("/ws/relay/{session_id}", pcaphandlers.HandleRelay)
	})

	return r
}
