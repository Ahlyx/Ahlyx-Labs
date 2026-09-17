package shared

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// CORSMiddleware permits only the public Ahlyx Labs frontend origins.
func CORSMiddleware() func(http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://ahlyxlabs.com", "https://www.ahlyxlabs.com"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         300,
	})
}

// Router is a minimal interface covering the Use method shared by chi routers.
type Router interface {
	Use(...func(http.Handler) http.Handler)
}

// ApplyGlobalMiddleware attaches logging, recovery, and CORS to r. Client IP
// handling stays inside RateLimiter and requires origin verification before
// it accepts the Cloudflare client identity header.
func ApplyGlobalMiddleware(r Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(CORSMiddleware())
}
