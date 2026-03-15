package shared

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// CORSMiddleware returns a chi-compatible CORS handler that allows all origins.
// Tighten AllowedOrigins to the Vercel domain before going to production.
func CORSMiddleware() func(http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		MaxAge:         300,
	})
}

// Router is a minimal interface covering the Use method shared by chi routers.
type Router interface {
	Use(...func(http.Handler) http.Handler)
}

// ApplyGlobalMiddleware attaches RealIP, Logger, Recoverer, and CORS to r.
func ApplyGlobalMiddleware(r Router) {
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(CORSMiddleware())
}
