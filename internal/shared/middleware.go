package shared

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// CORSMiddleware permits the public Ahlyx Labs frontend and its hashed Vercel
// preview deployment origins.
func CORSMiddleware() func(http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowOriginFunc: func(_ *http.Request, origin string) bool {
			return IsAllowedBrowserOrigin(origin)
		},
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
	r.Use(SanitizedRequestLogger)
	r.Use(middleware.Recoverer)
	r.Use(CORSMiddleware())
}

// SanitizedRequestLogger records operational metadata without retaining a
// submitted indicator, URL query, body, credentials, or request headers.
// chi makes the matched route pattern available after the next handler runs.
func SanitizedRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wrapped, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		log.Printf("http method=%s route=%s status=%d duration=%s", r.Method, route, wrapped.Status(), time.Since(started).Round(time.Millisecond))
	})
}
