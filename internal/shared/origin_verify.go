package shared

import (
	"context"
	"crypto/subtle"
	"net/http"
)

const cloudflareOriginHeader = "X-Ahlyx-Origin-Verify"

type originVerifiedContextKey struct{}

// OriginVerification requires the static header added by Cloudflare at the
// edge when a production secret is configured. With no secret configured it
// deliberately becomes a no-op so local development remains straightforward.
func OriginVerification(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				next.ServeHTTP(w, r)
				return
			}
			provided := r.Header.Get(cloudflareOriginHeader)
			if subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
				writeError(w, http.StatusForbidden, "request not permitted")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), originVerifiedContextKey{}, true)))
		})
	}
}

// OriginVerified reports whether this request passed origin verification.
func OriginVerified(r *http.Request) bool {
	verified, _ := r.Context().Value(originVerifiedContextKey{}).(bool)
	return verified
}
