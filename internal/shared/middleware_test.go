package shared

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestSanitizedRequestLoggerUsesRoutePattern(t *testing.T) {
	var output bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})

	r := chi.NewRouter()
	r.Use(SanitizedRequestLogger)
	r.Get("/api/v1/ip/{address}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ip/198.51.100.42?token=private-value", nil)
	req.Header.Set("Authorization", "Bearer private-value")
	req.Header.Set("X-Ahlyx-Origin-Verify", "private-value")
	r.ServeHTTP(httptest.NewRecorder(), req)

	entry := output.String()
	if !strings.Contains(entry, "method=GET route=/api/v1/ip/{address} status=204") {
		t.Fatalf("log entry did not contain sanitized metadata: %q", entry)
	}
	for _, sensitive := range []string{"198.51.100.42", "token=", "private-value", "Authorization", "X-Ahlyx-Origin-Verify"} {
		if strings.Contains(entry, sensitive) {
			t.Fatalf("log entry exposed %q: %q", sensitive, entry)
		}
	}
}
