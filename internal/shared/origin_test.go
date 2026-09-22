package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const previewOrigin = "https://ahlyx-labs-o8kiqf8xa-ahlyx-labs.vercel.app"

func TestClassifyOrigin(t *testing.T) {
	tests := []struct {
		origin      string
		kind        OriginKind
		corsAllowed bool
		logsQuery   bool
	}{
		{"https://ahlyxlabs.com", OriginProduction, true, true},
		{"https://www.ahlyxlabs.com", OriginProduction, true, true},
		{previewOrigin, OriginPreview, true, false},
		{"http://localhost:3000", OriginOther, false, true},
		{"https://ahlyx-labs-git-feature-ahlyx.vercel.app", OriginOther, false, true},
		{"https://random-app.vercel.app", OriginOther, false, true},
		{"", OriginOther, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := ClassifyOrigin(tt.origin); got != tt.kind {
				t.Fatalf("ClassifyOrigin(%q) = %v, want %v", tt.origin, got, tt.kind)
			}
			if got := IsAllowedBrowserOrigin(tt.origin); got != tt.corsAllowed {
				t.Fatalf("IsAllowedBrowserOrigin(%q) = %t, want %t", tt.origin, got, tt.corsAllowed)
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if got := ShouldLogQueryTelemetry(req); got != tt.logsQuery {
				t.Fatalf("ShouldLogQueryTelemetry(%q) = %t, want %t", tt.origin, got, tt.logsQuery)
			}
		})
	}
}

func TestCORSMiddlewareUsesOriginClassification(t *testing.T) {
	handler := CORSMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, origin := range []string{"https://ahlyxlabs.com", "https://www.ahlyxlabs.com", previewOrigin} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("CORS origin for %q = %q, want %q", origin, got, origin)
		}
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/", nil)
	preflight.Header.Set("Origin", previewOrigin)
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	preflightRec := httptest.NewRecorder()
	handler.ServeHTTP(preflightRec, preflight)
	if got := preflightRec.Header().Get("Access-Control-Allow-Origin"); got != previewOrigin {
		t.Fatalf("preview POST preflight CORS origin = %q, want %q", got, previewOrigin)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://random-app.vercel.app")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unrelated Vercel origin received CORS header %q", got)
	}
}
