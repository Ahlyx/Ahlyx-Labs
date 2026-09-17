package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOriginVerificationRejectsMissingAndIncorrectSecret(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := OriginVerification("expected")(next)
	for _, provided := range []string{"", "incorrect"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if provided != "" {
			req.Header.Set(cloudflareOriginHeader, provided)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("secret %q returned %d; want 403", provided, rec.Code)
		}
	}
}

func TestOriginVerificationMarksValidRequest(t *testing.T) {
	called := false
	handler := OriginVerification("expected")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = OriginVerified(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(cloudflareOriginHeader, "expected")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("valid secret was not accepted: code=%d called=%v", rec.Code, called)
	}
}

func TestOriginVerificationAllowsLocalDevelopment(t *testing.T) {
	handler := OriginVerification("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if OriginVerified(r) {
			t.Fatal("local request was incorrectly marked as edge-verified")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("local request returned %d", rec.Code)
	}
}
