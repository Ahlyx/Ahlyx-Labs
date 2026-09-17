package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

func TestScannerRouteIsAbsentByDefault(t *testing.T) {
	router := newRouter(&shared.Config{}, shared.NewCache())

	for _, target := range []string{
		"127.0.0.1",
		"169.254.169.254",
		"10.0.0.1",
		"192.168.1.1",
		"::1",
		"fc00::1",
		"fe80::1",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/scanner/scan?subnet="+target, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("scanner target %q returned %d; want route unavailable", target, rec.Code)
		}
	}
}

func TestScannerRouteRequiresAnAllowlist(t *testing.T) {
	router := newRouter(&shared.Config{ServerScannerEnabled: true}, shared.NewCache())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scanner/scan?subnet=192.168.1.1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("scanner without an allowlist returned %d; want route unavailable", rec.Code)
	}
}
