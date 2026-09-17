package main

import (
	"bytes"
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

func TestOriginSecretProtectsSensitiveRoutesButNotHealth(t *testing.T) {
	router := newRouter(&shared.Config{CloudflareOriginSecret: "expected"}, shared.NewCache())
	protected := httptest.NewRequest(http.MethodGet, "/api/v1/ip/8.8.8.8", nil)
	protectedRec := httptest.NewRecorder()
	router.ServeHTTP(protectedRec, protected)
	if protectedRec.Code != http.StatusForbidden {
		t.Fatalf("unverified API request returned %d; want 403", protectedRec.Code)
	}

	health := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRec := httptest.NewRecorder()
	router.ServeHTTP(healthRec, health)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health returned %d; want 200", healthRec.Code)
	}
}

func TestURLRouteIsPostOnlyAndDoesNotReadQueryValue(t *testing.T) {
	router := newRouter(&shared.Config{}, shared.NewCache())
	get := httptest.NewRequest(http.MethodGet, "/api/v1/url?url=https://example.test/reset?token=secret", nil)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusGone || getRec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET URL route = %d, Cache-Control=%q", getRec.Code, getRec.Header().Get("Cache-Control"))
	}

	post := httptest.NewRequest(http.MethodPost, "/api/v1/url?url=https://example.test/reset?token=secret", bytes.NewBufferString(`{}`))
	post.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	router.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusBadRequest || postRec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST URL route = %d, Cache-Control=%q", postRec.Code, postRec.Header().Get("Cache-Control"))
	}
}

func TestCapabilitiesExposeOnlyTheSafeURLScanEnablementSignal(t *testing.T) {
	router := newRouter(&shared.Config{URLScanActiveSubmission: true}, shared.NewCache())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("capabilities = %d, Cache-Control=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if got := rec.Body.String(); got != "{\"urlscan_active_submission\":true}\n" {
		t.Fatalf("unexpected capabilities response: %s", got)
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
