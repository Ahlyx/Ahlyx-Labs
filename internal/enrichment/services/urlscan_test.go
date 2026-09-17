package services

import (
	"encoding/json"
	"testing"
)

func TestURLScanPayloadUsesNonPublicVisibility(t *testing.T) {
	payload, err := urlscanPayload("https://example.com", "unlisted")
	if err != nil {
		t.Fatalf("urlscanPayload() error = %v", err)
	}
	var values map[string]string
	if err := json.Unmarshal(payload, &values); err != nil {
		t.Fatal(err)
	}
	if values["visibility"] != "unlisted" {
		t.Fatalf("visibility = %q", values["visibility"])
	}
	if _, err := urlscanPayload("https://example.com", "public"); err == nil {
		t.Fatal("public URLScan visibility was accepted")
	}
}
