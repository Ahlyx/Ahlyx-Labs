package shared

import "testing"

func TestServerScannerIsDisabledByDefault(t *testing.T) {
	t.Setenv("SERVER_SCANNER_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerScannerEnabled {
		t.Fatal("scanner enabled by default")
	}
}

func TestServerScannerRequiresExplicitTrue(t *testing.T) {
	t.Setenv("SERVER_SCANNER_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ServerScannerEnabled {
		t.Fatal("scanner disabled for explicit true")
	}
}

func TestServerScannerAllowlist(t *testing.T) {
	t.Setenv("SERVER_SCANNER_ALLOWED_TARGETS", "10.42.0.0/24,192.168.50.0/24")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ServerScannerAllowedTargets) != 2 {
		t.Fatalf("allowlist entries = %d", len(cfg.ServerScannerAllowedTargets))
	}
}

func TestURLScanSubmissionDefaultsToDisabledAndUnlisted(t *testing.T) {
	t.Setenv("URLSCAN_ACTIVE_SUBMISSION", "")
	t.Setenv("URLSCAN_VISIBILITY", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URLScanActiveSubmission || cfg.URLScanVisibility != "unlisted" {
		t.Fatalf("unsafe URLScan defaults: %+v", cfg)
	}
}

func TestURLScanRejectsPublicVisibility(t *testing.T) {
	t.Setenv("URLSCAN_VISIBILITY", "public")
	if _, err := Load(); err == nil {
		t.Fatal("public visibility accepted")
	}
}
