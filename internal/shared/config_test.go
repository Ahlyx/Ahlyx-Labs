package shared

import "testing"

func TestServerScannerIsDisabledByDefault(t *testing.T) {
	t.Setenv("SERVER_SCANNER_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ServerScannerEnabled {
		t.Fatal("ServerScannerEnabled = true by default; want false")
	}
}

func TestServerScannerRequiresExplicitTrue(t *testing.T) {
	t.Setenv("SERVER_SCANNER_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.ServerScannerEnabled {
		t.Fatal("ServerScannerEnabled = false for explicit true")
	}
}

func TestServerScannerAllowlist(t *testing.T) {
	t.Setenv("SERVER_SCANNER_ALLOWED_TARGETS", "10.42.0.0/24, 192.168.50.0/24")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.ServerScannerAllowedTargets) != 2 {
		t.Fatalf("allowlist entries = %d; want 2", len(cfg.ServerScannerAllowedTargets))
	}
}
