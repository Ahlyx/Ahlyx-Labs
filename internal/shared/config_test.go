package shared

import "testing"

func TestURLScanSubmissionDefaultsToDisabledAndUnlisted(t *testing.T) {
	t.Setenv("URLSCAN_ACTIVE_SUBMISSION", "")
	t.Setenv("URLSCAN_VISIBILITY", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.URLScanActiveSubmission || cfg.URLScanVisibility != "unlisted" {
		t.Fatalf("URLScan defaults = enabled:%v visibility:%q", cfg.URLScanActiveSubmission, cfg.URLScanVisibility)
	}
}

func TestURLScanRejectsPublicVisibility(t *testing.T) {
	t.Setenv("URLSCAN_VISIBILITY", "public")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted public URLScan visibility")
	}
}
