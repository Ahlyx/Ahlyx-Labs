package models

import (
	"encoding/json"
	"testing"
)

func intPtr(value int) *int          { return &value }
func boolPtr(value bool) *bool       { return &value }
func stringPtr(value string) *string { return &value }

func successfulSources(names ...string) []SourceMetadata {
	sources := make([]SourceMetadata, 0, len(names))
	for _, name := range names {
		sources = append(sources, SourceMetadata{Source: name, Success: true})
	}
	return sources
}

func TestDomainVerdict(t *testing.T) {
	vtAndOTX := successfulSources("virustotal", "alienvault_otx")
	failedOTX := []SourceMetadata{{Source: "virustotal", Success: true}, {Source: "alienvault_otx", Success: false}}

	tests := []struct {
		name    string
		vt      *DomainVTData
		otx     *OTXData
		sources []SourceMetadata
		tier    string
		mal     bool
	}{
		{"no positive evidence", &DomainVTData{MaliciousVotes: intPtr(0)}, &OTXData{PulseCount: intPtr(0)}, vtAndOTX, TierClean, false},
		{"minority VirusTotal detections", &DomainVTData{MaliciousVotes: intPtr(2), HarmlessVotes: intPtr(59)}, nil, vtAndOTX, TierReview, false},
		{"OTX pulses alone", &DomainVTData{MaliciousVotes: intPtr(0)}, &OTXData{PulseCount: intPtr(1)}, vtAndOTX, TierReview, false},
		{"strong VirusTotal without corroborating OTX", &DomainVTData{MaliciousVotes: intPtr(40), HarmlessVotes: intPtr(10), SuspiciousVotes: intPtr(2), UndetectedVotes: intPtr(5)}, &OTXData{PulseCount: intPtr(1)}, failedOTX, TierReview, false},
		{"strong VirusTotal and successful OTX", &DomainVTData{MaliciousVotes: intPtr(40), HarmlessVotes: intPtr(10), SuspiciousVotes: intPtr(2), UndetectedVotes: intPtr(5)}, &OTXData{PulseCount: intPtr(2)}, vtAndOTX, TierHigh, true},
		{"positive VT with many undetected votes", &DomainVTData{MaliciousVotes: intPtr(1), HarmlessVotes: intPtr(0), SuspiciousVotes: intPtr(0), UndetectedVotes: intPtr(60)}, &OTXData{PulseCount: intPtr(1)}, vtAndOTX, TierReview, false},
		{"Muse-style OTX signal", &DomainVTData{MaliciousVotes: intPtr(0)}, &OTXData{PulseCount: intPtr(3)}, vtAndOTX, TierReview, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := DomainVerdict(tt.vt, tt.otx, tt.sources)
			if verdict.Tier != tt.tier || verdict.IsMalicious != tt.mal || verdict.Score != nil {
				t.Fatalf("DomainVerdict() = %+v, want tier=%q malicious=%t score=nil", verdict, tt.tier, tt.mal)
			}
		})
	}
}

func TestURLVerdict(t *testing.T) {
	allSources := successfulSources("google_safe_browsing", "urlscan", "virustotal")
	tests := []struct {
		name string
		sb   *SafeBrowsingData
		scan *URLScanData
		vt   *URLVTData
		tier string
		mal  bool
	}{
		{"Safe Browsing unsafe", &SafeBrowsingData{IsSafe: boolPtr(false)}, nil, nil, TierHigh, true},
		{"URLScan malicious", nil, &URLScanData{Malicious: boolPtr(true)}, nil, TierHigh, true},
		{"minority VirusTotal malicious", nil, nil, &URLVTData{MaliciousVotes: intPtr(2), HarmlessVotes: intPtr(59)}, TierReview, false},
		{"positive VT with many undetected votes", nil, nil, &URLVTData{MaliciousVotes: intPtr(1), HarmlessVotes: intPtr(0), SuspiciousVotes: intPtr(0), UndetectedVotes: intPtr(60)}, TierReview, false},
		{"VirusTotal majority", nil, nil, &URLVTData{MaliciousVotes: intPtr(40), HarmlessVotes: intPtr(10), SuspiciousVotes: intPtr(2), UndetectedVotes: intPtr(5)}, TierHigh, true},
		{"VirusTotal suspicious", nil, nil, &URLVTData{MaliciousVotes: intPtr(0), SuspiciousVotes: intPtr(1)}, TierReview, false},
		{"no positive evidence", &SafeBrowsingData{IsSafe: boolPtr(true)}, nil, &URLVTData{MaliciousVotes: intPtr(0), SuspiciousVotes: intPtr(0)}, TierClean, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := URLVerdict(tt.sb, tt.scan, tt.vt, allSources)
			if verdict.Tier != tt.tier || verdict.IsMalicious != tt.mal || verdict.Score != nil {
				t.Fatalf("URLVerdict() = %+v, want tier=%q malicious=%t score=nil", verdict, tt.tier, tt.mal)
			}
		})
	}

	failedSafeBrowsing := URLVerdict(&SafeBrowsingData{IsSafe: boolPtr(false)}, nil, nil,
		[]SourceMetadata{{Source: "google_safe_browsing", Success: false}})
	if failedSafeBrowsing.Tier != TierClean {
		t.Fatalf("failed Safe Browsing source produced %q instead of clean", failedSafeBrowsing.Tier)
	}
}

func TestHashVerdict(t *testing.T) {
	sources := successfulSources("malwarebazaar", "virustotal", "circl_hashlookup")
	tests := []struct {
		name string
		vt   *HashVTData
		mb   *MalwareBazaarData
		tier string
		mal  bool
	}{
		{"MalwareBazaar signature", nil, &MalwareBazaarData{Signature: stringPtr("Emotet")}, TierHigh, true},
		{"VirusTotal threat label", &HashVTData{ThreatLabel: stringPtr("trojan")}, nil, TierHigh, true},
		{"minority VirusTotal detections", &HashVTData{MaliciousVotes: intPtr(2), HarmlessVotes: intPtr(59)}, nil, TierReview, false},
		{"positive VT with many undetected votes", &HashVTData{MaliciousVotes: intPtr(1), HarmlessVotes: intPtr(0), SuspiciousVotes: intPtr(0), UndetectedVotes: intPtr(60)}, nil, TierReview, false},
		{"VirusTotal majority", &HashVTData{MaliciousVotes: intPtr(40), HarmlessVotes: intPtr(10), SuspiciousVotes: intPtr(2), UndetectedVotes: intPtr(5)}, nil, TierHigh, true},
		{"no positive evidence", &HashVTData{MaliciousVotes: intPtr(0), SuspiciousVotes: intPtr(0)}, &MalwareBazaarData{}, TierClean, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := HashVerdict(tt.vt, tt.mb, &CIRCLData{KnownGood: boolPtr(true)}, sources)
			if verdict.Tier != tt.tier || verdict.IsMalicious != tt.mal || verdict.Score != nil {
				t.Fatalf("HashVerdict() = %+v, want tier=%q malicious=%t score=nil", verdict, tt.tier, tt.mal)
			}
		})
	}

	failedMalwareBazaar := HashVerdict(nil, &MalwareBazaarData{Signature: stringPtr("Emotet")}, nil,
		[]SourceMetadata{{Source: "malwarebazaar", Success: false}})
	if failedMalwareBazaar.Tier != TierClean {
		t.Fatalf("failed MalwareBazaar source produced %q instead of clean", failedMalwareBazaar.Tier)
	}
}

func TestIPVerdictRetainsCompositeScoreAndTier(t *testing.T) {
	for _, tt := range []struct {
		score int
		tier  string
	}{
		{0, TierClean}, {10, TierLow}, {25, TierMedium}, {50, TierHigh}, {80, TierCritical},
	} {
		verdict := IPVerdict(&AbuseData{AbuseScore: intPtr(tt.score)}, nil, false)
		if verdict.Score == nil || *verdict.Score != tt.score || verdict.Tier != tt.tier {
			t.Fatalf("IPVerdict(%d) = %+v, want score=%d tier=%q", tt.score, verdict, tt.score, tt.tier)
		}
		if verdict.IsMalicious != IsMaliciousTier(tt.tier) {
			t.Fatalf("IPVerdict(%d) malicious=%t does not match tier", tt.score, verdict.IsMalicious)
		}
	}
}

func TestVerdictQueryLogValuesPreserveCanonicalTier(t *testing.T) {
	for _, verdict := range []Verdict{
		{Tier: TierClean, IsMalicious: false},
		{Tier: TierReview, IsMalicious: false},
		{Tier: TierHigh, IsMalicious: true},
		{Tier: TierCritical, IsMalicious: true},
	} {
		tier, malicious := verdict.QueryLogValues()
		if tier != verdict.Tier || malicious != verdict.IsMalicious {
			t.Fatalf("QueryLogValues(%+v) = (%q, %t)", verdict, tier, malicious)
		}
	}
}

func TestAllEnrichmentResponsesExposeCanonicalVerdict(t *testing.T) {
	verdict := Verdict{Tier: TierReview, Score: nil, IsMalicious: false}
	responses := []interface{}{
		IPResponse{BaseResponse: BaseResponse{Verdict: verdict}},
		DomainResponse{BaseResponse: BaseResponse{Verdict: verdict}},
		URLResponse{BaseResponse: BaseResponse{Verdict: verdict}},
		HashResponse{BaseResponse: BaseResponse{Verdict: verdict}},
	}

	for _, response := range responses {
		data, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Verdict Verdict `json:"verdict"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Verdict != verdict {
			t.Fatalf("response %T verdict = %+v, want %+v", response, decoded.Verdict, verdict)
		}
	}
}
