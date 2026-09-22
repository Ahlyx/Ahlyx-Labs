package models

import "strings"

// Verdict is the canonical enrichment assessment. Only IP enrichment has a
// defensible composite score today; evidence-tiered tools leave Score nil.
type Verdict struct {
	Tier        string `json:"tier"`
	Score       *int   `json:"score"`
	IsMalicious bool   `json:"is_malicious"`
}

// IsMaliciousTier keeps the boolean telemetry meaning intentionally narrow:
// low, medium, and review warrant attention but are not malicious verdicts.
func IsMaliciousTier(tier string) bool {
	return tier == TierHigh || tier == TierCritical
}

func newVerdict(tier string, score *int) Verdict {
	return Verdict{Tier: tier, Score: score, IsMalicious: IsMaliciousTier(tier)}
}

// QueryLogValues gives telemetry the same tier and malicious semantics that
// the API returned, without allowing handlers to reinterpret the evidence.
func (v Verdict) QueryLogValues() (string, bool) {
	return v.Tier, v.IsMalicious
}

// IPVerdict preserves the existing IP composite score and compatibility tiers.
func IPVerdict(abuse *AbuseData, vt *VTIPData, isTor bool) Verdict {
	score, tier := ScoreIPThreat(abuse, vt, isTor)
	return newVerdict(tier, &score)
}

// DomainVerdict requires corroborated positive evidence for HIGH. OTX and VT
// failures are deliberately ignored instead of being interpreted as evidence.
func DomainVerdict(vt *DomainVTData, otx *OTXData, sources []SourceMetadata) Verdict {
	vtSucceeded := sourceSucceeded(sources, "virustotal")
	otxSucceeded := sourceSucceeded(sources, "alienvault_otx")
	if vtSucceeded && otxSucceeded && vt != nil && otx != nil && hasStrongVirusTotalConsensus(vt.MaliciousVotes, vt.HarmlessVotes, vt.SuspiciousVotes, vt.UndetectedVotes) && positive(otx.PulseCount) {
		return newVerdict(TierHigh, nil)
	}
	if vtSucceeded && vt != nil && positive(vt.MaliciousVotes) {
		return newVerdict(TierReview, nil)
	}
	if otxSucceeded && otx != nil && positive(otx.PulseCount) {
		return newVerdict(TierReview, nil)
	}
	return newVerdict(TierClean, nil)
}

// URLVerdict treats explicit Safe Browsing and URLScan findings as HIGH. A
// VirusTotal consensus can also be HIGH; smaller malicious or suspicious VT
// signals remain REVIEW rather than becoming a binary malicious verdict.
func URLVerdict(safeBrowsing *SafeBrowsingData, urlscan *URLScanData, vt *URLVTData, sources []SourceMetadata) Verdict {
	if sourceSucceeded(sources, "google_safe_browsing") && safeBrowsing != nil && safeBrowsing.IsSafe != nil && !*safeBrowsing.IsSafe {
		return newVerdict(TierHigh, nil)
	}
	if sourceSucceeded(sources, "urlscan") && urlscan != nil && urlscan.Malicious != nil && *urlscan.Malicious {
		return newVerdict(TierHigh, nil)
	}
	if sourceSucceeded(sources, "virustotal") && vt != nil {
		if hasStrongVirusTotalConsensus(vt.MaliciousVotes, vt.HarmlessVotes, vt.SuspiciousVotes, vt.UndetectedVotes) {
			return newVerdict(TierHigh, nil)
		}
		if positive(vt.MaliciousVotes) || positive(vt.SuspiciousVotes) {
			return newVerdict(TierReview, nil)
		}
	}
	return newVerdict(TierClean, nil)
}

// HashVerdict treats a confirmed MalwareBazaar entry, a VT threat label, or a
// strong VT consensus as HIGH. CIRCL known-good data remains available to the
// caller but must not erase independent malicious evidence from other sources.
func HashVerdict(vt *HashVTData, malwareBazaar *MalwareBazaarData, _ *CIRCLData, sources []SourceMetadata) Verdict {
	if sourceSucceeded(sources, "malwarebazaar") && hasMalwareBazaarEvidence(malwareBazaar) {
		return newVerdict(TierHigh, nil)
	}
	if sourceSucceeded(sources, "virustotal") && vt != nil {
		if vt.ThreatLabel != nil && strings.TrimSpace(*vt.ThreatLabel) != "" {
			return newVerdict(TierHigh, nil)
		}
		if hasStrongVirusTotalConsensus(vt.MaliciousVotes, vt.HarmlessVotes, vt.SuspiciousVotes, vt.UndetectedVotes) {
			return newVerdict(TierHigh, nil)
		}
		if positive(vt.MaliciousVotes) || positive(vt.SuspiciousVotes) {
			return newVerdict(TierReview, nil)
		}
	}
	return newVerdict(TierClean, nil)
}

func positive(value *int) bool {
	return value != nil && *value > 0
}

func sourceSucceeded(sources []SourceMetadata, name string) bool {
	for _, source := range sources {
		if source.Source == name {
			return source.Success
		}
	}
	return false
}

// hasStrongVirusTotalConsensus requires a malicious majority across every VT
// verdict-bearing category. Missing categories cannot establish consensus.
func hasStrongVirusTotalConsensus(malicious, harmless, suspicious, undetected *int) bool {
	if malicious == nil || harmless == nil || suspicious == nil || undetected == nil {
		return false
	}
	return *malicious > *harmless+*suspicious+*undetected
}

func hasMalwareBazaarEvidence(data *MalwareBazaarData) bool {
	if data == nil {
		return false
	}
	return (data.Signature != nil && strings.TrimSpace(*data.Signature) != "") ||
		(data.FileName != nil && strings.TrimSpace(*data.FileName) != "")
}
