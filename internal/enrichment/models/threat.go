package models

// IPThreatTiers, weakest to strongest.
const (
	TierClean    = "clean"
	TierLow      = "low"
	TierMedium   = "medium"
	TierHigh     = "high"
	TierCritical = "critical"
)

// ScoreIPThreat combines AbuseIPDB and VirusTotal signal into a single
// 0-100 composite score and tier, so a weak single-source hit (e.g. 2/57
// VT engines) doesn't render identically to overwhelming, corroborated
// evidence (e.g. AbuseIPDB maxed out with 1,000+ reports).
//
// AbuseIPDB is weighted higher (0.6) than VirusTotal's detection ratio
// (0.4) because it reflects observed abuse reports rather than static
// signature matching, then report volume and Tor status apply as
// evidence-strength modifiers on top of the base score.
func ScoreIPThreat(abuse *AbuseData, vt *VTIPData, isTor bool) (int, string) {
	var abuseComponent, vtComponent float64
	haveAbuse := abuse != nil && abuse.AbuseScore != nil
	haveVT := false

	if haveAbuse {
		abuseComponent = float64(*abuse.AbuseScore)
	}

	if vt != nil && vt.MaliciousVotes != nil {
		total := *vt.MaliciousVotes
		if vt.HarmlessVotes != nil {
			total += *vt.HarmlessVotes
		}
		if vt.SuspiciousVotes != nil {
			total += *vt.SuspiciousVotes
		}
		if vt.UndetectedVotes != nil {
			total += *vt.UndetectedVotes
		}
		if total > 0 {
			haveVT = true
			vtComponent = float64(*vt.MaliciousVotes) / float64(total) * 100
		}
	}

	var score float64
	switch {
	case haveAbuse && haveVT:
		score = 0.6*abuseComponent + 0.4*vtComponent
	case haveAbuse:
		score = abuseComponent
	case haveVT:
		score = vtComponent
	default:
		return 0, TierClean
	}

	if haveAbuse && abuse.TotalReports != nil {
		switch {
		case *abuse.TotalReports >= 1000:
			score += 15
		case *abuse.TotalReports >= 100:
			score += 5
		}
	}

	if isTor {
		score += 10
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	rounded := int(score + 0.5)

	var tier string
	switch {
	case rounded >= 80:
		tier = TierCritical
	case rounded >= 50:
		tier = TierHigh
	case rounded >= 25:
		tier = TierMedium
	case rounded >= 10:
		tier = TierLow
	default:
		tier = TierClean
	}

	return rounded, tier
}
