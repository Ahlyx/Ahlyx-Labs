(function (global) {
    'use strict';

    function urlControlState(queryType, activeSubmissionEnabled) {
        const isURL = queryType === 'url';
        return {
            showPrivacyWarning: isURL,
            showActiveSubmission: isURL && activeSubmissionEnabled === true
        };
    }

    const TIER_LABELS = Object.freeze({
        clean: '\u2713 CLEAN',
        low: '\u2691 LOW RISK',
        medium: '\u26A0 MEDIUM RISK',
        review: 'REVIEW \u2014 MIXED SIGNALS',
        high: '\u26A0 HIGH THREAT',
        critical: '\u26A0 CRITICAL THREAT'
    });

    function labelForTier(tier) {
        return TIER_LABELS[tier] || TIER_LABELS.clean;
    }

    // New API responses carry a backend-computed canonical verdict. The
    // compact fallbacks preserve rendering for an older API during rollout;
    // they deliberately do not recreate provider-specific scoring in the UI.
    function getVerdict(data) {
        if (data && data.verdict && typeof data.verdict.tier === 'string') {
            return {
                tier: data.verdict.tier,
                score: Number.isInteger(data.verdict.score) ? data.verdict.score : null,
                isMalicious: data.verdict.is_malicious === true
            };
        }
        if (data && data.threat_tier) {
            return {
                tier: data.threat_tier,
                score: Number.isInteger(data.threat_score) ? data.threat_score : null,
                isMalicious: data.threat_tier === 'high' || data.threat_tier === 'critical'
            };
        }
        const isMalicious = Boolean(data && data.is_malicious === true);
        return { tier: isMalicious ? 'high' : 'clean', score: null, isMalicious };
    }

    global.AhlyxEnrichmentUI = { urlControlState, getVerdict, labelForTier };
}(window));
