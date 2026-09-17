(function (global) {
    'use strict';

    function urlControlState(queryType, activeSubmissionEnabled) {
        const isURL = queryType === 'url';
        return {
            showPrivacyWarning: isURL,
            showActiveSubmission: isURL && activeSubmissionEnabled === true
        };
    }

    function positive(value) {
        return Number.isFinite(Number(value)) && Number(value) > 0;
    }

    function sourceSucceeded(data, sourceName) {
        if (!Array.isArray(data.sources)) return true;
        const source = data.sources.find((entry) => entry.source === sourceName);
        return !source || source.success === true;
    }

    function hasStrongVirusTotalConsensus(data) {
        const vt = data.virustotal || {};
        const malicious = Number(vt.malicious_votes) || 0;
        const harmless = Number(vt.harmless_votes) || 0;

        // This is an explainable evidence rule, not a composite score:
        // malicious verdicts must outnumber harmless verdicts before
        // VirusTotal is treated as a consensus. It is never enough alone.
        return malicious > 0 && malicious > harmless && sourceSucceeded(data, 'virustotal');
    }

    function getVerdict(data, type) {
        if (type === 'ip' && data.threat_tier) {
            return {
                tier: data.threat_tier,
                score: data.threat_score,
                isMalicious: data.threat_tier === 'high' || data.threat_tier === 'critical'
            };
        }
        if (type === 'domain') {
            // A HIGH domain verdict requires independent, visible evidence:
            // strong VirusTotal consensus plus an AlienVault OTX pulse. A
            // missing or failed source never contributes positive evidence.
            if (hasStrongVirusTotalConsensus(data) &&
                positive(data.otx && data.otx.pulse_count) &&
                sourceSucceeded(data, 'alienvault_otx')) {
                return { tier: 'high', score: null, isMalicious: true };
            }
            if (positive(data.virustotal && data.virustotal.malicious_votes)) {
                return { tier: 'review', score: null, isMalicious: false };
            }
            if (positive(data.otx && data.otx.pulse_count) && sourceSucceeded(data, 'alienvault_otx')) {
                return { tier: 'review', score: null, isMalicious: false };
            }
            return { tier: 'clean', score: null, isMalicious: false };
        }
        if (type === 'url') {
            const malicious = data.is_malicious === true ||
                (data.safe_browsing && data.safe_browsing.is_safe === false) ||
                (data.urlscan && data.urlscan.malicious === true);
            return { tier: malicious ? 'high' : 'clean', score: null, isMalicious: malicious };
        }
        if (type === 'hash') {
            const malicious = data.is_malicious === true ||
                Boolean(data.malware_bazaar && data.malware_bazaar.signature) ||
                Boolean(data.virustotal && data.virustotal.threat_label);
            return { tier: malicious ? 'high' : 'clean', score: null, isMalicious: malicious };
        }
        return { tier: 'clean', score: null, isMalicious: false };
    }

    global.AhlyxEnrichmentUI = { urlControlState, getVerdict };
}(window));
