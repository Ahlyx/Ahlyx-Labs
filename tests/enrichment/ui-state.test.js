const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(__dirname + '/../../frontend/enrichment/ui-state.js', 'utf8');
const context = { window: {} };
vm.createContext(context);
vm.runInContext(source, context);
const ui = context.window.AhlyxEnrichmentUI;

for (const type of ['ip', 'domain', 'hash']) {
    const state = ui.urlControlState(type, true);
    assert.equal(state.showPrivacyWarning, false, `${type} never shows URL privacy text`);
    assert.equal(state.showActiveSubmission, false, `${type} never shows URLScan controls`);
}
assert.deepEqual(JSON.parse(JSON.stringify(ui.urlControlState('url', false))), {
    showPrivacyWarning: true,
    showActiveSubmission: false
}, 'URL tab hides active submission when the operator has disabled it');
assert.deepEqual(JSON.parse(JSON.stringify(ui.urlControlState('url', true))), {
    showPrivacyWarning: true,
    showActiveSubmission: true
}, 'URL tab alone reveals enabled active submission');

const labels = {
    clean: '✓ CLEAN',
    low: '⚑ LOW RISK',
    medium: '⚠ MEDIUM RISK',
    review: 'REVIEW — MIXED SIGNALS',
    high: '⚠ HIGH THREAT',
    critical: '⚠ CRITICAL THREAT'
};
for (const [tier, label] of Object.entries(labels)) {
    assert.equal(ui.labelForTier(tier), label, `${tier} has the canonical label`);
}

const museDomain = ui.getVerdict({
    verdict: { tier: 'review', score: null, is_malicious: false }
});
assert.equal(museDomain.tier, 'review', 'the API review verdict remains review in the UI');
assert.equal(museDomain.isMalicious, false, 'review does not become malicious in the UI');
assert.equal(ui.labelForTier(museDomain.tier), 'REVIEW — MIXED SIGNALS',
    'the Muse-style OTX-only result has the same label in banner and history rendering');

const ipFallback = ui.getVerdict({ threat_tier: 'medium', threat_score: 25 });
assert.deepEqual(JSON.parse(JSON.stringify(ipFallback)), {
    tier: 'medium', score: 25, isMalicious: false
}, 'older IP responses retain their existing compatible fallback');

const app = fs.readFileSync(__dirname + '/../../frontend/enrichment/app.js', 'utf8');
assert.match(app, /\['A', data\.dns\.a\]/, 'domain DNS renders A records from the API schema');
assert.match(app, /\['AAAA', data\.dns\.aaaa\]/, 'domain DNS renders AAAA records from the API schema');
assert.match(app, /\['MX', data\.dns\.mx\]/, 'domain DNS renders MX records from the API schema');
assert.match(app, /\['NS', data\.dns\.ns\]/, 'domain DNS renders NS records from the API schema');
assert.match(app, /\['TXT', data\.dns\.txt\]/, 'domain DNS renders TXT records from the API schema');
assert.match(app, /malicious \/ \$\{data\.virustotal\.harmless_votes/, 'VirusTotal domain evidence is displayed as a ratio');
assert.match(app, /createCard\('ALIENVAULT OTX'/, 'independent OTX evidence is visible in the domain result cards');
assert.match(app, /label: window\.AhlyxEnrichmentUI\.labelForTier\(verdict\.tier\)/,
    'the main banner uses the shared tier label helper');
assert.match(app, /verdictEl\.textContent = window\.AhlyxEnrichmentUI\.labelForTier\(tier\)/,
    'Recent Queries uses the same tier label helper');
assert.doesNotMatch(app, /const TIER_LABELS/, 'the app does not keep a second tier label mapping');
assert.match(app, /if \(type !== 'url'\) addToHistory/, 'full URLs remain excluded from Recent Queries');

console.log('enrichment UI-state tests passed');
