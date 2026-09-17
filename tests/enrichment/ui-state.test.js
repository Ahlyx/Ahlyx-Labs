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

const mixedDomain = ui.getVerdict({ virustotal: { malicious_votes: 2, harmless_votes: 59 } }, 'domain');
assert.equal(mixedDomain.tier, 'review', 'minority VT detections are a review signal');
assert.equal(mixedDomain.isMalicious, false, 'minority VT detections do not become HIGH THREAT');
const cleanDomain = ui.getVerdict({ virustotal: { malicious_votes: 0, harmless_votes: 59 } }, 'domain');
assert.equal(cleanDomain.tier, 'clean', 'a domain with no malicious provider signal remains CLEAN');
const corroboratedDomain = ui.getVerdict({
    virustotal: { malicious_votes: 12, harmless_votes: 1 },
    otx: { pulse_count: 2 },
    sources: [
        { source: 'virustotal', success: true },
        { source: 'alienvault_otx', success: true }
    ]
}, 'domain');
assert.equal(corroboratedDomain.tier, 'high', 'strong VT consensus plus an independent OTX pulse is HIGH THREAT');
assert.equal(corroboratedDomain.isMalicious, true, 'corroborated evidence is marked malicious');
const unavailableOTX = ui.getVerdict({
    virustotal: { malicious_votes: 12, harmless_votes: 1 },
    sources: [
        { source: 'virustotal', success: true },
        { source: 'alienvault_otx', success: false }
    ]
}, 'domain');
assert.equal(unavailableOTX.tier, 'review', 'an unavailable source cannot turn a domain into HIGH THREAT');
const maliciousURL = ui.getVerdict({ safe_browsing: { is_safe: false } }, 'url');
assert.equal(maliciousURL.tier, 'high', 'an explicit malicious URL provider verdict remains prominent');

const app = fs.readFileSync(__dirname + '/../../frontend/enrichment/app.js', 'utf8');
assert.match(app, /\['A', data\.dns\.a\]/, 'domain DNS renders A records from the API schema');
assert.match(app, /\['AAAA', data\.dns\.aaaa\]/, 'domain DNS renders AAAA records from the API schema');
assert.match(app, /\['MX', data\.dns\.mx\]/, 'domain DNS renders MX records from the API schema');
assert.match(app, /\['NS', data\.dns\.ns\]/, 'domain DNS renders NS records from the API schema');
assert.match(app, /\['TXT', data\.dns\.txt\]/, 'domain DNS renders TXT records from the API schema');
assert.match(app, /malicious \/ \$\{data\.virustotal\.harmless_votes/, 'VirusTotal domain evidence is displayed as a ratio');
assert.match(app, /createCard\('ALIENVAULT OTX'/, 'independent OTX evidence is visible in the domain result cards');

console.log('enrichment UI-state tests passed');
