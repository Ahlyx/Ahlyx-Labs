// Run with: node tests/enrichment/privacy.test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');

const app = fs.readFileSync(__dirname + '/../../frontend/enrichment/app.js', 'utf8');
const page = fs.readFileSync(__dirname + '/../../frontend/enrichment/index.html', 'utf8');

assert.ok(!app.includes('/url?url='), 'full URL values are never placed in an API query string');
assert.match(app, /method:\s*'POST'/, 'URL enrichment uses POST');
assert.match(app, /JSON\.stringify\(\{ url: value, submit_urlscan: activeSubmission \}\)/,
    'URL request body contains the URL and explicit URLScan consent');
assert.match(app, /if \(type !== 'url'\) addToHistory/, 'URL searches are not persisted in localStorage history');
assert.match(page, /private paths, identifiers, or tokens/, 'UI warns before active third-party URL submission');

console.log('enrichment privacy tests passed');
