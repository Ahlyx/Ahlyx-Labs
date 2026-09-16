const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '../..');
const frontend = path.join(root, 'frontend');
const read = (file) => fs.readFileSync(path.join(frontend, file), 'utf8');

const indexablePages = [
    ['landing/index.html', 'https://ahlyxlabs.com/'],
    ['services/index.html', 'https://ahlyxlabs.com/services'],
    ['enrichment/index.html', 'https://ahlyxlabs.com/enrichment'],
    ['scanner/index.html', 'https://ahlyxlabs.com/scanner'],
    ['hardware/index.html', 'https://ahlyxlabs.com/hardware'],
    ['pcap/index.html', 'https://ahlyxlabs.com/pcap'],
    ['research/index.html', 'https://ahlyxlabs.com/research'],
    ['research/rustchain.html', 'https://ahlyxlabs.com/research/rustchain'],
    ['research/onedragon.html', 'https://ahlyxlabs.com/research/onedragon'],
    ['notes/index.html', 'https://ahlyxlabs.com/notes'],
    ['notes/custom-domain-email.html', 'https://ahlyxlabs.com/notes/custom-domain-email']
];

test('indexable pages have one apex canonical and complete share metadata', () => {
    for (const [file, canonical] of indexablePages) {
        const html = read(file);
        assert.equal((html.match(/<title>/g) || []).length, 1, `${file} has one title`);
        assert.match(html, /<meta name="description" content="[^"]+">/, `${file} has a description`);
        assert.equal((html.match(/rel="canonical"/g) || []).length, 1, `${file} has one canonical`);
        assert.match(html, new RegExp(`rel="canonical" href="${canonical.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`), `${file} self-canonicalizes`);
        assert.match(html, /<meta property="og:site_name" content="Ahlyx Labs">/, `${file} declares site name`);
        assert.match(html, new RegExp(`property="og:url" content="${canonical.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`), `${file} has matching Open Graph URL`);
        assert.match(html, /<meta property="og:image" content="https:\/\/ahlyxlabs\.com\/assets\/brand\/ahlyxlabs-social\.png">/, `${file} has social image`);
    }
});

test('sitemap contains only intended apex indexable URLs', () => {
    const sitemap = read('sitemap.xml');
    const urls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
    assert.deepEqual(urls, indexablePages.map(([, url]) => url));
    assert.ok(urls.every((url) => url.startsWith('https://ahlyxlabs.com/')));
    assert.ok(urls.every((url) => !url.includes('api.ahlyxlabs.com') && !url.includes('www.')));
});

test('security.txt is complete and the public assets exist', () => {
    const security = read('.well-known/security.txt');
    assert.match(security, /^Contact: mailto:alex@ahlyxlabs\.com$/m);
    assert.match(security, /^Expires: 2027-09-01T00:00:00Z$/m);
    assert.match(security, /^Canonical: https:\/\/ahlyxlabs\.com\/.well-known\/security\.txt$/m);
    assert.ok(fs.statSync(path.join(frontend, 'favicon-96x96.png')).size > 0);
    assert.ok(fs.statSync(path.join(frontend, 'assets/brand/ahlyxlabs-social.png')).size > 0);
});

test('Vercel routes do not turn missing nested paths into successful pages', () => {
    const config = JSON.parse(read('vercel.json'));
    assert.ok(config.rewrites.every((rewrite) => !rewrite.source.includes('(.*)')));
});

test('every mailto contact option has a Gmail compose fallback', () => {
    for (const file of ['landing/index.html', 'services/index.html']) {
        const html = read(file);
        const mailtoLinks = html.match(/href="mailto:alex@ahlyxlabs\.com/g) || [];
        const gmailLinks = html.match(/https:\/\/mail\.google\.com\/mail\/\?view=cm/g) || [];
        assert.ok(mailtoLinks.length > 0, `${file} has mailto links to check`);
        assert.equal(gmailLinks.length, mailtoLinks.length, `${file} provides a Gmail fallback for every mailto link`);
    }
});
