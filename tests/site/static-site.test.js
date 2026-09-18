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
    ['lab/index.html', 'https://ahlyxlabs.com/lab'],
    ['lab/auditmcp.html', 'https://ahlyxlabs.com/lab/auditmcp'],
    ['lab/conveyance.html', 'https://ahlyxlabs.com/lab/conveyance'],
    ['lab/security-enrichment.html', 'https://ahlyxlabs.com/lab/security-enrichment'],
    ['lab/baptisia.html', 'https://ahlyxlabs.com/lab/baptisia'],
    ['lab/pcap-agent.html', 'https://ahlyxlabs.com/lab/pcap-agent'],
    ['lab/network-scanner.html', 'https://ahlyxlabs.com/lab/network-scanner'],
    ['lab/hardware-dashboard.html', 'https://ahlyxlabs.com/lab/hardware-dashboard'],
    ['enrichment/index.html', 'https://ahlyxlabs.com/enrichment'],
    ['hardware/index.html', 'https://ahlyxlabs.com/hardware'],
    ['pcap/index.html', 'https://ahlyxlabs.com/pcap'],
    ['security/index.html', 'https://ahlyxlabs.com/security'],
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
    const projectSlugs = ['auditmcp', 'conveyance', 'security-enrichment', 'baptisia', 'pcap-agent', 'network-scanner', 'hardware-dashboard'];
    assert.deepEqual(config.rewrites.filter((rewrite) => rewrite.source.startsWith('/lab')).map((rewrite) => rewrite.source),
        ['/lab', ...projectSlugs.map((slug) => `/lab/${slug}`)]);
    assert.ok(!config.rewrites.some((rewrite) => rewrite.source === '/lab/(.*)'));
    const legacyRoutes = ['/projects', ...projectSlugs.map((slug) => `/projects/${slug}`)];
    assert.deepEqual(config.redirects.filter((redirect) => redirect.source.startsWith('/projects')), legacyRoutes.map((source, index) => ({
        source,
        destination: ['/lab', ...projectSlugs.map((slug) => `/lab/${slug}`)][index],
        permanent: true
    })));
    assert.ok(!config.redirects.some((redirect) => redirect.source === '/projects/(.*)'));
});

test('the retired hosted scanner route redirects to the local-tool repository', () => {
    const config = JSON.parse(read('vercel.json'));
    assert.deepEqual(config.redirects.find((redirect) => redirect.source === '/scanner'), {
        source: '/scanner',
        destination: 'https://github.com/Ahlyx/Network-Scanner',
        permanent: false
    });
    assert.ok(!config.rewrites.some((rewrite) => rewrite.source === '/scanner'));
    assert.ok(!fs.existsSync(path.join(frontend, 'scanner/index.html')), 'obsolete hosted scanner assets are removed');
});

test('Vercel headers protect documents without breaking PCAP local mode', () => {
    const config = JSON.parse(read('vercel.json'));
    const headers = Object.fromEntries(config.headers[0].headers.map((header) => [header.key, header.value]));
    const csp = headers['Content-Security-Policy'];
    assert.match(csp, /object-src 'none'/);
    assert.match(csp, /base-uri 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /ws:\/\/localhost:7777/);
    assert.match(csp, /wss:\/\/api\.ahlyxlabs\.com/);
    assert.doesNotMatch(csp, /upgrade-insecure-requests/);
    assert.doesNotMatch(csp, /script-src[^;]*'unsafe-inline'/);
    assert.equal(headers['Referrer-Policy'], 'no-referrer');
    assert.equal(headers['X-Content-Type-Options'], 'nosniff');
});

test('Google Analytics is only loaded by the consent-aware external loader', () => {
    const htmlFiles = [];
    const walk = (directory) => {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const target = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(target);
            else if (entry.name.endsWith('.html')) htmlFiles.push(target);
        }
    };
    walk(frontend);
    for (const file of htmlFiles) {
        const html = fs.readFileSync(file, 'utf8');
        assert.doesNotMatch(html, /googletagmanager\.com\/gtag\/js/, `${file} has no unconditional Google tag`);
        assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${file} has no executable inline event handler`);
    }
    const analytics = read('assets/analytics.js');
    assert.match(analytics, /localStorage\.getItem\(consentKey\)/);
    assert.match(analytics, /if \(consent === 'accepted'\)/);
    assert.match(analytics, /script\.src = 'https:\/\/www\.googletagmanager\.com\/gtag\/js\?id='/);
});

test('subpages expose the same primary navigation destinations', () => {
    const subpages = [
        'services/index.html',
        'enrichment/index.html',
        'hardware/index.html',
        'pcap/index.html',
        'research/index.html',
        'research/rustchain.html',
        'research/onedragon.html',
        'notes/index.html',
        'notes/custom-domain-email.html',
        'landing/privacy.html'
    ];
    const destinations = ['/services', '/#work', '/research', '/notes', '/#lab', '/#about', '/#contact', 'https://github.com/Ahlyx'];

    for (const file of subpages) {
        const html = read(file);
        for (const destination of destinations) {
            assert.match(html, new RegExp(`<a href="${destination.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`), `${file} links to ${destination}`);
        }
    }
});

test('content pages use the shared homepage header while tools remain compact', () => {
    const site = read('assets/site.css');
    assert.match(site, /\.site-header \{[\s\S]*background: rgba\(9, 10, 11, \.96\)/,
        'shared content header keeps the homepage background treatment');
    assert.match(site, /\.header-inner \{[\s\S]*min-height: 6\.5rem/,
        'shared content header keeps the homepage height');
    assert.match(site, /\.brand-lockup \{[\s\S]*width: clamp\(22rem, 35vw, 34rem\)/,
        'shared content header keeps the homepage brand-lockup size');
    assert.match(site, /\.header-identity \{[\s\S]*display: flex;[\s\S]*align-items: center;[\s\S]*min-width: 0/,
        'Back controls and brand lockups stay inline in the shared identity wrapper');

    for (const file of [
        'services/index.html', 'notes/index.html', 'notes/custom-domain-email.html',
        'research/index.html', 'research/rustchain.html', 'research/onedragon.html',
        'landing/privacy.html', 'security/index.html'
    ]) {
        const html = read(file);
        assert.match(html, /class="header-identity"/, `${file} uses the shared brand-lockup wrapper`);
        assert.match(html, /<button class="back-button" type="button" data-back-fallback="[^"]+"><span aria-hidden="true">&larr;<\/span> Back<\/button>/,
            `${file} has the shared inline Back control with the standard label`);
        assert.match(html, /class="site-nav"/, `${file} uses the shared navigation styling`);
    }

    for (const file of ['landing/privacy.html', 'security/index.html']) {
        const html = read(file);
        assert.match(html, /<body class="content-page policy-page">/, `${file} is a standard content page`);
        assert.doesNotMatch(html, /href="\/assets\/tool-theme\.css"/, `${file} does not inherit the compact tool header`);
    }

    for (const file of ['enrichment/index.html', 'hardware/index.html', 'pcap/index.html']) {
        assert.match(read(file), /<body class="tool-page">/, `${file} retains the compact tool-header theme`);
    }

    assert.doesNotMatch(read('landing/style.css'), /\.site-header \{/, 'homepage header structure is not duplicated');
    assert.doesNotMatch(read('services/style.css'), /\.site-header \{/, 'services does not duplicate header structure');
    assert.doesNotMatch(read('research/shared.css'), /\.site-header \{/, 'research does not duplicate header structure');
});

test('frontend source contains no known mojibake sequences', () => {
    const textFiles = [];
    const walk = (directory) => {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const target = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(target);
            else if (/\.(?:html|css|js|xml|txt)$/.test(entry.name)) textFiles.push(target);
        }
    };
    walk(frontend);
    const malformed = /(?:\uFFFD|Ã.|Â.|â€|â†|â—|å¸|èŠ|è¯|åˆ)/;
    for (const file of textFiles) {
        assert.doesNotMatch(fs.readFileSync(file, 'utf8'), malformed, `${file} has valid UTF-8 text`);
    }
});

test('tool pages rely on centralized analytics rather than page-specific GA bootstraps', () => {
    for (const file of ['enrichment/app.js', 'hardware/script.js', 'pcap/app.js']) {
        const source = read(file);
        assert.doesNotMatch(source, /const GA_ID|const CONSENT_KEY|window\.dataLayer/,
            `${file} has no duplicate GA bootstrap`);
    }
    for (const file of ['landing/index.html', 'enrichment/index.html', 'hardware/index.html']) {
        assert.doesNotMatch(read(file), /id="consent-banner"/, `${file} has no duplicate consent banner`);
    }
});

test('hardware output keeps generic OS telemetry and readable metric units', () => {
    const script = read('hardware/script.js');
    const style = read('hardware/style.css');
    assert.match(script, /appendRow\(container, 'host_os',\s+d\.host_os\)/);
    assert.match(script, /if \(d\.platform\) appendRow/, 'blank platforms are not rendered');
    assert.match(style, /white-space: nowrap/, 'value and unit stay together');
    assert.doesNotMatch(style, /word-break: break-all/, 'large metric values do not break every character');
});

test('Gmail compose fallback is available in site footers without bloating primary contact actions', () => {
    for (const file of ['landing/index.html', 'services/index.html']) {
        const html = read(file);
        assert.match(html, /<footer class="site-footer">[\s\S]*https:\/\/mail\.google\.com\/mail\/\?view=cm[\s\S]*<\/footer>/, `${file} footer has Gmail fallback`);
        const bodyBeforeFooter = html.split('<footer class="site-footer">')[0];
        assert.doesNotMatch(bodyBeforeFooter, /Email via Gmail/, `${file} keeps Gmail fallback out of primary CTAs`);
    }
});

test('every public footer exactly matches the homepage canonical footer', () => {
    const canonicalFooter = read('landing/index.html').match(/<footer class="site-footer">[\s\S]*?<\/footer>/)[0];
    const requiredLinks = [
        'https://github.com/Ahlyx',
        'https://twitter.com/AhIyxx',
        'mailto:alex@ahlyxlabs.com',
        'https://mail.google.com/mail/?view=cm&amp;fs=1&amp;to=alex%40ahlyxlabs.com',
        '/security',
        '/privacy',
        '/llms.txt'
    ];
    const footerPages = [];
    const walk = (directory) => {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const target = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(target);
            else if (entry.name.endsWith('.html') && fs.readFileSync(target, 'utf8').includes('site-footer')) footerPages.push(target);
        }
    };
    walk(frontend);

    for (const page of footerPages) {
        const footer = fs.readFileSync(page, 'utf8').match(/<footer class="site-footer">[\s\S]*?<\/footer>/)[0];
        assert.equal(footer, canonicalFooter, `${page} uses the canonical homepage footer`);
        for (const link of requiredLinks) assert.ok(footer.includes(`href="${link}"`), `${page} includes ${link}`);
        assert.doesNotMatch(footer, /Build notes[\s\S]*notes\/custom-domain-email/, `${page} has no unrelated PCAP build-notes footer link`);
    }
    assert.ok(footerPages.some((page) => page.endsWith(path.join('security', 'index.html'))));
    assert.ok(footerPages.some((page) => page.endsWith(path.join('landing', 'privacy.html'))));
});

test('shared CSS owns the canonical footer structure and aligned Lab CTAs', () => {
    const site = read('assets/site.css');
    assert.match(site, /\.site-footer \{[\s\S]*display: flex;[\s\S]*justify-content: center;[\s\S]*flex-wrap: wrap;[\s\S]*border-top: 1px solid var\(--border\)/,
        'shared CSS centers and wraps every footer');
    assert.match(site, /\.site-footer a \{[\s\S]*text-decoration: none/, 'shared CSS styles footer links');
    assert.match(site, /\.site-footer \.sep \{[\s\S]*color: var\(--border\)/, 'shared CSS styles footer separators');

    const landing = read('landing/index.html');
    assert.match(landing, /href="\/lab\/network-scanner"[^>]*>View project/, 'Network Scanner links to its internal explanation with project wording');
    assert.doesNotMatch(landing, /href="\/scanner"/, 'Network Scanner does not point to the retired hosted page');
    const landingStyles = read('landing/style.css');
    assert.match(landingStyles, /\.lab-entry \{ display: flex; flex-direction: column;/, 'Lab cards use flex-column layout');
    assert.match(landingStyles, /\.lab-entry \.text-link \{ margin-top: auto; padding-top: 1\.2rem; \}/,
        'Lab CTA alignment uses auto margin instead of fixed card heights');
    assert.match(landingStyles, /\.lab-actions \.text-link \{ margin-top: 0; padding-top: 0; \}/,
        'paired Lab card actions form one clean action row');
    assert.match(landingStyles, /\.about-section \{[\s\S]*grid-template-columns: var\(--homepage-label-column\)/,
        'About uses the shared homepage label column');
    assert.match(landingStyles, /\.contact-inner \{[\s\S]*grid-template-columns: var\(--homepage-label-column\)/,
        'Contact uses the shared homepage label column');
});

test('project pages expose complete static explanations and tool relationships', () => {
    const projects = [
        ['auditmcp', 'https://github.com/Ahlyx/auditmcp'],
        ['conveyance', 'https://github.com/Ahlyx/Conveyance'],
        ['security-enrichment', 'https://github.com/Ahlyx/Ahlyx-Labs/tree/master/internal/enrichment'],
        ['baptisia', 'https://github.com/Ahlyx/Baptisia'],
        ['pcap-agent', 'https://github.com/Ahlyx/pcap-agent'],
        ['network-scanner', 'https://github.com/Ahlyx/Network-Scanner'],
        ['hardware-dashboard', 'https://github.com/Ahlyx/Ahlyx-Labs/tree/master/internal/hardware']
    ];
    for (const [slug, source] of projects) {
        const html = read(`lab/${slug}.html`);
        assert.equal((html.match(/<h1/g) || []).length, 1, `${slug} has one H1`);
        for (const anchor of ['overview', 'how-it-works', 'getting-started', 'limitations']) {
            assert.match(html, new RegExp(`id="${anchor}"`), `${slug} has #${anchor}`);
        }
        const reviewed = html.match(/Last reviewed: (\d{4}-\d{2}-\d{2})/);
        assert.ok(reviewed, `${slug} has a YYYY-MM-DD review date`);
        assert.equal(new Date(`${reviewed[1]}T00:00:00Z`).toISOString().slice(0, 10), reviewed[1],
            `${slug} has a valid review date`);
        assert.ok(html.includes(source), `${slug} links to its source`);
        assert.match(html, /"@type":"WebPage"/, `${slug} declares WebPage schema`);
        assert.match(html, /"@type":"SoftwareSourceCode"/, `${slug} declares source-code schema`);
    }
    assert.match(read('lab/security-enrichment.html'), /id="api"/);
    for (const [file, destination] of [
        ['enrichment/index.html', '/lab/security-enrichment'],
        ['pcap/index.html', '/lab/pcap-agent'],
        ['hardware/index.html', '/lab/hardware-dashboard']
    ]) assert.match(read(file), new RegExp(`href="${destination}"`), `${file} links to its project overview`);
});

test('Lab owns project browsing and paired project/tool actions are ordered consistently', () => {
    const landing = read('landing/index.html');
    const featured = landing.match(/<section class="content-section section-shell" id="work"[\s\S]*?<\/section>/)[0];
    const lab = landing.match(/<section class="content-section section-shell" id="lab"[\s\S]*?<\/section>/)[0];
    assert.doesNotMatch(featured, /Browse projects/);
    assert.match(lab, /href="\/lab">Browse projects/);
    assert.doesNotMatch(landing, /Use tool/);

    for (const [project, tool] of [
        ['/lab/security-enrichment', '/enrichment'],
        ['/lab/pcap-agent', '/pcap'],
        ['/lab/hardware-dashboard', '/hardware']
    ]) {
        assert.ok(landing.indexOf(project) < landing.indexOf(tool), `${project} precedes ${tool} on the homepage`);
    }

    const directory = read('lab/index.html');
    for (const [project, tool] of [
        ['/lab/security-enrichment', '/enrichment'],
        ['/lab/pcap-agent', '/pcap'],
        ['/lab/hardware-dashboard', '/hardware']
    ]) {
        assert.ok(directory.indexOf(project) < directory.indexOf(tool), `${project} precedes ${tool} in the Lab directory`);
    }
    assert.doesNotMatch(directory, /Use tool/);
    assert.match(directory, /class="subtle-link" href="\/enrichment">Open tool/);
    assert.match(directory, /class="subtle-link" href="\/pcap">Open tool/);
    assert.match(directory, /class="subtle-link" href="\/hardware">Open tool/);
});

test('llms.txt is a plain-text project index and is excluded from the sitemap', () => {
    const llms = read('llms.txt');
    assert.match(llms, /^# Ahlyx Labs/m);
    for (const slug of ['auditmcp', 'conveyance', 'security-enrichment', 'baptisia', 'pcap-agent', 'network-scanner', 'hardware-dashboard']) {
        assert.ok(llms.includes(`https://ahlyxlabs.com/lab/${slug}`));
    }
    assert.doesNotMatch(read('sitemap.xml'), /llms\.txt/);
    const config = JSON.parse(read('vercel.json'));
    assert.deepEqual(config.headers.find((entry) => entry.source === '/llms.txt').headers,
        [{ key: 'Content-Type', value: 'text/plain; charset=utf-8' }]);
});
