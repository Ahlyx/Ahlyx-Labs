// ---------------------------------------------------------------------------
// GA4 bootstrap — must run before DOMContentLoaded so the dataLayer is
// available when the async gtag.js library initialises.
// ---------------------------------------------------------------------------
window.dataLayer = window.dataLayer || [];
function gtag() { dataLayer.push(arguments); }

const CONSENT_KEY = 'analytics_consent';
const GA_ID = 'G-99NT7YXMY8';

const consent = localStorage.getItem(CONSENT_KEY);

if (consent === 'accepted') {
    // User previously accepted — initialise GA4 fully.
    gtag('js', new Date());
    gtag('config', GA_ID);
} else {
    // 'declined' or not yet set — keep GA4 in denied mode.
    gtag('consent', 'default', {
        analytics_storage: 'denied',
        ad_storage: 'denied',
    });
}

// ---------------------------------------------------------------------------
// Consent banner wiring
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
    const banner     = document.getElementById('consent-banner');
    const btnAccept  = document.getElementById('consent-accept');
    const btnDecline = document.getElementById('consent-decline');

    if (!localStorage.getItem(CONSENT_KEY)) {
        banner.classList.remove('hidden');
    }

    btnAccept.addEventListener('click', function () {
        localStorage.setItem(CONSENT_KEY, 'accepted');
        banner.classList.add('hidden');
        gtag('consent', 'update', { analytics_storage: 'granted' });
        gtag('js', new Date());
        gtag('config', GA_ID);
    });

    btnDecline.addEventListener('click', function () {
        localStorage.setItem(CONSENT_KEY, 'declined');
        banner.classList.add('hidden');
    });
});

// ---------------------------------------------------------------------------
// API config
// ---------------------------------------------------------------------------
// dev: http://localhost:8080
const API_BASE = 'https://ahlyx-labs.onrender.com/api/v1';

const placeholders = {
    ip: 'Enter an IP address... e.g. 8.8.8.8',
    domain: 'Enter a domain... e.g. google.com',
    url: 'Enter a URL... e.g. https://google.com',
    hash: 'Enter a MD5, SHA1, or SHA256 hash...'
};

const prefixes = {
    ip: 'ip://',
    domain: 'domain://',
    url: 'url://',
    hash: 'hash://'
};

let currentType = 'ip';
let history = [];

// Health check
async function checkHealth() {
    try {
        const res = await fetch('https://ahlyx-labs.onrender.com/health');
        const data = await res.json();
        if (data.status === 'ok') {
            document.getElementById('statusDot').className = 'status-dot online';
            document.getElementById('statusText').textContent = 'online';
        }
    } catch {
        document.getElementById('statusDot').className = 'status-dot offline';
        document.getElementById('statusText').textContent = 'offline';
    }
}

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentType = tab.dataset.type;
        document.getElementById('searchInput').placeholder = placeholders[currentType];
        document.getElementById('searchPrefix').textContent = prefixes[currentType];
        document.getElementById('searchInput').focus();
    });
});

// Example queries
document.querySelectorAll('.example').forEach(btn => {
    btn.addEventListener('click', () => {
        const type = btn.dataset.type;
        const value = btn.dataset.value;
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`.tab[data-type="${type}"]`).classList.add('active');
        currentType = type;
        document.getElementById('searchPrefix').textContent = prefixes[type];
        document.getElementById('searchInput').placeholder = placeholders[type];
        document.getElementById('searchInput').value = value;
        performSearch(value, type);
    });
});

// Search on enter
document.getElementById('searchInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
        const value = e.target.value.trim();
        if (value) performSearch(value, currentType);
    }
});

// Search button
document.getElementById('searchBtn').addEventListener('click', () => {
    const value = document.getElementById('searchInput').value.trim();
    if (value) performSearch(value, currentType);
});

async function performSearch(value, type) {
    const resultsSection = document.getElementById('resultsSection');
    const loading = document.getElementById('loading');
    const resultsContent = document.getElementById('resultsContent');
    const resultsQuery = document.getElementById('resultsQuery');
    const resultsTime = document.getElementById('resultsTime');
    const searchBtn = document.getElementById('searchBtn');

    resultsSection.style.display = 'block';
    loading.style.display = 'flex';
    resultsContent.innerHTML = '';
    resultsQuery.textContent = value;
    resultsTime.textContent = '';
    searchBtn.disabled = true;

    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    const start = Date.now();

    try {
        let endpoint;
        if (type === 'ip') endpoint = `${API_BASE}/ip/${encodeURIComponent(value)}`;
        else if (type === 'domain') endpoint = `${API_BASE}/domain/${encodeURIComponent(value)}`;
        else if (type === 'url') endpoint = `${API_BASE}/url?url=${encodeURIComponent(value)}`;
        else if (type === 'hash') endpoint = `${API_BASE}/hash/${encodeURIComponent(value)}`;

        const res = await fetch(endpoint);
        const data = await res.json();

        if (!res.ok) {
            const detail = data.detail ?? `HTTP ${res.status}`;
            throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
        }

        const elapsed = ((Date.now() - start) / 1000).toFixed(2);

        document.title = `[${value}] — SEC ENRICH`;
        resultsTime.textContent = `${elapsed}s`;
        loading.style.display = 'none';

        renderResults(data, type);
        addToHistory(value, type, data);

    } catch (err) {
        loading.style.display = 'none';
        const errBanner = document.createElement('div');
        errBanner.className = 'verdict-banner malicious';
        const errDot = document.createElement('div');
        errDot.className = 'verdict-dot';
        const errMsg = document.createElement('span');
        errMsg.textContent = `ERROR: ${err.message}`;
        errBanner.appendChild(errDot);
        errBanner.appendChild(errMsg);
        resultsContent.appendChild(errBanner);
    } finally {
        searchBtn.disabled = false;
    }
}

function renderResults(data, type) {
    const container = document.getElementById('resultsContent');
    container.innerHTML = '';

    // Verdict banner
    const isMalicious = data.is_malicious || data.is_tor ||
        (data.abuse && data.abuse.abuse_score >= 80) ||
        (data.virustotal && data.virustotal.malicious_votes > 0);

    const banner = document.createElement('div');
    banner.className = `verdict-banner ${isMalicious ? 'malicious' : 'clean'}`;
    banner.innerHTML = `
        <div class="verdict-dot"></div>
        ${isMalicious ? '⚠ THREAT DETECTED' : '✓ CLEAN'}
    `;
    container.appendChild(banner);

    // Sources
    if (data.sources && data.sources.length > 0) {
        const sourcesRow = document.createElement('div');
        sourcesRow.className = 'sources-row';
        data.sources.forEach(source => {
            const badge = document.createElement('span');
            badge.className = `source-badge ${source.success ? 'success' : 'failed'}`;
            badge.textContent = source.source;
            if (!source.success && source.error) badge.title = source.error;
            sourcesRow.appendChild(badge);
        });
        container.appendChild(sourcesRow);
    }

    // Data grid
    const grid = document.createElement('div');
    grid.className = 'data-grid';

    if (type === 'ip') renderIPCards(data, grid);
    else if (type === 'domain') renderDomainCards(data, grid);
    else if (type === 'url') renderURLCards(data, grid);
    else if (type === 'hash') renderHashCards(data, grid);

    container.appendChild(grid);
}

function createCard(title, rows) {
    const card = document.createElement('div');
    card.className = 'data-card';
    const titleEl = document.createElement('div');
    titleEl.className = 'data-card-title';
    titleEl.textContent = title;
    card.appendChild(titleEl);
    rows.forEach(([key, value, style]) => {
        if (value === undefined) return;
        const row = document.createElement('div');
        row.className = 'data-row';
        const keyEl = document.createElement('span');
        keyEl.className = 'data-key';
        keyEl.textContent = key;
        const valEl = document.createElement('span');
        valEl.className = `data-value ${style || ''}`;
        if (value === null || value === undefined) {
            valEl.classList.add('null');
            valEl.textContent = 'null';
        } else if (typeof value === 'boolean') {
            valEl.classList.add(value ? 'threat' : 'safe');
            valEl.textContent = value.toString();
        } else if (Array.isArray(value)) {
            if (value.length === 0) {
                valEl.classList.add('null');
                valEl.textContent = '[]';
            } else {
                const tags = document.createElement('div');
                tags.className = 'tags';
                value.forEach(v => {
                    const tag = document.createElement('span');
                    tag.className = `tag ${style || ''}`;
                    tag.textContent = v;
                    tags.appendChild(tag);
                });
                valEl.appendChild(tags);
            }
        } else {
            valEl.textContent = value;
        }
        row.appendChild(keyEl);
        row.appendChild(valEl);
        card.appendChild(row);
    });
    return card;
}

function renderIPCards(data, grid) {
    if (data.geolocation) {
        grid.appendChild(createCard('GEOLOCATION', [
            ['country', data.geolocation.country],
            ['region', data.geolocation.region],
            ['city', data.geolocation.city],
            ['latitude', data.geolocation.latitude],
            ['longitude', data.geolocation.longitude],
        ]));
    }
    if (data.abuse) {
        const score = data.abuse.abuse_score;
        grid.appendChild(createCard('ABUSE DATA', [
            ['abuse_score', `${score}/100`, score >= 80 ? 'threat' : score >= 30 ? '' : 'safe'],
            ['total_reports', data.abuse.total_reports],
            ['isp', data.abuse.isp],
            ['usage_type', data.abuse.usage_type],
            ['is_tor', data.abuse.is_tor],
            ['last_reported', data.abuse.last_reported],
        ]));
    }
    if (data.virustotal) {
        grid.appendChild(createCard('VIRUSTOTAL', [
            ['malicious', data.virustotal.malicious_votes, data.virustotal.malicious_votes > 0 ? 'threat' : 'safe'],
            ['harmless', data.virustotal.harmless_votes, 'safe'],
            ['suspicious', data.virustotal.suspicious_votes],
        ]));
    }
    grid.appendChild(createCard('METADATA', [
        ['ip', data.ip],
        ['is_bogon', data.is_bogon],
        ['is_tor', data.is_tor],
        ['query_time', data.timestamp],
    ]));
}

function renderDomainCards(data, grid) {
    if (data.whois) {
        grid.appendChild(createCard('WHOIS', [
            ['registrar', data.whois.registrar],
            ['created', data.whois.creation_date],
            ['expires', data.whois.expiration_date],
            ['age_days', data.whois.domain_age_days],
            ['newly_registered', data.whois.is_newly_registered],
        ]));
    }
    if (data.ssl) {
        grid.appendChild(createCard('SSL / TLS', [
            ['valid', data.ssl.is_valid],
            ['issuer', data.ssl.issuer],
            ['subject', data.ssl.subject],
            ['tls_version', data.ssl.tls_version],
            ['expires', data.ssl.expires_at],
            ['days_left', data.ssl.days_until_expiry, data.ssl.days_until_expiry <= 30 ? 'threat' : 'safe'],
            ['expiring_soon', data.ssl.is_expiring_soon],
            ['self_signed', data.ssl.is_self_signed],
        ]));
    }
    if (data.dns) {
        grid.appendChild(createCard('DNS RECORDS', [
            ['a_records', data.dns.a_records],
            ['mx_records', data.dns.mx_records],
            ['ns_records', data.dns.ns_records],
        ]));
    }
    if (data.virustotal) {
        grid.appendChild(createCard('VIRUSTOTAL', [
            ['malicious', data.virustotal.malicious_votes, data.virustotal.malicious_votes > 0 ? 'threat' : 'safe'],
            ['harmless', data.virustotal.harmless_votes, 'safe'],
            ['categories', data.virustotal.categories],
        ]));
    }
}

function renderURLCards(data, grid) {
    if (data.safe_browsing) {
        grid.appendChild(createCard('GOOGLE SAFE BROWSING', [
            ['is_safe', data.safe_browsing.is_safe],
            ['threats', data.safe_browsing.threats],
        ]));
    }
    if (data.urlscan) {
        grid.appendChild(createCard('URLSCAN', [
            ['verdict', data.urlscan.verdict, data.urlscan.malicious ? 'threat' : 'safe'],
            ['score', data.urlscan.score],
            ['malicious', data.urlscan.malicious],
            ['categories', data.urlscan.categories],
            ['screenshot', data.urlscan.screenshot_url],
        ]));
    }
    if (data.virustotal) {
        grid.appendChild(createCard('VIRUSTOTAL', [
            ['malicious', data.virustotal.malicious_votes, data.virustotal.malicious_votes > 0 ? 'threat' : 'safe'],
            ['harmless', data.virustotal.harmless_votes, 'safe'],
            ['suspicious', data.virustotal.suspicious_votes],
        ]));
    }
}

function renderHashCards(data, grid) {
    grid.appendChild(createCard('HASH INFO', [
        ['hash', data.hash_value],
        ['type', data.hash_type],
        ['is_malicious', data.is_malicious],
        ['is_known_good', data.is_known_good],
    ]));
    if (data.virustotal) {
        grid.appendChild(createCard('VIRUSTOTAL', [
            ['malicious', data.virustotal.malicious_votes, data.virustotal.malicious_votes > 0 ? 'threat' : 'safe'],
            ['harmless', data.virustotal.harmless_votes, 'safe'],
            ['file_type', data.virustotal.file_type],
            ['file_size', data.virustotal.file_size ? `${data.virustotal.file_size} bytes` : null],
            ['name', data.virustotal.meaningful_name],
            ['threat_label', data.virustotal.threat_label, data.virustotal.threat_label ? 'threat' : ''],
        ]));
    }
    if (data.malwarebazaar) {
        grid.appendChild(createCard('MALWAREBAZAAR', [
            ['file_name', data.malwarebazaar.file_name],
            ['file_type', data.malwarebazaar.file_type],
            ['signature', data.malwarebazaar.signature, data.malwarebazaar.signature ? 'threat' : ''],
            ['tags', data.malwarebazaar.tags],
            ['first_seen', data.malwarebazaar.first_seen],
            ['last_seen', data.malwarebazaar.last_seen],
        ]));
    }
    if (data.circl) {
        grid.appendChild(createCard('CIRCL HASHLOOKUP', [
            ['found', data.circl.found],
            ['file_name', data.circl.file_name],
            ['file_size', data.circl.file_size],
            ['trust_level', data.circl.trust_level],
            ['known_good', data.circl.known_good],
        ]));
    }
}

function addToHistory(value, type, data) {
    const isMalicious = data.is_malicious || data.is_tor ||
        (data.abuse && data.abuse.abuse_score >= 80) ||
        (data.virustotal && data.virustotal.malicious_votes > 0);

    history.unshift({
        value,
        type,
        isMalicious,
        timestamp: new Date().toLocaleTimeString()
    });

    if (history.length > 15) history.pop();
    localStorage.setItem('searchHistory', JSON.stringify(history));
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById('historyList');
    list.innerHTML = '';

    if (history.length === 0) {
        list.innerHTML = '<div class="history-empty">No recent queries</div>';
        return;
    }

    history.forEach(item => {
        const el = document.createElement('div');
        el.className = 'history-item';

        const typeEl = document.createElement('span');
        typeEl.className = 'history-type';
        typeEl.textContent = item.type.toUpperCase();

        const valueEl = document.createElement('span');
        valueEl.className = 'history-value';
        valueEl.textContent = item.value;

        const verdictEl = document.createElement('span');
        verdictEl.className = `history-verdict ${item.isMalicious ? 'malicious' : 'clean'}`;
        verdictEl.textContent = item.isMalicious ? '⚠ THREAT' : '✓ CLEAN';

        const timeEl = document.createElement('span');
        timeEl.className = 'history-time';
        timeEl.textContent = item.timestamp;

        el.appendChild(typeEl);
        el.appendChild(valueEl);
        el.appendChild(verdictEl);
        el.appendChild(timeEl);
        el.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelector(`.tab[data-type="${item.type}"]`).classList.add('active');
            currentType = item.type;
            document.getElementById('searchPrefix').textContent = prefixes[item.type];
            document.getElementById('searchInput').placeholder = placeholders[item.type];
            document.getElementById('searchInput').value = item.value;
            performSearch(item.value, item.type);
        });
        list.appendChild(el);
    });
}

document.getElementById('clearHistory').addEventListener('click', () => {
    history = [];
    localStorage.removeItem('searchHistory');
    renderHistory();
});

// Keyboard shortcut: pressing / focuses the search input when it isn't already focused.
document.addEventListener('keydown', e => {
    if (e.key === '/' && document.activeElement !== document.getElementById('searchInput')) {
        e.preventDefault();
        document.getElementById('searchInput').focus();
    }
});

// Load persisted history before first render.
try {
    const saved = localStorage.getItem('searchHistory');
    if (saved) history = JSON.parse(saved);
} catch {
    history = [];
}
renderHistory();

checkHealth();
