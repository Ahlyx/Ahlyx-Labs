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
    gtag('js', new Date());
    gtag('config', GA_ID);
} else {
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
// dev: http://localhost:8080/api/v1/hardware
const API_BASE = 'https://ahlyx-labs.onrender.com/api/v1/hardware';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Create a label/value row and append it to a parent element.
function appendRow(parent, key, value, highlightValue) {
    const row = document.createElement('div');
    row.className = 'data-row';

    const keyEl = document.createElement('span');
    keyEl.className = 'data-key';
    keyEl.textContent = key;

    const valEl = document.createElement('span');
    valEl.className = highlightValue ? 'data-val highlight' : 'data-val';
    valEl.textContent = value ?? '—';

    row.appendChild(keyEl);
    row.appendChild(valEl);
    parent.appendChild(row);
}

// Show a fetch error inside a card container.
function showError(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = '';
    const msg = document.createElement('div');
    msg.className = 'card-error';
    msg.textContent = 'Error fetching data';
    el.appendChild(msg);
}

// Append a dim rate-limit note without wiping the panel.
function showRateLimit(containerId) {
    const el = document.getElementById(containerId);
    if (!el || el.querySelector('.rate-limit-note')) return;
    const note = document.createElement('div');
    note.className = 'rate-limit-note';
    note.textContent = '// rate limited, retrying...';
    el.appendChild(note);
}

// Remove rate-limit note once a successful response arrives.
function clearRateLimit(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const note = el.querySelector('.rate-limit-note');
    if (note) note.remove();
}

// ---------------------------------------------------------------------------
// Fetch functions
// ---------------------------------------------------------------------------

async function fetchSystem() {
    try {
        const res = await fetch(`${API_BASE}/system`);
        if (res.status === 429) { showRateLimit('system-data'); return; }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();

        clearRateLimit('system-data');
        const container = document.getElementById('system-data');
        container.innerHTML = '';

        appendRow(container, 'os',           d.os);
        appendRow(container, 'os_version',   d.os_version);
        appendRow(container, 'architecture', d.architecture);
        appendRow(container, 'hostname',     d.hostname);
        appendRow(container, 'processor',    d.processor);
    } catch {
        showError('system-data');
    }
}

async function fetchCPU() {
    try {
        const res = await fetch(`${API_BASE}/cpu`);
        if (res.status === 429) { showRateLimit('cpu-data'); return; }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();

        clearRateLimit('cpu-data');
        const container = document.getElementById('cpu-data');
        container.innerHTML = '';

        appendRow(container, 'physical_cores', d.physical_cores);
        appendRow(container, 'total_cores',    d.total_cores);
        appendRow(container, 'current_speed',  d.current_speed);
        appendRow(container, 'cpu_usage',      d.cpu_usage, true);
    } catch {
        showError('cpu-data');
    }
}

async function fetchRAM() {
    try {
        const res = await fetch(`${API_BASE}/ram`);
        if (res.status === 429) { showRateLimit('ram-data'); return; }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();

        clearRateLimit('ram-data');
        const container = document.getElementById('ram-data');
        container.innerHTML = '';

        appendRow(container, 'total',      d.total);
        appendRow(container, 'used',       d.used);
        appendRow(container, 'available',  d.available);
        appendRow(container, 'usage',      d.usage,      true);
        appendRow(container, 'swap_total', d.swap_total);
        appendRow(container, 'swap_used',  d.swap_used);
        appendRow(container, 'swap_usage', d.swap_usage, true);
    } catch {
        showError('ram-data');
    }
}

async function fetchDisk() {
    try {
        const res = await fetch(`${API_BASE}/disk`);
        if (res.status === 429) { showRateLimit('disk-data'); return; }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();

        clearRateLimit('disk-data');
        const container = document.getElementById('disk-data');
        container.innerHTML = '';

        // Partition blocks
        const partitions = d.partitions ?? [];
        partitions.forEach(function (p) {
            const block = document.createElement('div');
            block.className = 'partition-block';

            const mount = document.createElement('div');
            mount.className = 'partition-mount highlight';
            mount.textContent = p.mountpoint;
            block.appendChild(mount);

            const rows = document.createElement('div');
            rows.className = 'data-rows';
            appendRow(rows, 'filesystem', p.filesystem);
            appendRow(rows, 'total',      p.total);
            appendRow(rows, 'used',       p.used);
            appendRow(rows, 'free',       p.free);
            appendRow(rows, 'usage',      p.usage, true);
            block.appendChild(rows);

            container.appendChild(block);
        });

        // I/O totals
        const totals = document.createElement('div');
        totals.className = 'totals-row';

        appendRow(totals, 'total_read',    d.total_read);
        appendRow(totals, 'total_written', d.total_written);
        appendRow(totals, 'read_ops',      d.read_ops);
        appendRow(totals, 'write_ops',     d.write_ops);

        container.appendChild(totals);
    } catch {
        showError('disk-data');
    }
}

async function fetchNetwork() {
    try {
        const res = await fetch(`${API_BASE}/network`);
        if (res.status === 429) { showRateLimit('network-data'); return; }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();

        clearRateLimit('network-data');
        const container = document.getElementById('network-data');
        container.innerHTML = '';

        // Interface blocks
        const interfaces = d.interfaces ?? [];
        interfaces.forEach(function (iface) {
            const block = document.createElement('div');
            block.className = 'interface-block';

            const name = document.createElement('div');
            name.className = 'interface-name highlight';
            name.textContent = iface.interface;
            block.appendChild(name);

            const rows = document.createElement('div');
            rows.className = 'data-rows';
            appendRow(rows, 'ip_address',  iface.ip_address);
            appendRow(rows, 'subnet_mask', iface.subnet_mask);
            block.appendChild(rows);

            container.appendChild(block);
        });

        // Traffic totals
        const totals = document.createElement('div');
        totals.className = 'totals-row';

        appendRow(totals, 'bytes_sent',       d.bytes_sent);
        appendRow(totals, 'bytes_received',   d.bytes_received);
        appendRow(totals, 'packets_sent',     d.packets_sent);
        appendRow(totals, 'packets_received', d.packets_received);

        container.appendChild(totals);
    } catch {
        showError('network-data');
    }
}

// ---------------------------------------------------------------------------
// Fetch all and update timestamp — staggered 200 ms apart
// ---------------------------------------------------------------------------
const delay = ms => new Promise(r => setTimeout(r, ms));

async function fetchAll() {
    await fetchSystem();
    await delay(200);
    await fetchCPU();
    await delay(200);
    await fetchRAM();
    await delay(200);
    await fetchDisk();
    await delay(200);
    await fetchNetwork();

    const ts = document.getElementById('last-updated-time');
    if (ts) ts.textContent = new Date().toLocaleTimeString();
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
fetchAll();
setInterval(fetchAll, 10000);
