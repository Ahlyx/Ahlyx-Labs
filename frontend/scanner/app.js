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
// dev: http://localhost:8080
const API_BASE = 'https://api.ahlyxlabs.com';

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------
async function runScan() {
    const subnetInput = document.getElementById('subnetInput');
    const scanBtn     = document.getElementById('scanBtn');
    const statusLine  = document.getElementById('statusLine');
    const resultsTable = document.getElementById('resultsTable');
    const resultsBody  = document.getElementById('resultsBody');

    const subnet = subnetInput.value.trim();
    if (!subnet) return;

    const inputType = subnet.includes('/') ? 'cidr' : 'ip';
    if (typeof gtag !== 'undefined') {
        gtag('event', 'scan_submitted', { input_type: inputType });
    }

    // Reset state
    scanBtn.disabled = true;
    scanBtn.textContent = 'SCANNING...';
    statusLine.textContent = '';
    statusLine.className = 'status-line';
    resultsTable.style.display = 'none';
    resultsBody.innerHTML = '';

    try {
        const res = await fetch(
            `${API_BASE}/api/v1/scanner/scan?subnet=${encodeURIComponent(subnet)}`
        );
        const data = await res.json();

        if (!res.ok) {
            const detail = data.detail ?? data.error ?? `HTTP ${res.status}`;
            throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
        }

        const hosts = data.hosts ?? [];
        const count = data.hosts_found ?? hosts.length;

        statusLine.textContent = `Found ${count} host${count !== 1 ? 's' : ''} on ${data.subnet ?? subnet}`;
        statusLine.className = 'status-line success';

        const openPortCount = hosts.reduce((sum, h) => sum + (h.ports ? h.ports.length : 0), 0);
        if (typeof gtag !== 'undefined') {
            gtag('event', 'scan_result', {
                input_type: inputType,
                host_count: count,
                open_port_count: openPortCount
            });
        }

        if (hosts.length > 0) {
            hosts.forEach(host => {
                const row = document.createElement('tr');

                // IP column
                const tdIP = document.createElement('td');
                tdIP.className = 'col-ip';
                tdIP.textContent = host.ip;

                // Ports column
                const tdPorts = document.createElement('td');
                const portsDiv = document.createElement('div');
                portsDiv.className = 'col-ports';

                const ports = host.ports ?? [];
                if (ports.length === 0) {
                    const span = document.createElement('span');
                    span.className = 'port-entry none';
                    span.textContent = 'none';
                    portsDiv.appendChild(span);
                } else {
                    ports.forEach(p => {
                        const span = document.createElement('span');
                        span.className = p.ot_flag ? 'port-entry ot' : 'port-entry normal';

                        let label = `${p.port}`;
                        if (p.service) label += ` ${p.service}`;
                        if (p.ot_flag) label += ' \u26a0 OT';

                        span.textContent = label;
                        portsDiv.appendChild(span);
                    });
                }

                tdPorts.appendChild(portsDiv);
                row.appendChild(tdIP);
                row.appendChild(tdPorts);
                resultsBody.appendChild(row);
            });

            resultsTable.style.display = 'table';

            const feedbackRow = document.createElement('div');
            feedbackRow.className = 'feedback-row';
            feedbackRow.innerHTML = `
                <span class="feedback-label">// was this useful?</span>
                <button class="feedback-btn" data-value="up">[ ↑ ]</button>
                <button class="feedback-btn" data-value="down">[ ↓ ]</button>
            `;
            feedbackRow.querySelectorAll('.feedback-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    if (typeof gtag !== 'undefined') {
                        gtag('event', 'scan_feedback', { value: btn.dataset.value });
                    }
                    feedbackRow.innerHTML = '<span class="feedback-thanks">// thanks</span>';
                });
            });
            document.querySelector('.results-wrapper').appendChild(feedbackRow);
        }

    } catch (err) {
        if (typeof gtag !== 'undefined') {
            gtag('event', 'scan_error', { input_type: subnet.includes('/') ? 'cidr' : 'ip' });
        }
        statusLine.textContent = err.message;
        statusLine.className = 'status-line error';
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = '[ SCAN ]';
    }
}

// ---------------------------------------------------------------------------
// Event bindings
// ---------------------------------------------------------------------------
document.getElementById('scanBtn').addEventListener('click', runScan);

document.getElementById('subnetInput').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') runScan();
});

document.querySelectorAll('.preset-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
        document.getElementById('subnetInput').value = btn.dataset.value;
    });
});
