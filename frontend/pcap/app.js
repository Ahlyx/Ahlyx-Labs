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
// WebSocket
// ---------------------------------------------------------------------------
const urlParams = new URLSearchParams(window.location.search);
const SESSION_ID = urlParams.get('session');

const WS_URL = SESSION_ID
    ? `wss://api.ahlyxlabs.com/ws/relay/${SESSION_ID}?role=browser`
    : 'ws://localhost:7777/ws';
const MAX_FLOWS      = 200;
const MAX_ALERTS     = 50;
const MAX_DNS        = 100;
const MAX_ENRICHMENT = 50;
const MAX_MACS       = 50;
const FLOW_FOLLOW_THRESHOLD = 16;
const MAX_PENDING_FLOWS = MAX_FLOWS;

const OT_PORTS = new Set([502, 102, 44818, 4840, 20000, 47808, 9600, 1962,
                           18245, 4000, 2222, 1089, 1090, 1091]);

const OT_PROTOCOLS = new Set(['Modbus', 'S7comm', 'EtherNet/IP', 'OPC-UA',
    'DNP3', 'BACnet', 'OMRON FINS', 'PCWorx', 'GE SRTP', 'Emerson DeltaV',
    'FF Annunciation', 'Foundation Fieldbus', 'FF System Management']);

let ws             = null;
let reconnectTimer = null;
let reconnectAttempts = 0;
let threatIPs      = new Set();
let statsData      = { packets: 0, bytes: 0, flows: 0, alerts: 0 };
const renderedAlerts = new Map();
let pendingFlowCount = 0;
let followingFlows = true;
let pendingFlows = [];
let flowTouchStartY = null;
let lastFlowScrollTop = 0;

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------
function connect() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        return;
    }

    if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    setStatus('connecting');

    console.info('pcap websocket: connecting', { url: WS_URL, attempt: reconnectAttempts });
    const socket = new WebSocket(WS_URL);
    ws = socket;

    socket.addEventListener('open', function () {
        if (ws !== socket) return;
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
        reconnectAttempts = 0;
        console.info('pcap websocket: open', { url: WS_URL });
        setStatus('connected');
    });

    socket.addEventListener('message', function (event) {
        if (ws !== socket) return;
        try {
            const msg = JSON.parse(event.data);
            handleMessage(msg);
        } catch (e) {
            // Ignore malformed frames.
        }
    });

    socket.addEventListener('close', function (event) {
        if (ws !== socket) return;
        console.warn('pcap websocket: closed', {
            code: event.code,
            reason: event.reason || '',
            wasClean: Boolean(event.wasClean),
        });
        ws = null;
        setStatus('disconnected');
        scheduleReconnect();
    });

    socket.addEventListener('error', function (event) {
        if (ws !== socket) return;
        console.warn('pcap websocket: error', { url: WS_URL, event: event });
        // Browsers follow an error with close. Keep reconnection centralized in
        // the close handler so a single timer/socket remains authoritative.
    });
}

function scheduleReconnect() {
    if (reconnectTimer !== null) return;
    reconnectAttempts++;
    const delay = 3000;
    console.info('pcap websocket: reconnect scheduled', { attempt: reconnectAttempts, delay: delay });
    reconnectTimer = setTimeout(function () {
        reconnectTimer = null;
        connect();
    }, delay);
}

function handleMessage(msg) {
    switch (msg.type) {
        case 'flow':        addFlow(msg);        break;
        case 'alert':       addAlert(msg);       break;
        case 'dns':         addDNS(msg);         break;
        case 'stats':       updateStats(msg);    break;
        case 'enrichment':  addEnrichment(msg);  break;
        case 'mac':         addMAC(msg);          break;
        case 'status':      /* no-op for now */  break;
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------
function setStatus(state) {
    const dot    = document.getElementById('statusDot');
    const text   = document.getElementById('statusText');
    const banner = document.getElementById('downloadBanner');

    if (state === 'connected') {
        dot.className   = 'status-dot online';
        text.className  = 'status-text status-connected';
        text.textContent = SESSION_ID
            ? `CONNECTED — relay mode | session: ${SESSION_ID}`
            : 'CONNECTED — local mode';
        banner.classList.add('hidden');
    } else if (state === 'connecting') {
        dot.className   = 'status-dot';
        text.className  = 'status-text status-connecting';
        text.textContent = 'CONNECTING...';
        banner.classList.remove('hidden');
    } else {
        dot.className   = 'status-dot offline';
        text.className  = 'status-text status-disconnected';
        text.textContent = 'DISCONNECTED';
        banner.classList.remove('hidden');
    }
}

// ---------------------------------------------------------------------------
// Flow table
// ---------------------------------------------------------------------------
function addFlow(msg) {
    const scrollContainer = document.getElementById('flow-scroll');
    const atTop = !scrollContainer || scrollContainer.scrollTop <= FLOW_FOLLOW_THRESHOLD;

    if (!followingFlows || !atTop) {
        if (followingFlows) {
            followingFlows = false;
        }
        pendingFlows.push(msg);
        if (pendingFlows.length > MAX_PENDING_FLOWS) pendingFlows.shift();
        pendingFlowCount = pendingFlows.length;
        updateFlowLiveControl();
        return;
    }

    if (!followingFlows) mergePendingFlows();
    renderFlow(msg);
    followingFlows = true;
    pendingFlowCount = 0;
    if (scrollContainer) scrollContainer.scrollTop = 0;
    lastFlowScrollTop = 0;
    updateFlowLiveControl();
}

function renderFlow(msg) {
    const tbody = document.getElementById('flow-body');

    const tr = document.createElement('tr');
    tr.classList.add('row-new');
    setTimeout(function () { tr.classList.remove('row-new'); }, 500);

    const src = msg.src || msg.src_ip || '';
    const dst = msg.dst || msg.dst_ip || '';
    const isOT     = isOTPort(msg.dst_port);
    const isThreat = threatIPs.has(src) || threatIPs.has(dst);

    const tdTime  = document.createElement('td');
    const tdSrc   = document.createElement('td');
    const tdDst   = document.createElement('td');
    const tdService = document.createElement('td');
    const tdBytes = document.createElement('td');

    tdTime.className  = 'col-dim';
    tdSrc.className   = 'flow-ip' + (isThreat ? ' col-threat' : '');
    tdDst.className   = 'flow-ip' + (isThreat ? ' col-threat' : '');
    tdService.className = isOT ? 'col-ot' : 'col-dim';
    tdBytes.className = 'col-dim';

    tdTime.textContent  = formatTime(msg.timestamp);
    tdSrc.textContent   = formatFlowIP(src);
    tdSrc.title         = src;
    tdDst.textContent   = formatFlowIP(dst);
    tdDst.title         = dst;
    tdService.textContent = String(msg.dst_port || '?') + '/' + String(msg.protocol || '?') + (isOT ? ' ⚠ OT' : '');
    tdBytes.textContent = formatBytes(msg.bytes);

    tr.appendChild(tdTime);
    tr.appendChild(tdSrc);
    tr.appendChild(tdDst);
    tr.appendChild(tdService);
    tr.appendChild(tdBytes);

    tbody.insertBefore(tr, tbody.firstChild);

    while (tbody.children.length > MAX_FLOWS) {
        tbody.removeChild(tbody.lastChild);
    }
}

function mergePendingFlows() {
    if (!pendingFlows.length) return;

    const buffered = pendingFlows;
    pendingFlows = [];
    pendingFlowCount = 0;
    buffered.forEach(renderFlow);
}

function handleFlowScroll() {
    const scrollContainer = document.getElementById('flow-scroll');
    if (!scrollContainer) return;
    const scrollTop = scrollContainer.scrollTop;
    let pausedThisEvent = false;

    if (followingFlows && scrollTop > lastFlowScrollTop) {
        followingFlows = false;
        pausedThisEvent = true;
    }

    if (!followingFlows && !pausedThisEvent && scrollTop <= FLOW_FOLLOW_THRESHOLD && scrollTop < lastFlowScrollTop) {
        mergePendingFlows();
        followingFlows = true;
        scrollContainer.scrollTop = 0;
    }
    lastFlowScrollTop = scrollContainer.scrollTop;
    updateFlowLiveControl();
}

function pauseFlowLive() {
    if (!followingFlows) return;
    followingFlows = false;
    updateFlowLiveControl();
}

function handleFlowWheel(event) {
    if (event.deltaY > 0) pauseFlowLive();
}

function handleFlowTouchStart(event) {
    const touch = event.touches && event.touches[0];
    flowTouchStartY = touch ? touch.clientY : null;
}

function handleFlowTouchMove(event) {
    const touch = event.touches && event.touches[0];
    if (touch && flowTouchStartY != null && touch.clientY < flowTouchStartY) pauseFlowLive();
}

function handleFlowTouchEnd() {
    flowTouchStartY = null;
}

function jumpToLive() {
    const scrollContainer = document.getElementById('flow-scroll');
    mergePendingFlows();
    followingFlows = true;
    pendingFlowCount = 0;
    if (scrollContainer) scrollContainer.scrollTop = 0;
    lastFlowScrollTop = 0;
    updateFlowLiveControl();
}

function updateFlowLiveControl() {
    const control = document.getElementById('flow-live-control');
    if (!control) return;

    control.hidden = followingFlows;
    if (followingFlows) return;
    control.textContent = pendingFlowCount
        ? pendingFlowCount + ' new packet' + (pendingFlowCount === 1 ? '' : 's') + ' · Jump to live'
        : 'LIVE PAUSED · Jump to live';
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
// Alert identity/severity handling. Agent-side suppression is authoritative;
// this map is a browser safety layer for reconnects and repeated updates.
function addAlert(msg) {
    const list = document.getElementById('alerts-list');
    const empty = list.querySelector('.panel-empty');
    if (empty) list.removeChild(empty);

    const id = alertID(msg);
    let rendered = renderedAlerts.get(id);
    if (!rendered) {
        const entry = document.createElement('div');
        const textSpan = document.createElement('span');
        const timeSpan = document.createElement('span');
        timeSpan.className = 'alert-time';
        entry.appendChild(textSpan);
        entry.appendChild(timeSpan);
        rendered = { entry: entry, text: textSpan, time: timeSpan };
        renderedAlerts.set(id, rendered);
        list.insertBefore(entry, list.firstChild);
        statsData.alerts++;
        updateStatsDisplay();
    }

    const severity = normalizeSeverity(msg.severity);
    rendered.entry.className = 'alert-entry severity-' + severity;
    rendered.text.textContent = alertText(msg, severity);
    rendered.time.textContent = formatTime(msg.timestamp);

    while (list.children.length > MAX_ALERTS) {
        const removed = list.lastChild;
        for (const [alertID, item] of renderedAlerts.entries()) {
            if (item.entry === removed) renderedAlerts.delete(alertID);
        }
        list.removeChild(removed);
    }
}

function alertID(msg) {
    if (typeof msg.id === 'string' && msg.id) return msg.id;
    return ['legacy', msg.alert_type || '', msg.subtype || '', msg.src || '', msg.dst || '', msg.dst_port || ''].join('|');
}

function normalizeSeverity(severity) {
    const value = typeof severity === 'string' ? severity.toLowerCase() : 'info';
    return ['info', 'notice', 'warning', 'critical'].includes(value) ? value : 'info';
}

function alertText(msg, severity) {
    const prefix = severity.toUpperCase();
    const src = msg.src || '';
    const dst = msg.dst || '';
    const source = formatEndpoint(src, msg.src_port);
    const destination = formatEndpoint(dst, msg.dst_port);
    if (msg.alert_type === 'periodic_connection') {
        const interval = msg.interval_ms != null ? Number(msg.interval_ms).toFixed(0) : '?';
        const jitter = msg.jitter_pct != null ? ' jitter ' + (Number(msg.jitter_pct) * 100).toFixed(1) + '%' : '';
        return prefix + ' periodic connection — ' + source + ' → ' + destination + ' — ' + interval + 'ms' + jitter + ' × ' + (msg.count || '?');
    }
    if (msg.alert_type === 'possible_port_scan') {
        const ports = Array.isArray(msg.ports_hit) ? msg.ports_hit.length : '?';
        const evidence = Array.isArray(msg.ports_hit) && msg.ports_hit.length ? ' (' + msg.ports_hit.join(', ') + ')' : '';
        return prefix + ' possible port scan — ' + source + ' → ' + destination + ' — ' + ports + ' unique ports in ' + (msg.window_seconds || '?') + 's' + evidence;
    }
    if (msg.subtype === 'tcp_retransmission') return prefix + ' TCP retransmission — ' + source + ' → ' + destination;
    if (msg.subtype === 'tcp_reset') return prefix + ' TCP reset — ' + source + ' → ' + destination;
    if (msg.subtype === 'possible_syn_flood') return prefix + ' possible SYN flood — ' + source + ' → ' + destination + ' — ' + (msg.count || '?') + ' half-open sessions';
    if (msg.alert_type === 'mac_multi_ip') return prefix + ' MAC associated with multiple IP addresses — ' + src;
    return prefix + ' ' + String(msg.subtype || msg.alert_type || 'alert').replaceAll('_', ' ') + ' — ' + source + (dst ? ' → ' + destination : '');
}

function formatEndpoint(ip, port) {
    if (!ip) return '';
    return port ? ip + ':' + port : ip;
}

function formatFlowIP(ip) {
    if (!ip) return '';
    const value = String(ip);
    if (!value.includes(':') || value.length <= 24) return value;
    const groups = value.split(':');
    const compressedAt = groups.indexOf('');
    const prefix = compressedAt >= 0
        ? groups.slice(0, compressedAt).join(':') + '::' + (groups[compressedAt + 1] || '')
        : groups.slice(0, 3).join(':');
    return prefix + ':…:' + groups.slice(-2).join(':');
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------
function addDNS(msg) {
    const tbody = document.getElementById('dns-body');

    const tr = document.createElement('tr');

    const tdTime  = document.createElement('td');
    const tdSrc   = document.createElement('td');
    const tdQuery = document.createElement('td');
    const tdType  = document.createElement('td');
    const tdResp  = document.createElement('td');

    tdTime.className = 'col-dim';
    tdType.className = 'col-dim';
    tdResp.className = 'col-dim';

    tdTime.textContent  = formatTime(msg.timestamp);
    tdSrc.textContent   = msg.src || '';
    tdQuery.textContent = msg.query || '';
    tdType.textContent  = msg.record_type || '';
    tdResp.textContent  = msg.response || '—';

    if (msg.is_suspicious) {
        tr.classList.add('col-threat');
        const reason = msg.suspicion_reason ? ' ⚠ ' + msg.suspicion_reason : ' ⚠';
        tdQuery.textContent += reason;
    }

    tr.appendChild(tdTime);
    tr.appendChild(tdSrc);
    tr.appendChild(tdQuery);
    tr.appendChild(tdType);
    tr.appendChild(tdResp);

    tbody.insertBefore(tr, tbody.firstChild);

    while (tbody.children.length > MAX_DNS) {
        tbody.removeChild(tbody.lastChild);
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------
function updateStats(msg) {
    statsData.packets = msg.total_packets;
    statsData.bytes   = msg.total_bytes;
    statsData.flows   = msg.active_flows;
    updateStatsDisplay();
    if (msg.protocol_breakdown) updateProtoBars(msg.protocol_breakdown);
    if (msg.top_talkers)        updateTopTalkers(msg.top_talkers);
}

function updateStatsDisplay() {
    document.getElementById('stat-packets').textContent = statsData.packets.toLocaleString();
    document.getElementById('stat-bytes').textContent   = formatBytes(statsData.bytes);
    document.getElementById('stat-flows').textContent   = statsData.flows.toLocaleString();
    document.getElementById('stat-alerts').textContent  = statsData.alerts.toLocaleString();
}

function updateProtoBars(breakdown) {
    const container = document.getElementById('proto-bars');

    // Sort descending by count.
    const entries = Object.entries(breakdown).sort(function (a, b) { return b[1] - a[1]; });
    const total   = entries.reduce(function (sum, e) { return sum + e[1]; }, 0);

    if (total === 0) return;

    const top  = entries.slice(0, 8);
    const rest = entries.slice(8).reduce(function (sum, e) { return sum + e[1]; }, 0);
    if (rest > 0) top.push(['Other', rest]);

    container.textContent = '';

    top.forEach(function (entry) {
        const name  = entry[0];
        const count = entry[1];
        const pct   = ((count / total) * 100).toFixed(1);
        const isOT  = OT_PROTOCOLS.has(name);

        const row   = document.createElement('div');
        row.className = 'proto-row';

        const nameEl = document.createElement('span');
        nameEl.className  = 'proto-name';
        nameEl.textContent = name;

        const wrap = document.createElement('div');
        wrap.className = 'proto-bar-wrap';

        const bar  = document.createElement('div');
        bar.className = 'proto-bar' + (isOT ? ' ot' : '');
        bar.style.width = pct + '%';

        wrap.appendChild(bar);

        const pctEl = document.createElement('span');
        pctEl.className  = 'proto-pct';
        pctEl.textContent = pct + '%';

        row.appendChild(nameEl);
        row.appendChild(wrap);
        row.appendChild(pctEl);
        container.appendChild(row);
    });
}

function updateTopTalkers(talkers) {
    const list = document.getElementById('talkers-list');
    list.textContent = '';

    if (!talkers || talkers.length === 0) {
        const empty = document.createElement('div');
        empty.className  = 'panel-empty';
        empty.textContent = '// waiting for traffic';
        list.appendChild(empty);
        return;
    }

    talkers.forEach(function (t) {
        const row    = document.createElement('div');
        row.className = 'talker-row';

        const ipEl   = document.createElement('span');
        ipEl.className  = 'talker-ip' + (threatIPs.has(t.ip) ? ' threat' : '');
        ipEl.textContent = t.ip;

        const bytesEl = document.createElement('span');
        bytesEl.className  = 'talker-bytes';
        bytesEl.textContent = '↑ ' + formatBytes(t.bytes);

        row.appendChild(ipEl);
        row.appendChild(bytesEl);
        list.appendChild(row);
    });
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------
function addEnrichment(msg) {
    const list = document.getElementById('enrichment-list');

    // Remove empty placeholder.
    const empty = list.querySelector('.panel-empty');
    if (empty) list.removeChild(empty);

    const isThreat = msg.verdict === 'threat' || msg.verdict === 'malicious';

    if (isThreat) {
        threatIPs.add(msg.ip);
        // Retroactively colour any existing flow rows for this IP.
        document.querySelectorAll('#flow-body tr').forEach(function (tr) {
            const cells = tr.querySelectorAll('td');
            if (cells.length < 3) return;
            if (cells[1].textContent === msg.ip || cells[2].textContent === msg.ip) {
                cells[1].classList.add('col-threat');
                cells[2].classList.add('col-threat');
            }
        });
    }

    const entry = document.createElement('div');
    entry.className = 'enrich-entry ' + (isThreat ? 'threat' : 'clean');

    const ipEl = document.createElement('span');
    ipEl.className  = 'enrich-ip';
    ipEl.textContent = msg.ip;

    const badgeEl = document.createElement('span');
    badgeEl.className  = 'enrich-badge';
    badgeEl.textContent = (msg.verdict || 'unknown').toUpperCase();

    const metaEl = document.createElement('span');
    metaEl.className = 'enrich-badge';
    const scorePart = msg.abuse_score != null ? 'abuse: ' + msg.abuse_score + '/100' : '';
    const torPart   = 'TOR: ' + (msg.is_tor ? 'true' : 'false');
    metaEl.textContent = [scorePart, torPart].filter(Boolean).join(' | ');

    entry.appendChild(ipEl);
    entry.appendChild(badgeEl);
    entry.appendChild(metaEl);

    list.insertBefore(entry, list.firstChild);

    while (list.children.length > MAX_ENRICHMENT) {
        list.removeChild(list.lastChild);
    }
}

// ---------------------------------------------------------------------------
// MAC observations
// ---------------------------------------------------------------------------
function addMAC(msg) {
    const list = document.getElementById('mac-list');
    if (!list) return;
    const empty = list.querySelector('.panel-empty');
    if (empty) list.removeChild(empty);

    const entry = document.createElement('div');
    entry.className = 'mac-entry';
    const mac = document.createElement('span');
    mac.textContent = msg.mac || 'unknown MAC';
    const details = document.createElement('span');
    const parts = [msg.ip, msg.vendor].filter(Boolean);
    if (msg.locally_administered) parts.push('locally administered MAC');
    details.className = 'mac-details';
    details.textContent = parts.join(' | ') || 'MAC observation';
    entry.appendChild(mac);
    entry.appendChild(details);
    list.insertBefore(entry, list.firstChild);
    while (list.children.length > MAX_MACS) list.removeChild(list.lastChild);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatBytes(bytes) {
    if (bytes == null || bytes === 0) return '0 B';
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
}

function formatTime(timestamp) {
    if (!timestamp) {
        return new Date().toTimeString().slice(0, 8);
    }
    const date = new Date(timestamp);
    return Number.isNaN(date.getTime()) ? new Date().toTimeString().slice(0, 8) : date.toTimeString().slice(0, 8);
}

function isOTPort(port) {
    return OT_PORTS.has(parseInt(port, 10));
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
connect();

// ---------------------------------------------------------------------------
// Setup section toggle
// ---------------------------------------------------------------------------
function toggleSetup(forceCollapse) {
    var body = document.getElementById('setupBody');
    var btn  = document.getElementById('setupToggleBtn');
    if (!body || !btn) return;
    var isOpen = !body.classList.contains('collapsed');
    if (forceCollapse === true) {
        if (!isOpen) return;
        body.classList.add('collapsed');
        btn.textContent = '[ + SETUP ]';
    } else if (isOpen) {
        body.classList.add('collapsed');
        btn.textContent = '[ + SETUP ]';
    } else {
        body.classList.remove('collapsed');
        btn.textContent = '[ \u2212 SETUP ]';
    }
}

document.addEventListener('DOMContentLoaded', function () {
    var toggle = document.getElementById('setupToggle');
    if (toggle) { toggle.addEventListener('click', toggleSetup); }
    var flowScroll = document.getElementById('flow-scroll');
    var flowControl = document.getElementById('flow-live-control');
    if (flowScroll) {
        flowScroll.addEventListener('scroll', handleFlowScroll);
        flowScroll.addEventListener('wheel', handleFlowWheel, { passive: true });
        flowScroll.addEventListener('touchstart', handleFlowTouchStart, { passive: true });
        flowScroll.addEventListener('touchmove', handleFlowTouchMove, { passive: true });
        flowScroll.addEventListener('touchend', handleFlowTouchEnd, { passive: true });
    }
    if (flowControl) { flowControl.addEventListener('click', jumpToLive); }
    updateFlowLiveControl();
});

// Patch setStatus to auto-collapse the setup panel when the agent connects.
var _origSetStatus = setStatus;
setStatus = function (state) {
    _origSetStatus(state);
    if (state === 'connected') { toggleSetup(true); }
};
