// Run with: node tests/pcap/app.protocol.test.js
// Exercises the production script with a tiny DOM/WebSocket shim; no browser
// framework or production dependency is required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const pcapDir = __dirname + '/../../frontend/pcap';
const page = fs.readFileSync(pcapDir + '/index.html', 'utf8');
const styles = fs.readFileSync(pcapDir + '/style.css', 'utf8');
assert.ok(styles.includes('.live-flow-table'), 'the production PCAP stylesheet is present');
assert.ok(!page.includes('v0.1.0'), 'the stale release version is absent');
assert.ok(page.includes('>v0.4.3</a>'), 'the deployed release is visibly identified');
assert.ok(page.includes('https://github.com/Ahlyx/pcap-agent/releases/latest'), 'the version label links to the official latest release');
assert.ok(page.includes('Release details / checksums / provenance'), 'release details and verification information are easy to find');
assert.ok(!page.includes('v0.4.0'), 'the previous stable release version is absent');
assert.ok(!page.includes('v0.4.0-rc.1'), 'the release-candidate version is absent');
assert.ok(!page.includes('pcap-agent-linux-amd64'), 'the old Linux architecture-named asset is absent');
assert.ok(!page.includes('pcap-agent-darwin-amd64'), 'the old macOS Intel architecture-named asset is absent');
assert.ok(!page.includes('pcap-agent-darwin-arm64'), 'the old macOS Apple Silicon architecture-named asset is absent');
assert.ok(page.includes('/releases/latest/download/pcap-agent-windows.zip'), 'Windows download targets the latest packaged asset');
assert.ok(page.includes('/releases/latest/download/pcap-agent-linux.tar.gz'), 'Linux download targets the latest packaged asset');
assert.ok(page.includes('/releases/latest/download/pcap-agent-macos-intel.tar.gz'), 'macOS Intel download targets the latest packaged asset');
assert.ok(page.includes('/releases/latest/download/pcap-agent-macos-apple-silicon.tar.gz'), 'macOS Apple Silicon download targets the latest packaged asset');
const bootstrapIndex = page.indexOf('/pcap/bootstrap.js');
const vercelAnalyticsIndex = page.indexOf('/_vercel/insights/script.js');
const consentLoaderIndex = page.indexOf('/assets/analytics.js');
assert.ok(bootstrapIndex >= 0 && bootstrapIndex < vercelAnalyticsIndex && bootstrapIndex < consentLoaderIndex,
    'relay fragment cleanup bootstrap loads before every analytics script');
const bootstrapSource = fs.readFileSync(pcapDir + '/bootstrap.js', 'utf8');
assert.ok(bootstrapSource.includes('window.location.hash.slice(1)'), 'bootstrap reads credentials only from the fragment');
assert.ok(bootstrapSource.includes('window.history.replaceState'), 'bootstrap removes the fragment before analytics execute');
assert.ok(!bootstrapSource.includes('localStorage') && !bootstrapSource.includes('sessionStorage'), 'bootstrap never persists relay credentials');
const appSource = fs.readFileSync(pcapDir + '/app.js', 'utf8');
assert.ok(appSource.includes('delete window.__AHLYX_RELAY_BOOTSTRAP'), 'relay bootstrap credentials are removed after WebSocket construction');
assert.ok(page.includes('macOS (Apple Silicon)'), 'Apple Silicon is named clearly in the platform choices');
const windowsSetup = page.slice(page.indexOf('Windows PowerShell'), page.indexOf('setup-platform-title">Linux'));
assert.ok(windowsSetup.includes('.\\pcap-agent start'));
assert.ok(windowsSetup.includes('.\\pcap-agent list-interfaces'));
assert.ok(windowsSetup.includes('.\\pcap-agent start --interface'));
assert.ok(!windowsSetup.includes('sudo'), 'Windows instructions do not present sudo');
assert.ok(!page.includes('pcap-agent-windows-amd64.exe'), 'the old Windows artifact name is absent');
const linuxSetup = page.slice(page.indexOf('setup-platform-title">Linux'), page.indexOf('setup-platform-title">macOS'));
const macSetup = page.slice(page.indexOf('setup-platform-title">macOS'), page.indexOf('setup-block-title">// modes'));
assert.ok(linuxSetup.includes('./pcap-agent start'), 'Linux primary command uses the extracted binary name');
assert.ok(macSetup.includes('./pcap-agent start'), 'macOS primary command uses the extracted binary name');
assert.equal((page.match(/id="statusDot"/g) || []).length, 1, 'the header has one status-dot element');
assert.ok(!page.includes('status-dot-live'), 'the unused second status-dot styling is removed');
const flowTableMarkup = page.slice(page.indexOf('id="flow-panel"'), page.indexOf('id="alerts-panel"'));
assert.equal((flowTableMarkup.match(/<th>/g) || []).length, 5, 'the live flow table has five desktop columns');
assert.ok(flowTableMarkup.includes('<th>SERVICE</th>'));
assert.ok(!flowTableMarkup.includes('<th>PORT</th>') && !flowTableMarkup.includes('<th>PROTO</th>'), 'the old separate port/protocol columns are absent');

class Element {
    constructor() {
        this.children = [];
        this.className = '';
        this.textContent = '';
        this.parentNode = null;
        this.classList = {
            add: value => { if (!this.className.split(/\s+/).includes(value)) this.className = (this.className + ' ' + value).trim(); },
            remove: value => { this.className = this.className.split(/\s+/).filter(item => item && item !== value).join(' '); },
            contains: value => this.className.split(/\s+/).includes(value),
        };
    }
    appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
    insertBefore(child, before) { child.parentNode = this; const index = this.children.indexOf(before); if (index < 0) this.children.push(child); else this.children.splice(index, 0, child); return child; }
    removeChild(child) { const index = this.children.indexOf(child); if (index >= 0) this.children.splice(index, 1); child.parentNode = null; return child; }
    querySelector(selector) { return this.children.find(child => selector === '.panel-empty' && child.classList.contains('panel-empty')) || null; }
    get firstChild() { return this.children[0] || null; }
    get lastChild() { return this.children[this.children.length - 1] || null; }
}

const elements = new Map();
function element(id) {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
}
const alerts = element('alerts-list');
const placeholder = new Element(); placeholder.className = 'panel-empty'; alerts.appendChild(placeholder);
const macs = element('mac-list');
const macPlaceholder = new Element(); macPlaceholder.className = 'panel-empty'; macs.appendChild(macPlaceholder);
const flowScroll = element('flow-scroll');
flowScroll.scrollTop = 0;
flowScroll.scrollHeight = 100;
const flowBody = element('flow-body');
const originalInsertBefore = flowBody.insertBefore.bind(flowBody);
flowBody.insertBefore = function (child, before) {
    const result = originalInsertBefore(child, before);
    flowScroll.scrollHeight += 20;
    return result;
};

const sockets = [];
const timers = new Map();
let nextTimerID = 1;

function FakeWebSocket(url) {
    this.url = url;
    this.readyState = 0;
    this.listeners = new Map();
    sockets.push(this);
}
FakeWebSocket.OPEN = 1;
FakeWebSocket.CONNECTING = 0;
FakeWebSocket.CLOSING = 2;
FakeWebSocket.CLOSED = 3;
FakeWebSocket.prototype.addEventListener = function (type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
};
FakeWebSocket.prototype.emit = function (type, event) {
    if (type === 'open') this.readyState = FakeWebSocket.OPEN;
    if (type === 'close') this.readyState = FakeWebSocket.CLOSED;
    (this.listeners.get(type) || []).forEach(listener => listener(event || {}));
};
FakeWebSocket.prototype.close = function () {
    this.emit('close', { code: 1000, reason: '', wasClean: true });
};

const context = {
    console, URLSearchParams, Date, Number, String, Array, Object, Map, Set,
    localStorage: { getItem: () => null, setItem: () => {} },
    dataLayer: [],
    window: { location: { search: '' }, dataLayer: [] },
    document: { getElementById: element, createElement: () => new Element(), addEventListener: () => {} },
    WebSocket: FakeWebSocket,
    setTimeout: callback => { const id = nextTimerID++; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id),
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(pcapDir + '/app.js', 'utf8'), context);

assert.equal(sockets.length, 1, 'initial load creates one WebSocket');
const firstSocket = sockets[0];
firstSocket.emit('open');
assert.equal(element('statusDot').className, 'status-dot online');
assert.equal(vm.runInContext('reconnectAttempts', context), 0, 'opening resets reconnect attempts');

firstSocket.emit('close', { code: 1006, reason: '', wasClean: false });
assert.equal(element('statusDot').className, 'status-dot offline', 'actual close sets disconnected status');
assert.equal(element('statusText').textContent, 'LOCAL AGENT NOT RUNNING', 'a missing local agent has a stable explanatory state');
const reconnectID = vm.runInContext('reconnectTimer', context);
assert.ok(reconnectID, 'a close schedules a reconnect');
firstSocket.emit('close', { code: 1006, reason: '', wasClean: false });
assert.equal(vm.runInContext('reconnectTimer', context), reconnectID, 'duplicate close events do not schedule competing reconnects');
assert.equal(sockets.length, 1, 'no second socket exists before the scheduled reconnect');
timers.get(reconnectID)();
assert.equal(sockets.length, 2, 'the scheduled reconnect creates exactly one replacement socket');
assert.equal(element('statusText').textContent, 'LOCAL AGENT NOT RUNNING', 'quiet local retries do not visibly flap back to CONNECTING');
const replacementSocket = sockets[1];
replacementSocket.emit('close', { code: 1006, reason: '', wasClean: false });
assert.equal(element('statusText').textContent, 'LOCAL AGENT NOT RUNNING', 'repeated local failures retain the stable absent-agent state');
const secondReconnectID = vm.runInContext('reconnectTimer', context);
assert.ok(secondReconnectID && secondReconnectID !== reconnectID, 'a later local retry uses one new timer');
timers.get(secondReconnectID)();
assert.equal(sockets.length, 3, 'a repeated local failure still retries quietly in the background');
const recoveredSocket = sockets[2];
recoveredSocket.emit('open');
assert.equal(vm.runInContext('reconnectTimer', context), null, 'successful reconnect clears reconnect state');
assert.equal(vm.runInContext('reconnectAttempts', context), 0, 'successful reconnect resets attempt count');
assert.equal(element('statusDot').className, 'status-dot online', 'an open socket remains connected without packet activity');

const timestamp = '2026-09-14T12:34:56Z';
context.setStatus('connected');
assert.equal(element('statusDot').className, 'status-dot online');
assert.ok(!element('statusText').textContent.includes('●'), 'status text does not render a second dot');
context.setStatus('connecting');
assert.equal(element('statusDot').className, 'status-dot');
assert.equal(element('statusText').textContent, 'CONNECTING...');
context.setStatus('disconnected');
assert.equal(element('statusDot').className, 'status-dot offline');
assert.equal(element('statusText').textContent, 'DISCONNECTED');

const examples = [
    { id: 'rtx', type: 'alert', alert_type: 'tcp_anomaly', subtype: 'tcp_retransmission', severity: 'info', src: 'a', dst: 'b', timestamp },
    { id: 'reset', type: 'alert', alert_type: 'tcp_anomaly', subtype: 'tcp_reset', severity: 'info', src: 'a', dst: 'b', timestamp },
    { id: 'periodic', type: 'alert', alert_type: 'periodic_connection', severity: 'notice', src: 'a', dst: 'b', dst_port: 443, interval_ms: 60000, jitter_pct: 0.02, count: 6, timestamp },
    { id: 'scan', type: 'alert', alert_type: 'possible_port_scan', severity: 'warning', src: 'a', dst: 'b', ports_hit: [22, 80], window_seconds: 10, timestamp },
    { id: 'syn', type: 'alert', alert_type: 'tcp_anomaly', subtype: 'possible_syn_flood', severity: 'warning', src: 'a', dst: 'b', count: 20, timestamp },
];
examples.forEach(context.addAlert);

assert.equal(alerts.children.length, 5, 'each distinct alert ID renders once');
assert.ok(alerts.children.some(entry => entry.className.includes('severity-info')));
assert.ok(alerts.children.some(entry => entry.className.includes('severity-notice')));
assert.ok(alerts.children.some(entry => entry.className.includes('severity-warning')));
assert.ok(alerts.children.some(entry => entry.children[0].textContent.includes('TCP retransmission')));
assert.ok(alerts.children.some(entry => entry.className.includes('severity-info') && entry.children[0].textContent.includes('TCP retransmission')), 'TCP retransmissions remain informational');
assert.ok(alerts.children.some(entry => entry.children[0].textContent.includes('possible SYN flood')));
assert.equal(alerts.children[0].children[1].textContent, context.formatTime(timestamp), 'backend timestamp is rendered');

context.addAlert({ ...examples[0], count: 2, timestamp: '2026-09-14T12:35:56Z' });
assert.equal(alerts.children.length, 5, 'duplicate ID updates instead of appending');
assert.equal(vm.runInContext('statsData.alerts', context), 5, 'counter tracks unique alert IDs');

context.addAlert({ id: 'future', type: 'alert', alert_type: 'future_detector', subtype: 'new_signal', severity: 'critical', timestamp });
assert.ok(alerts.children[0].className.includes('severity-critical'), 'unknown alert remains visible with supplied severity');
assert.ok(alerts.children[0].children[0].textContent.includes('new signal'), 'unknown subtype has a safe label');

context.addMAC({ type: 'mac', mac: '02:00:00:00:00:01', ip: '192.0.2.10', locally_administered: true, timestamp });
assert.ok(macs.children[0].children[1].textContent.includes('locally administered MAC'));

context.addFlow({ type: 'flow', src: '192.0.2.1', dst: '198.51.100.1', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
assert.equal(element('flow-body').children[0].children.length, 5, 'TIME, SRC, DST, SERVICE, and BYTES are rendered');
assert.equal(element('flow-body').children[0].children[1].textContent, '192.0.2.1', 'IPv4 source remains intact');
assert.equal(element('flow-body').children[0].children[1].title, '192.0.2.1', 'full IPv4 source is available as a tooltip');
assert.equal(element('flow-body').children[0].children[3].textContent, '443/TCP', 'service combines destination port and protocol');

const longIPv6 = '2601:8c0:1081:ede0:c1eb:735c:72fc:bb8b';
assert.equal(context.formatFlowIP(longIPv6), '2601:8c0:1081:…:72fc:bb8b', 'long global IPv6 preserves a prefix and final two hextets');
const globalIPv6Flow = { type: 'flow', src: longIPv6, dst: '198.51.100.2', dst_port: 19341, protocol: 'UDP', bytes: 42, timestamp };
context.addFlow(globalIPv6Flow);
assert.equal(globalIPv6Flow.src, longIPv6, 'IPv6 presentation does not mutate the flow record');
assert.equal(element('flow-body').children[0].children[1].textContent, '2601:8c0:1081:…:72fc:bb8b', 'long global IPv6 is presentation-truncated in the table');
assert.equal(element('flow-body').children[0].children[1].title, longIPv6, 'full IPv6 is preserved in the tooltip');
assert.equal(element('flow-body').children[0].children[2].textContent, '198.51.100.2', 'IPv4 destination remains intact');
assert.equal(element('flow-body').children[0].children[3].textContent, '19341/UDP', 'UDP service combines destination port and protocol');

const linkLocalIPv6 = 'fe80::4e50:ddff:fe63:42e4';
assert.equal(context.formatFlowIP(linkLocalIPv6), 'fe80::4e50:…:fe63:42e4', 'link-local IPv6 preserves useful prefix and suffix context');
context.addFlow({ type: 'flow', src: linkLocalIPv6, dst: '198.51.100.3', dst_port: 53, protocol: 'UDP', bytes: 42, timestamp });
assert.equal(element('flow-body').children[0].children[1].textContent, 'fe80::4e50:…:fe63:42e4', 'link-local IPv6 uses a single middle ellipsis');
assert.equal(element('flow-body').children[0].children[1].title, linkLocalIPv6, 'full link-local IPv6 is preserved in the tooltip');

const wheelRows = flowBody.children.length;
context.handleFlowWheel({ deltaY: 1 });
assert.equal(vm.runInContext('followingFlows', context), false, 'one downward wheel gesture immediately pauses live follow');
flowScroll.scrollTop = 1;
context.handleFlowScroll();
assert.equal(vm.runInContext('followingFlows', context), false, 'the intentional pause survives the immediate downward near-top scroll event');
context.addFlow({ type: 'flow', src: 'wheel-buffered', dst: '198.51.100.4', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
assert.equal(flowBody.children.length, wheelRows, 'a packet after one wheel gesture is buffered instead of rendered');
assert.equal(vm.runInContext('pendingFlows.length', context), 1, 'the wheel-paused packet enters the pending buffer');
context.handleFlowWheel({ deltaY: -1 });
assert.equal(vm.runInContext('followingFlows', context), false, 'upward wheel movement while paused does not resume live follow');
flowScroll.scrollTop = 80;
context.handleFlowScroll();
flowScroll.scrollTop = 0;
context.handleFlowScroll();
assert.equal(vm.runInContext('followingFlows', context), true, 'manually returning to the top resumes wheel-paused live follow');
assert.equal(vm.runInContext('pendingFlows.length', context), 0, 'returning to the top merges the wheel-paused packet');
assert.equal(flowBody.children[0].children[1].textContent, 'wheel-buffered', 'the wheel-paused packet is rendered after resuming');

flowScroll.scrollTop = 80;
context.handleFlowScroll();
const pausedViewport = flowScroll.scrollTop;
const pausedHeight = flowScroll.scrollHeight;
const pausedRows = flowBody.children.length;
context.addFlow({ type: 'flow', src: 'paused-older', dst: '198.51.100.2', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
context.addFlow({ type: 'flow', src: 'paused-newer', dst: '198.51.100.3', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
assert.equal(flowBody.children.length, pausedRows, 'paused mode does not mutate visible flow rows');
assert.equal(flowScroll.scrollHeight, pausedHeight, 'paused mode does not change the table height');
assert.equal(flowScroll.scrollTop, pausedViewport, 'paused mode does not compensate scroll position');
assert.equal(vm.runInContext('pendingFlows.length', context), 2, 'paused packets are buffered in memory');
assert.equal(vm.runInContext('pendingFlowCount', context), 2, 'paused follow mode counts buffered packets');
assert.equal(element('flow-live-control').hidden, false, 'paused follow mode shows a jump-to-live control');

context.jumpToLive();
assert.equal(flowScroll.scrollTop, 0, 'jump-to-live returns to the newest packet');
assert.equal(vm.runInContext('pendingFlowCount', context), 0, 'jump-to-live clears pending packets');
assert.equal(vm.runInContext('pendingFlows.length', context), 0, 'jump-to-live empties the flow buffer');
assert.equal(element('flow-live-control').hidden, true, 'jump-to-live hides the pending control');
assert.equal(flowBody.children[0].children[1].textContent, 'paused-newer', 'jump-to-live merges buffered packets newest first');
assert.equal(flowBody.children[1].children[1].textContent, 'paused-older', 'jump-to-live retains buffered packet order');

flowScroll.scrollTop = 80;
context.handleFlowScroll();
context.addFlow({ type: 'flow', src: 'manual-older', dst: '198.51.100.4', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
context.addFlow({ type: 'flow', src: 'manual-newer', dst: '198.51.100.5', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
assert.equal(vm.runInContext('followingFlows', context), false, 'scrolling away pauses live follow');
flowScroll.scrollTop = 0;
context.handleFlowScroll();
assert.equal(vm.runInContext('followingFlows', context), true, 'returning to the top resumes live follow');
assert.equal(vm.runInContext('pendingFlowCount', context), 0, 'returning to the top clears pending packets');
assert.equal(flowBody.children[0].children[1].textContent, 'manual-newer', 'returning to the top merges buffered packets newest first');

const maxFlows = vm.runInContext('MAX_FLOWS', context);
flowScroll.scrollTop = 80;
context.handleFlowScroll();
const visibleRowsBeforeBulk = flowBody.children.length;
for (let index = 0; index <= maxFlows; index++) {
    context.addFlow({ type: 'flow', src: 'buffer-' + index, dst: '198.51.100.6', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
}
assert.equal(vm.runInContext('pendingFlows.length', context), maxFlows, 'the paused flow buffer is bounded');
assert.equal(flowBody.children.length, visibleRowsBeforeBulk, 'buffering does not alter visible rows before resuming');
context.jumpToLive();
assert.equal(flowBody.children.length, maxFlows, 'the normal row cap applies after buffered packets merge');
assert.equal(flowBody.children[0].children[1].textContent, 'buffer-' + maxFlows, 'the latest buffered packet is rendered first');

console.log('pcap frontend protocol tests passed');
