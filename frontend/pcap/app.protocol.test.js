// Run with: node frontend/pcap/app.protocol.test.js
// Exercises the production script with a tiny DOM/WebSocket shim; no browser
// framework or production dependency is required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const page = fs.readFileSync(__dirname + '/index.html', 'utf8');
assert.ok(!page.includes('v0.1.0'), 'the stale release version is absent');
assert.ok(page.includes('v0.4.0-rc.1'), 'the release-candidate version is shown');
const windowsSetup = page.slice(page.indexOf('Windows PowerShell'), page.indexOf('setup-platform-title">Linux'));
assert.ok(windowsSetup.includes('.\\pcap-agent-windows-amd64.exe list-interfaces'));
assert.ok(windowsSetup.includes('.\\pcap-agent-windows-amd64.exe start --interface'));
assert.ok(!windowsSetup.includes('sudo'), 'Windows instructions do not present sudo');

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

function FakeWebSocket() { this.readyState = 0; }
FakeWebSocket.OPEN = 1;
FakeWebSocket.CONNECTING = 0;
FakeWebSocket.prototype.addEventListener = function () {};
FakeWebSocket.prototype.close = function () {};

const context = {
    console, URLSearchParams, Date, Number, String, Array, Object, Map, Set,
    localStorage: { getItem: () => null, setItem: () => {} },
    dataLayer: [],
    window: { location: { search: '' }, dataLayer: [] },
    document: { getElementById: element, createElement: () => new Element(), addEventListener: () => {} },
    WebSocket: FakeWebSocket, setTimeout: callback => callback(), clearTimeout: () => {},
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(__dirname + '/app.js', 'utf8'), context);

const timestamp = '2026-09-14T12:34:56Z';
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
assert.equal(element('flow-body').children[0].children[1].textContent, '192.0.2.1', 'current flow src field is consumed');

flowScroll.scrollTop = 80;
context.handleFlowScroll();
const pausedViewport = flowScroll.scrollTop;
const pausedHeight = flowScroll.scrollHeight;
context.addFlow({ type: 'flow', src: '192.0.2.2', dst: '198.51.100.2', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
assert.equal(flowScroll.scrollTop, pausedViewport + (flowScroll.scrollHeight - pausedHeight), 'prepended packets preserve a paused viewport');
assert.equal(vm.runInContext('pendingFlowCount', context), 1, 'paused follow mode counts new packets');
assert.equal(element('flow-live-control').hidden, false, 'paused follow mode shows a jump-to-live control');

context.jumpToLive();
assert.equal(flowScroll.scrollTop, 0, 'jump-to-live returns to the newest packet');
assert.equal(vm.runInContext('pendingFlowCount', context), 0, 'jump-to-live clears pending packets');
assert.equal(element('flow-live-control').hidden, true, 'jump-to-live hides the pending control');

flowScroll.scrollTop = 80;
context.handleFlowScroll();
context.addFlow({ type: 'flow', src: '192.0.2.3', dst: '198.51.100.3', dst_port: 443, protocol: 'TCP', bytes: 42, timestamp });
assert.equal(vm.runInContext('followingFlows', context), false, 'scrolling away pauses live follow');
flowScroll.scrollTop = 0;
context.handleFlowScroll();
assert.equal(vm.runInContext('followingFlows', context), true, 'returning to the top resumes live follow');
assert.equal(vm.runInContext('pendingFlowCount', context), 0, 'returning to the top clears pending packets');

console.log('pcap frontend protocol tests passed');
