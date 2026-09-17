const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

class Element {
    constructor() {
        this.children = [];
        this.className = '';
        this.textContent = '';
        this.innerHTML = '';
    }

    appendChild(child) { this.children.push(child); return child; }
    querySelector() { return null; }
}

async function flushAsyncWork() {
    for (let index = 0; index < 100; index++) await Promise.resolve();
}

test('hardware polling only runs while the document is visible', async () => {
    const elements = new Map();
    const element = id => {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
    };
    const listeners = new Map();
    const intervals = new Map();
    let nextIntervalID = 1;
    const requests = [];
    const document = {
        visibilityState: 'visible',
        getElementById: element,
        createElement: () => new Element(),
        addEventListener: (name, listener) => listeners.set(name, listener),
    };
    const context = {
        document,
        Date,
        Promise,
        fetch: async url => {
            requests.push(url);
            return { status: 200, ok: true, json: async () => ({ host_os: 'linux', architecture: 'amd64' }) };
        },
        setTimeout: callback => { callback(); return 0; },
        setInterval: callback => {
            const id = nextIntervalID++;
            intervals.set(id, callback);
            return id;
        },
        clearInterval: id => intervals.delete(id),
    };

    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.resolve(__dirname, '../../frontend/hardware/script.js'), 'utf8'), context);
    await flushAsyncWork();

    assert.equal(requests.length, 5, 'a visible initial page load fetches every dashboard panel once');
    assert.equal(intervals.size, 1, 'a visible page has exactly one polling interval');
    const initialPolling = intervals.values().next().value;
    initialPolling();
    await flushAsyncWork();
    assert.equal(requests.length, 10, 'the visible-tab interval refreshes all five panels');

    document.visibilityState = 'hidden';
    listeners.get('visibilitychange')();
    assert.equal(intervals.size, 0, 'hiding the tab stops the authoritative polling interval');
    initialPolling();
    await flushAsyncWork();
    assert.equal(requests.length, 10, 'a stale interval callback cannot fetch while the tab is hidden');
    await vm.runInContext('fetchAll()', context);
    assert.equal(requests.length, 10, 'a direct refresh does not schedule panel requests while hidden');

    document.visibilityState = 'visible';
    listeners.get('visibilitychange')();
    await flushAsyncWork();
    assert.equal(requests.length, 15, 'returning to the tab immediately refreshes all panels');
    assert.equal(intervals.size, 1, 'returning to the tab creates one polling interval');

    document.visibilityState = 'hidden';
    listeners.get('visibilitychange')();
    document.visibilityState = 'visible';
    listeners.get('visibilitychange')();
    await flushAsyncWork();
    assert.equal(intervals.size, 1, 'repeated visibility changes never create duplicate intervals');
});
