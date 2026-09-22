const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const analytics = fs.readFileSync(path.resolve(__dirname, '../../frontend/assets/analytics.js'), 'utf8');

function createElement(document) {
    const listeners = new Map();
    return {
        children: [],
        addEventListener(type, listener) { listeners.set(type, listener); },
        append(...children) { this.children.push(...children); },
        click() { listeners.get('click')(); },
        remove() { document.elements.delete(this.id); },
        setAttribute(name, value) { this[name] = value; }
    };
}

function runLoader(hostname, consent) {
    const elements = new Map();
    const documentListeners = new Map();
    const injectedScripts = [];
    const storage = new Map(consent ? [['analytics_consent', consent]] : []);
    let getItemCalls = 0;
    const document = {
        elements,
        head: { appendChild(element) { injectedScripts.push(element); } },
        body: {
            appendChild(element) {
                if (element.id) elements.set(element.id, element);
            }
        },
        addEventListener(type, listener) { documentListeners.set(type, listener); },
        createElement() { return createElement(document); },
        getElementById(id) { return elements.get(id) || null; }
    };
    const localStorage = {
        getItem(key) { getItemCalls += 1; return storage.get(key) || null; },
        setItem(key, value) { storage.set(key, value); }
    };
    const window = { location: { hostname } };

    vm.runInNewContext(analytics, { window, document, localStorage, Date, encodeURIComponent });

    return {
        document,
        documentListeners,
        getItemCalls: () => getItemCalls,
        injectedScripts,
        localStorage,
        window
    };
}

test('only the apex and www production hosts initialize the analytics loader', () => {
    for (const hostname of ['ahlyxlabs.com', 'www.ahlyxlabs.com']) {
        const result = runLoader(hostname, 'declined');
        assert.equal(result.getItemCalls(), 1, `${hostname} reads consent`);
        assert.equal(typeof result.window.gtag, 'function', `${hostname} initializes the consent-aware loader`);
    }

    for (const hostname of ['ahlyx-labs-git-feature-ahlyx.vercel.app', 'localhost', 'example.test']) {
        const result = runLoader(hostname, 'accepted');
        assert.equal(result.getItemCalls(), 0, `${hostname} exits before reading consent`);
        assert.equal(result.window.gtag, undefined, `${hostname} does not create gtag`);
        assert.equal(result.window.dataLayer, undefined, `${hostname} does not create dataLayer`);
        assert.equal(result.injectedScripts.length, 0, `${hostname} does not inject Google Analytics`);
        assert.equal(result.documentListeners.size, 0, `${hostname} does not initialize consent UI`);
    }
});

test('production consent preserves GA loading and banner behavior', () => {
    const accepted = runLoader('ahlyxlabs.com', 'accepted');
    assert.equal(accepted.injectedScripts.length, 1, 'accepted consent loads Google Analytics');
    assert.match(accepted.injectedScripts[0].src, /https:\/\/www\.googletagmanager\.com\/gtag\/js\?id=G-99NT7YXMY8/);
    assert.ok(Array.isArray(accepted.window.dataLayer), 'accepted consent creates the GA dataLayer');

    const newVisitor = runLoader('www.ahlyxlabs.com');
    assert.equal(newVisitor.injectedScripts.length, 0, 'new visitors do not load GA before consent');
    newVisitor.documentListeners.get('DOMContentLoaded')();
    const banner = newVisitor.document.getElementById('consent-banner');
    assert.ok(banner, 'new visitors receive the analytics consent banner');
    assert.equal(newVisitor.injectedScripts.length, 0, 'showing the banner does not load GA');

    const accept = banner.children[1].children[0];
    accept.click();
    assert.equal(newVisitor.localStorage.getItem('analytics_consent'), 'accepted', 'acceptance is persisted');
    assert.equal(newVisitor.injectedScripts.length, 1, 'accepting loads Google Analytics');

    const decline = runLoader('ahlyxlabs.com', 'declined');
    assert.equal(decline.injectedScripts.length, 0, 'declined consent does not load GA');

    const decliningVisitor = runLoader('ahlyxlabs.com');
    decliningVisitor.documentListeners.get('DOMContentLoaded')();
    decliningVisitor.document.getElementById('consent-banner').children[1].children[1].click();
    assert.equal(decliningVisitor.localStorage.getItem('analytics_consent'), 'declined', 'decline is persisted');
    assert.equal(decliningVisitor.injectedScripts.length, 0, 'declining does not load GA');
});
