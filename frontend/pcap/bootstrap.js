(function () {
    'use strict';

    var fragment = new URLSearchParams(window.location.hash.slice(1));
    var relaySession = fragment.get('relay_session');
    var viewerToken = fragment.get('viewer_token');
    var query = new URLSearchParams(window.location.search);
    query.delete('session');
    var cleanURL = window.location.pathname + (query.size ? '?' + query.toString() : '');

    if (window.location.hash || query.toString() !== window.location.search.slice(1)) {
        window.history.replaceState(null, document.title, cleanURL);
    }
    if (relaySession && viewerToken) {
        window.__AHLYX_RELAY_BOOTSTRAP = { sessionID: relaySession, viewerToken: viewerToken };
    }
}());
