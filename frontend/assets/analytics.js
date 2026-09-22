(function () {
    'use strict';

    var productionHosts = ['ahlyxlabs.com', 'www.ahlyxlabs.com'];
    if (productionHosts.indexOf(window.location.hostname) === -1) return;

    var consentKey = 'analytics_consent';
    var measurementId = 'G-99NT7YXMY8';
    var consent = localStorage.getItem(consentKey);
    var googleLoaded = false;

    // Keep event calls harmless before consent. No Google endpoint or dataLayer
    // is created until the visitor has explicitly accepted analytics.
    window.gtag = window.gtag || function () {};

    function loadGoogleAnalytics() {
        if (googleLoaded) return;
        googleLoaded = true;
        window.dataLayer = window.dataLayer || [];
        window.gtag = function () { window.dataLayer.push(arguments); };
        window.gtag('js', new Date());
        window.gtag('config', measurementId);

        var script = document.createElement('script');
        script.async = true;
        script.src = 'https://www.googletagmanager.com/gtag/js?id=' + encodeURIComponent(measurementId);
        document.head.appendChild(script);
    }

    if (consent === 'accepted') {
        loadGoogleAnalytics();
    }

    function createBanner() {
        if (document.getElementById('consent-banner')) return;

        var banner = document.createElement('aside');
        banner.id = 'consent-banner';
        banner.className = 'consent-banner';
        banner.setAttribute('role', 'dialog');
        banner.setAttribute('aria-label', 'Analytics consent');

        var copy = document.createElement('p');
        copy.className = 'consent-text';
        copy.textContent = 'This site uses Vercel Analytics and, with your consent, Google Analytics to understand how it is used.';

        var actions = document.createElement('div');
        actions.className = 'consent-actions';

        var accept = document.createElement('button');
        accept.type = 'button';
        accept.className = 'consent-btn consent-btn-accept';
        accept.textContent = 'Accept';
        accept.addEventListener('click', function () {
            localStorage.setItem(consentKey, 'accepted');
            loadGoogleAnalytics();
            banner.remove();
        });

        var decline = document.createElement('button');
        decline.type = 'button';
        decline.className = 'consent-btn consent-btn-decline';
        decline.textContent = 'Decline';
        decline.addEventListener('click', function () {
            localStorage.setItem(consentKey, 'declined');
            banner.remove();
        });

        actions.append(accept, decline);
        banner.append(copy, actions);
        document.body.appendChild(banner);
    }

    if (!consent) {
        document.addEventListener('DOMContentLoaded', createBanner);
    }
}());
