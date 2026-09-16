(function () {
    'use strict';

    var consentKey = 'analytics_consent';
    var measurementId = 'G-99NT7YXMY8';
    var consent = localStorage.getItem(consentKey);

    window.dataLayer = window.dataLayer || [];
    window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };

    gtag('consent', 'default', {
        analytics_storage: consent === 'accepted' ? 'granted' : 'denied',
        ad_storage: 'denied'
    });
    gtag('js', new Date());

    if (consent === 'accepted') {
        gtag('config', measurementId);
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
            gtag('consent', 'update', { analytics_storage: 'granted' });
            gtag('config', measurementId);
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
