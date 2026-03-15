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
// DOM — banner and button wiring
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
    const banner  = document.getElementById('consent-banner');
    const btnAccept  = document.getElementById('consent-accept');
    const btnDecline = document.getElementById('consent-decline');

    // Show banner only when no decision has been stored yet.
    if (!localStorage.getItem(CONSENT_KEY)) {
        banner.classList.remove('hidden');
    }

    btnAccept.addEventListener('click', function () {
        localStorage.setItem(CONSENT_KEY, 'accepted');
        banner.classList.add('hidden');

        // Upgrade consent and send the first hit.
        gtag('consent', 'update', { analytics_storage: 'granted' });
        gtag('js', new Date());
        gtag('config', GA_ID);
    });

    btnDecline.addEventListener('click', function () {
        localStorage.setItem(CONSENT_KEY, 'declined');
        banner.classList.add('hidden');
        // GA4 stays in denied mode — no further action needed.
    });
});
