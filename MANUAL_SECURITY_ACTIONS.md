# Manual security actions

This repository contains the application-side controls. The following dashboard
and account changes require the owner and must not be committed to source.

## Cloudflare-to-Render origin verification

`api.ahlyxlabs.com` is intentionally Cloudflare-proxied. Prepare the
edge-to-origin verification boundary in this order:

1. While the old production code is still deployed, open **Cloudflare Dashboard
   → Rules → Transform Rules → Request Header Transform Rule** and match hostname
   `api.ahlyxlabs.com`.
2. Use **Set static** for `X-Ahlyx-Origin-Verify`, so Cloudflare supplies and
   overwrites the verification header.
3. Generate a strong random secret locally. Never commit or paste it into
   project documentation, issues, screenshots, or chat logs.
4. Add the exact same value to the Render `ahlyx-labs` service as
   `CLOUDFLARE_ORIGIN_SECRET`. The old production code does not read this
   variable/header, so preparation does not change old production behavior.
5. Merge and deploy Ahlyx Labs PR #21.
6. Verify `https://api.ahlyxlabs.com/health` behaves as intended, and normal
   API requests through the Cloudflare hostname work.
7. Confirm protected API and relay requests sent directly to the known Render
   origin without the header receive a generic `403`.
8. Confirm `CF-Connecting-IP` is used for per-client rate limiting only after
   origin verification, and that no logs or errors disclose the secret.

Local development intentionally works when `CLOUDFLARE_ORIGIN_SECRET` is not
set. Never add a sample secret to `.env.example`.

## Safe-default feature flags

These settings are already false when absent, but may be set explicitly in
Render for operational clarity:

```text
SERVER_SCANNER_ENABLED=false
URLSCAN_ACTIVE_SUBMISSION=false
URLSCAN_VISIBILITY=unlisted
```

The scanner must remain disabled on the normal public backend. URLScan active
submission requires both operator enablement and a visitor opt-in.

## Email, identity, and anti-impersonation

- Monitor SPF, DKIM, and DMARC alignment before moving DMARC toward
  quarantine/reject enforcement. Inventory every legitimate sender first.
- Review DNS for stale DKIM selectors and remove only selectors that no active
  sender uses.
- Keep a private administrator/recovery identity separate from public contact
  addresses.
- Use passkeys or hardware security keys for the domain registrar, Cloudflare,
  Render, Vercel, GitHub, and email provider. Review registrar lock, DNSSEC,
  and CAA settings where supported.

## GitHub protections

For `Ahlyx-Labs/master` and `pcap-agent/main`, require pull requests and CI
checks, prevent force pushes and deletion, require conversation resolution if
available, and require secure 2FA/passkeys for organization members.
